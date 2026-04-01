#ifndef SENSOR_PROCESS_H
#define SENSOR_PROCESS_H

/* ========================
 * Process Monitoring
 * ======================== */

struct process_event_t {
	u64 ts_us;
	u32 pid;
	u32 ppid;
	u8  event_type;  /* EVENT_TYPE_FORK or EVENT_TYPE_EXEC */
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN]; /* exec only */
	char args[MAX_ARGS_LEN];         /* exec: NUL-separated argv */
	u16 args_len;                    /* actual argv byte length (excludes env) */
	u8  blocked;                     /* 1 if killed by BPF */
} __attribute__((packed));

/* Ring buffer for process events */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 128 * 1024); /* 128 KB */
} process_events SEC(".maps");

/* ========================
 * Process BPF Programs
 * ======================== */

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx) {
	__u32 key = 0;
	__u32 *enabled = bpf_map_lookup_elem(&process_monitor_map, &key);
	if (!enabled || *enabled == 0)
		return 0;

	/* Drop events from kntrl's own process group */
	__u32 current_tgid = bpf_get_current_pid_tgid() >> 32;
	__u32 stkey = 0;
	__u32 *self_tgid = bpf_map_lookup_elem(&self_tgid_map, &stkey);
	if (self_tgid && *self_tgid == current_tgid)
		return 0;

	struct process_event_t *evt;
	evt = bpf_ringbuf_reserve(&process_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	evt->ts_us = bpf_ktime_get_ns() / 1000;
	evt->pid = bpf_get_current_pid_tgid() >> 32;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	evt->ppid = BPF_CORE_READ(task, real_parent, tgid);

	evt->event_type = EVENT_TYPE_EXEC;
	bpf_get_current_comm(&evt->comm, TASK_COMM_LEN);

	unsigned int fname_off = BPF_CORE_READ(ctx, __data_loc_filename) & 0xFFFF;
	bpf_probe_read_str(&evt->filename, MAX_FILENAME_LEN, (void *)ctx + fname_off);

	/* Read process arguments (NUL-separated argv) from user memory.
	 * Pass args_len so Go can truncate — avoids env var leakage. */
	__builtin_memset(evt->args, 0, MAX_ARGS_LEN);
	evt->args_len = 0;
	unsigned long arg_start = BPF_CORE_READ(task, mm, arg_start);
	unsigned long arg_end = BPF_CORE_READ(task, mm, arg_end);
	if (arg_start && arg_end > arg_start) {
		unsigned long arg_len = arg_end - arg_start;
		if (arg_len > MAX_ARGS_LEN)
			arg_len = MAX_ARGS_LEN;
		evt->args_len = (u16)arg_len;
		bpf_probe_read_user(evt->args, MAX_ARGS_LEN, (void *)arg_start);
	}

	/* Check if this executable is blocked */
	evt->blocked = 0;
	if (bpf_map_lookup_elem(&blocked_exec_map, &evt->comm) != NULL) {
		evt->blocked = EVENT_FLAG_BLOCKED;
		bpf_send_signal(9);  /* SIGKILL */
	}

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx) {
	__u32 key = 0;
	__u32 *enabled = bpf_map_lookup_elem(&process_monitor_map, &key);
	if (!enabled || *enabled == 0)
		return 0;

	/* Drop events from kntrl's own process group */
	__u32 current_tgid = bpf_get_current_pid_tgid() >> 32;
	__u32 stkey = 0;
	__u32 *self_tgid = bpf_map_lookup_elem(&self_tgid_map, &stkey);
	if (self_tgid && *self_tgid == current_tgid)
		return 0;

	struct process_event_t *evt;
	evt = bpf_ringbuf_reserve(&process_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	evt->ts_us = bpf_ktime_get_ns() / 1000;
	evt->pid = ctx->child_pid;
	evt->ppid = bpf_get_current_pid_tgid() >> 32;
	evt->event_type = EVENT_TYPE_FORK;

	bpf_probe_read_str(&evt->comm, TASK_COMM_LEN, ctx->child_comm);
	evt->filename[0] = '\0';
	evt->args[0] = '\0';
	evt->args_len = 0;
	evt->blocked = 0;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

#endif /* SENSOR_PROCESS_H */
