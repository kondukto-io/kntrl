#ifndef SENSOR_FILE_H
#define SENSOR_FILE_H

/* ========================
 * File Access Monitoring
 * ======================== */

struct file_event_t {
	u64 ts_us;
	u32 pid;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	int flags;
	u8 blocked;  /* 1 if killed by BPF */
	u8 op;       /* FILE_OP_OPEN, FILE_OP_RENAME, FILE_OP_UNLINK */
} __attribute__((packed));

/* Ring buffer for file events */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 128 * 1024); /* 128 KB */
} file_events SEC(".maps");

/* ========================
 * File BPF Programs
 * ======================== */

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(void *ctx) {
	__u32 key = 0;
	__u32 *enabled = bpf_map_lookup_elem(&file_monitor_map, &key);
	if (!enabled || *enabled == 0)
		return 0;

	struct file_event_t *evt;
	evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	evt->ts_us = bpf_ktime_get_ns() / 1000;
	evt->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&evt->comm, TASK_COMM_LEN);
	evt->op = FILE_OP_OPEN;

	/* Read filename from args[1] (user pointer) */
	char *filename_ptr;
	bpf_probe_read(&filename_ptr, sizeof(filename_ptr), (void *)ctx + 24);
	bpf_probe_read_user_str(&evt->filename, MAX_FILENAME_LEN, filename_ptr);

	/* Read flags from args[2] */
	bpf_probe_read(&evt->flags, sizeof(evt->flags), (void *)ctx + 32);

	/* Check if write-flagged open targets a protected path */
	evt->blocked = 0;
	int flags_val = evt->flags;
	if (flags_val & WRITE_FLAGS_MASK) {
		if (bpf_map_lookup_elem(&protected_paths_map, &evt->filename) != NULL) {
			evt->blocked = EVENT_FLAG_BLOCKED;
			bpf_send_signal(9);  /* SIGKILL - prevent the write */
		}
	}

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_renameat2(void *ctx) {
	__u32 key = 0;
	__u32 *enabled = bpf_map_lookup_elem(&file_monitor_map, &key);
	if (!enabled || *enabled == 0)
		return 0;

	struct file_event_t *evt;
	evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	evt->ts_us = bpf_ktime_get_ns() / 1000;
	evt->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&evt->comm, TASK_COMM_LEN);
	evt->op = FILE_OP_RENAME;
	evt->flags = 0;

	/* newname is args[3] (4th argument, offset 32) */
	char *newname_ptr;
	bpf_probe_read(&newname_ptr, sizeof(newname_ptr), (void *)ctx + 32);
	bpf_probe_read_user_str(&evt->filename, MAX_FILENAME_LEN, newname_ptr);

	evt->blocked = 0;
	if (bpf_map_lookup_elem(&protected_paths_map, &evt->filename) != NULL) {
		evt->blocked = EVENT_FLAG_BLOCKED;
		bpf_send_signal(9);
	}

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(void *ctx) {
	__u32 key = 0;
	__u32 *enabled = bpf_map_lookup_elem(&file_monitor_map, &key);
	if (!enabled || *enabled == 0)
		return 0;

	struct file_event_t *evt;
	evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	evt->ts_us = bpf_ktime_get_ns() / 1000;
	evt->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&evt->comm, TASK_COMM_LEN);
	evt->op = FILE_OP_UNLINK;
	evt->flags = 0;

	/* pathname is args[1] (2nd argument, offset 24) */
	char *pathname_ptr;
	bpf_probe_read(&pathname_ptr, sizeof(pathname_ptr), (void *)ctx + 24);
	bpf_probe_read_user_str(&evt->filename, MAX_FILENAME_LEN, pathname_ptr);

	evt->blocked = 0;
	if (bpf_map_lookup_elem(&protected_paths_map, &evt->filename) != NULL) {
		evt->blocked = EVENT_FLAG_BLOCKED;
		bpf_send_signal(9);
	}

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_faccessat")
int trace_faccessat(void *ctx) {
	__u32 key = 0;
	__u32 *enabled = bpf_map_lookup_elem(&file_monitor_map, &key);
	if (!enabled || *enabled == 0)
		return 0;

	struct file_event_t *evt;
	evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	evt->ts_us = bpf_ktime_get_ns() / 1000;
	evt->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&evt->comm, TASK_COMM_LEN);
	evt->op = FILE_OP_ACCESS;
	evt->blocked = 0;

	/* faccessat(int dfd, const char *filename, int mode)
	 * filename is args[1] at offset 24 */
	char *filename_ptr;
	bpf_probe_read(&filename_ptr, sizeof(filename_ptr), (void *)ctx + 24);
	bpf_probe_read_user_str(&evt->filename, MAX_FILENAME_LEN, filename_ptr);

	/* Read mode from args[2] */
	bpf_probe_read(&evt->flags, sizeof(evt->flags), (void *)ctx + 32);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_newfstatat")
int trace_newfstatat(void *ctx) {
	__u32 key = 0;
	__u32 *enabled = bpf_map_lookup_elem(&file_monitor_map, &key);
	if (!enabled || *enabled == 0)
		return 0;

	struct file_event_t *evt;
	evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	evt->ts_us = bpf_ktime_get_ns() / 1000;
	evt->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&evt->comm, TASK_COMM_LEN);
	evt->op = FILE_OP_ACCESS;
	evt->blocked = 0;

	/* newfstatat(int dfd, const char *filename, struct stat *statbuf, int flag)
	 * filename is args[1] at offset 24 */
	char *filename_ptr;
	bpf_probe_read(&filename_ptr, sizeof(filename_ptr), (void *)ctx + 24);
	bpf_probe_read_user_str(&evt->filename, MAX_FILENAME_LEN, filename_ptr);

	evt->flags = 0;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

#endif /* SENSOR_FILE_H */
