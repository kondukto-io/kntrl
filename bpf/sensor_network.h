#ifndef SENSOR_NETWORK_H
#define SENSOR_NETWORK_H

struct ipv4_event_t {
	u64 ts_us;
	u64 cookie;
	u32 pid;
	u16 af;
	char task[TASK_COMM_LEN];
	u8 proto;
	u32 daddr;
	u16 dport;
} __attribute__((packed));

struct ipv6_event_t {
	u64 ts_us;
	u64 cookie;
	u32 pid;
	u16 af;
	char task[TASK_COMM_LEN];
	u8 proto;
	u32 daddr[4];
	u16 dport;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} ipv4_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} ipv6_events SEC(".maps");

/* Sock-addr hooks identify the initiating process even when packets later
 * run in softirq context. Missing events leave egress denied. TCP retries
 * its SYN after approval; UDP applications must retry datagrams. */
static __always_inline int observe_connect4(struct bpf_sock_addr *ctx) {
	struct ipv4_event_t event = {};
	event.ts_us = bpf_ktime_get_ns() / 1000;
	event.cookie = bpf_get_socket_cookie(ctx);
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.af = AF_INET;
	event.proto = ctx->protocol;
	event.daddr = ctx->user_ip4;
	event.dport = bpf_ntohs(ctx->user_port);
	bpf_get_current_comm(event.task, sizeof(event.task));
	bpf_ringbuf_output(&ipv4_events, &event, sizeof(event), 0);
	return 1;
}

static __always_inline int observe_connect6(struct bpf_sock_addr *ctx) {
	struct ipv6_event_t event = {};
	event.ts_us = bpf_ktime_get_ns() / 1000;
	event.cookie = bpf_get_socket_cookie(ctx);
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.af = AF_INET6;
	event.proto = ctx->protocol;
	event.daddr[0] = ctx->user_ip6[0];
	event.daddr[1] = ctx->user_ip6[1];
	event.daddr[2] = ctx->user_ip6[2];
	event.daddr[3] = ctx->user_ip6[3];
	event.dport = bpf_ntohs(ctx->user_port);
	bpf_get_current_comm(event.task, sizeof(event.task));
	bpf_ringbuf_output(&ipv6_events, &event, sizeof(event), 0);
	return 1;
}

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx) { return observe_connect4(ctx); }
SEC("cgroup/connect6")
int connect6(struct bpf_sock_addr *ctx) { return observe_connect6(ctx); }
SEC("cgroup/sendmsg4")
int sendmsg4(struct bpf_sock_addr *ctx) { return observe_connect4(ctx); }
SEC("cgroup/sendmsg6")
int sendmsg6(struct bpf_sock_addr *ctx) { return observe_connect6(ctx); }

SEC("kprobe/security_socket_create")
int kprobe__security_socket_create(struct pt_regs *ctx) {
	int family = (int)PT_REGS_PARM1(ctx);
	int type   = (int)PT_REGS_PARM2(ctx);
	int protocol = (int)PT_REGS_PARM3(ctx);

	(void)type;

	if (family != AF_PACKET && protocol != IPPROTO_RAW && protocol != IPPROTO_ICMP)
		return 0;

	struct ipv4_event_t evt4 = {};
	evt4.ts_us = bpf_ktime_get_ns() / 1000;
	evt4.pid   = bpf_get_current_pid_tgid() >> 32;
	evt4.af    = family;
	evt4.proto = protocol;
	evt4.daddr = 0;
	evt4.dport = 0;
	bpf_get_current_comm(&evt4.task, TASK_COMM_LEN);
	bpf_ringbuf_output(&ipv4_events, &evt4, sizeof(evt4), 0);
	return 0;
}

#endif
