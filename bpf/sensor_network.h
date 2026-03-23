#ifndef SENSOR_NETWORK_H
#define SENSOR_NETWORK_H

/* ========================
 * IPv4 Connection Monitoring
 * ======================== */

/* Event structure for IPv4 connection events */
struct ipv4_event_t {
	u64 ts_us;
	u32 pid;
	u16 af;
	char task[TASK_COMM_LEN];
	u8 proto;
	u32 daddr;
	u16 dport;
} __attribute__((packed));

/* Ring buffer for sending events to userspace */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KB */
} ipv4_events SEC(".maps");

/* ========================
 * IPv6 Connection Monitoring
 * ======================== */

struct ipv6_event_t {
	u64 ts_us;
	u32 pid;
	u16 af;
	char task[TASK_COMM_LEN];
	u8 proto;
	u8 daddr[16]; /* in6_addr */
	u16 dport;
} __attribute__((packed));

/* Ring buffer for IPv6 events */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KB */
} ipv6_events SEC(".maps");

/* ========================
 * Network Helper
 * ======================== */

static int __attribute__((always_inline)) handle_event(struct ipv4_event_t *evt4, struct sockaddr *address, uint8_t proto) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u16 address_family = 0;

	bpf_probe_read(&address_family, sizeof(address_family), &address->sa_family);

	if (address_family == AF_INET) {
		evt4->pid = pid;
		evt4->af = address_family;
		evt4->proto = proto;
		evt4->ts_us = bpf_ktime_get_ns() / 1000;

		struct sockaddr_in *daddr = (struct sockaddr_in *)address;
		bpf_probe_read(&evt4->daddr, sizeof(evt4->daddr), &daddr->sin_addr.s_addr);

		u16 dport = 0;
		bpf_probe_read(&dport, sizeof(dport), &daddr->sin_port);
		evt4->dport = bpf_ntohs(dport);

		bpf_get_current_comm(&evt4->task, TASK_COMM_LEN);

		if (evt4->dport != 0) {
			return 1;
		}
	}

	return 0;
}

/* ========================
 * Network BPF Programs
 * ======================== */

SEC("kprobe/ip4_datagram_connect")
int kprobe__ip4_datagram_connect(struct pt_regs *ctx) {
	struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx);
	if (!address) {
		return 0;
	}

	struct ipv4_event_t evt4 = {};
	if (handle_event(&evt4, address, IPPROTO_UDP)) {
		bpf_ringbuf_output(&ipv4_events, &evt4, sizeof(evt4), 0);
	}

	return 0;
}

SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx) {
	struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx);
	if (!address) {
		return 0;
	}

	struct ipv4_event_t evt4 = {};
	if (handle_event(&evt4, address, IPPROTO_TCP)) {
		bpf_ringbuf_output(&ipv4_events, &evt4, sizeof(evt4), 0);
	}

	return 0;
}

SEC("kprobe/tcp_v6_connect")
int kprobe__tcp_v6_connect(struct pt_regs *ctx) {
	struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx);
	if (!address)
		return 0;

	u16 address_family = 0;
	bpf_probe_read(&address_family, sizeof(address_family), &address->sa_family);
	if (address_family != AF_INET6)
		return 0;

	struct ipv6_event_t *evt6;
	evt6 = bpf_ringbuf_reserve(&ipv6_events, sizeof(*evt6), 0);
	if (!evt6)
		return 0;

	evt6->pid = bpf_get_current_pid_tgid() >> 32;
	evt6->af = AF_INET6;
	evt6->proto = IPPROTO_TCP;
	evt6->ts_us = bpf_ktime_get_ns() / 1000;
	bpf_get_current_comm(&evt6->task, TASK_COMM_LEN);

	struct sockaddr_in6 *daddr6 = (struct sockaddr_in6 *)address;
	bpf_probe_read(&evt6->daddr, 16, &daddr6->sin6_addr);

	u16 dport = 0;
	bpf_probe_read(&dport, sizeof(dport), &daddr6->sin6_port);
	evt6->dport = bpf_ntohs(dport);

	if (evt6->dport != 0) {
		bpf_ringbuf_submit(evt6, 0);
	} else {
		bpf_ringbuf_discard(evt6, 0);
	}

	return 0;
}

SEC("kprobe/udpv6_sendmsg")
int kprobe__udpv6_sendmsg(struct pt_regs *ctx) {
	struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
	if (!msg)
		return 0;

	struct sockaddr *address = NULL;
	bpf_probe_read(&address, sizeof(address), &msg->msg_name);
	if (!address)
		return 0;

	u16 address_family = 0;
	bpf_probe_read(&address_family, sizeof(address_family), &address->sa_family);
	if (address_family != AF_INET6)
		return 0;

	struct ipv6_event_t *evt6;
	evt6 = bpf_ringbuf_reserve(&ipv6_events, sizeof(*evt6), 0);
	if (!evt6)
		return 0;

	evt6->pid = bpf_get_current_pid_tgid() >> 32;
	evt6->af = AF_INET6;
	evt6->proto = IPPROTO_UDP;
	evt6->ts_us = bpf_ktime_get_ns() / 1000;
	bpf_get_current_comm(&evt6->task, TASK_COMM_LEN);

	struct sockaddr_in6 *daddr6 = (struct sockaddr_in6 *)address;
	bpf_probe_read(&evt6->daddr, 16, &daddr6->sin6_addr);

	u16 dport = 0;
	bpf_probe_read(&dport, sizeof(dport), &daddr6->sin6_port);
	evt6->dport = bpf_ntohs(dport);

	if (evt6->dport != 0) {
		bpf_ringbuf_submit(evt6, 0);
	} else {
		bpf_ringbuf_discard(evt6, 0);
	}

	return 0;
}

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

#endif /* SENSOR_NETWORK_H */
