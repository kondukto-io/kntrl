//go:build ignore

#include <c++/13.2.1/bits/fs_fwd.h>
#include <stdbool.h>
#include <linux/socket.h>
#include <stdint.h>

#include "headers/common.h"
#include "headers/tcp.h"
#include "headers/bpf_helpers.h"
#include "headers/bpf_core_read.h"
#include "headers/bpf_endian.h"
#include "headers/bpf_tracing.h"
#include "cidr_range.h"

#define TASK_COMM_LEN 16
#define MAX_ENTIRES 1024
#define MODE_ALLOW 1

///* Map for allowed IP addresses (hosts) from userspace */
struct bpf_map_def SEC("maps") allow_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = MAX_ENTIRES,
};

///* Map to pass mode to filter function */
struct bpf_map_def SEC("maps") mode_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

struct ipv4_event_t {
    u64 ts_us;
    u32 pid;
    u16 af;
    char task[TASK_COMM_LEN];
    u8 proto;
    u32 daddr;
    u16 dport;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} ipv4_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} ipv4_closed_events SEC(".maps");

struct event *unused __attribute__((unused));

static int __attribute__((always_inline)) is_allowed_cidr(uint32_t addr) {
	const int range_size = sizeof(ALLOWED_RANGES) / sizeof(ALLOWED_RANGES[0]);

	struct in_addr netmask;
	struct in_addr network;

	for (int i=0; i < range_size; i++) {
		netmask.s_addr = bpf_htonl(~((1 << (32 - ALLOWED_RANGES[i].mask)) - 1));
		network.s_addr = bpf_htonl(ALLOWED_RANGES[i].addr);

		if ((addr & netmask.s_addr) == (network.s_addr & netmask.s_addr)) {
			return 1;
		}
	}
	return 0;
}


static int __attribute__((always_inline)) handle_event(struct ipv4_event_t *evt4, struct sockaddr *address, uint8_t proto) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u16 address_family = 0;

	bpf_probe_read(&address_family, sizeof(address_family), &address->sa_family);

	// handle IP event only
	if (address_family == AF_INET) {
		//struct ipv4_event_t evt4 = { .pid = pid, .af = address_family, .proto = proto };
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
			bpf_printk("\t\t handle event pid=%d AF=%d Proto=%d IP=%x", evt4->pid, evt4->af, evt4->proto, evt4->daddr);
		}
	}


	return 0;
}

SEC("kprobe/ip4_datagram_connect")
int kprobe__ip4_datagram_connect(struct pt_regs *ctx) {
	struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx);
	if (!address) {
		return 0;
	}

	struct ipv4_event_t evt4 = {};
	handle_event(&evt4, address, IPPROTO_UDP);
	bpf_printk("\t handle event pid=%d AF=%d Proto=%d IP=%x", evt4.pid, evt4.af, evt4.proto, evt4.daddr);
	//if (evt4.dport != 0) {
	//            bpf_perf_event_output(ctx, &ipv4_events, BPF_F_CURRENT_CPU, &evt4, sizeof(evt4));
	//}

	return 0;
}

SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx) {
	struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx);
	if (!address) {
		return 0;
	}

	struct ipv4_event_t evt4 = {};
	handle_event(&evt4, address, IPPROTO_TCP);
	bpf_printk("\t handle event pid=%d AF=%d Proto=%d IP=%pI4", evt4.pid, evt4.af, evt4.proto, evt4.daddr);
	if (evt4.dport != 0) {
	            bpf_perf_event_output(ctx, &ipv4_events, BPF_F_CURRENT_CPU, &evt4, sizeof(evt4));
	}
	//u32 pid = bpf_get_current_pid_tgid() >> 32;
	//u16 address_family = 0;
	//bpf_probe_read(&address_family, sizeof(address_family), &address->sa_family);

	//if (address_family == AF_INET) {
	//	struct ipv4_event_t evt4 = { .pid = pid, .af = address_family, .proto = IPPROTO_TCP };
	//	evt4.ts_us = bpf_ktime_get_ns() / 1000;

	//	struct sockaddr_in *daddr = (struct sockaddr_in *)address;

	//	bpf_probe_read(&evt4.daddr, sizeof(evt4.daddr), &daddr->sin_addr.s_addr);

	//	u16 dport = 0;
	//    	bpf_probe_read(&dport, sizeof(dport), &daddr->sin_port);
	//	evt4.dport = bpf_ntohs(dport);

	//	bpf_get_current_comm(&evt4.task, TASK_COMM_LEN);

	//	if (evt4.dport != 0) {
	//            bpf_perf_event_output(ctx, &ipv4_events, BPF_F_CURRENT_CPU, &evt4, sizeof(evt4));
	//	}
	//}

	//bpf_printk("kprobe:tcp_v4_connect=%d", pid);

	return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(void *ctx) {
  	struct trace_event_raw_inet_sock_set_state args = {};
  	if (bpf_core_read(&args, sizeof(args), ctx) < 0) {
		return 0;
  	}

	// if not tcp protocol, ignore
	if (BPF_CORE_READ(&args, protocol) != IPPROTO_TCP) {
		return 0;
	}

	u32 pid = bpf_get_current_pid_tgid() >> 32;
	int oldstate;
	int newstate;

	oldstate = BPF_CORE_READ(&args, oldstate);
	newstate = BPF_CORE_READ(&args, newstate);

	u8 daddr[16];
	__builtin_memcpy(&daddr, &args.daddr, sizeof(daddr));

	__u32 val = 0;
	__be32 *p32;
	p32 = (__be32 *)daddr;
	bpf_printk("tracepoint:=%d oldstate=%d newstate=%d daddr=%pI4", pid, oldstate, newstate, p32);

	//if (oldstate == EVENT_TCP_ESTABLISHED){
	if ((oldstate == EVENT_TCP_ESTABLISHED) || (is_allowed_cidr(*p32))){
		bpf_map_update_elem(&allow_map, &daddr, &val, BPF_ANY);
	}
	return 0;
}

inline bool handle_pkt(struct __sk_buff *skb, bool egress) {
	bool block = true;

	// INFO: ingress context is usually a kernel thread or a running task
	struct iphdr iph;
	// load packet header
	bpf_skb_load_bytes(skb, 0, &iph, sizeof(struct iphdr));

	// pass all UDP traffic for now
	if (iph.protocol == IPPROTO_UDP){
		return 1;
	}

	if ((iph.version == 4) && (iph.protocol == IPPROTO_TCP)){
		bool pass = bpf_map_lookup_elem(&allow_map, &iph.saddr) || bpf_map_lookup_elem(&allow_map, &iph.daddr);

		__u32 key = 0;
		__u32 *mode;

		mode = bpf_map_lookup_elem(&mode_map, &key);
		if (mode) {
			if (*mode == MODE_ALLOW) {
				block = (*mode && pass);
			}
		}
	}

	//bpf_printk("cgroup_skb/egress=%d", iph.daddr);
	// 0 block || 1 pass
	return block;
}

//
SEC("cgroup_skb/egress")
int egress(struct __sk_buff *skb) {
	return (int)handle_pkt(skb, true);
}

char __license[] SEC("license") = "GPL";
