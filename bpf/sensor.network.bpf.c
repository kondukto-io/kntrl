//go:build ignore

#include "headers/vmlinux.h"
#include <stdbool.h>

#include "headers/bpf_helpers.h"
#include "headers/bpf_core_read.h"
#include "headers/bpf_endian.h"
#include "headers/bpf_tracing.h"
#include "headers/dns.h"

#define AF_INET 2
#define TASK_COMM_LEN 16
#define MAX_ENTIRES 1024
#define MODE_ALLOW 1

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/

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

// Taken from: 
// https://github.com/DataDog/datadog-agent/blob/main/pkg/network/ebpf/c/skb.h
static __always_inline unsigned char* sk_buff_head(struct sk_buff *skb) {
	unsigned char *h = NULL;
	BPF_CORE_READ_INTO(&h, skb, head);
	return h;
}

static __always_inline u16 sk_buff_network_header(struct sk_buff *skb) {
	u16 net_head = 0;
	BPF_CORE_READ_INTO(&net_head, skb, network_header);
	return net_head;
}

static __always_inline u16 __strlen(char *ptr) {
	int len = 0;

	for (int i = 0; i < 256; i++) {
		if (*ptr == '\0')
			break;
		len++; 
		ptr++;
	}

	return len;
}

static int __attribute__((always_inline)) handle_event(struct ipv4_event_t *evt4, struct sockaddr *address, uint8_t proto) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u16 address_family = 0;

	bpf_probe_read(&address_family, sizeof(address_family), &address->sa_family);

	// handle IP event only
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

SEC("kprobe/skb_consume_udp")
int kprobe__skb_consume_udp(struct pt_regs *ctx) {
	//struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	//if (!sk) {
	//	return 0;
	//}

	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
	if (!skb) {
		return 0;
	} 

	int len = (int) PT_REGS_PARM3(ctx);
	if (len < 0) {
		return 0;
	}

	unsigned char *head = sk_buff_head(skb);
	if (!head) {
		return 0;
	}

	u16 net_head = sk_buff_network_header(skb);
	if (!net_head) {
		return 0;
	}

	struct iphdr iph = {};
	int ret = bpf_probe_read(&iph, sizeof(iph), (struct iph *)(head + net_head));
	if (ret) {
		bpf_printk("ERR reading iph");
		return ret;
	}

	bpf_printk("checking IP header version=%d protocol=%d", iph.version, iph.protocol);

	struct udphdr udph = {};
	ret = bpf_probe_read(&udph, sizeof(udph), (struct udph *)(head + net_head + sizeof(iph)));
	if (ret) {
		bpf_printk("ERR reading udph");
		return ret;
	}

	bpf_printk("checking UDP header source=%d dest=%d Len=%d", bpf_ntohs(udph.source), bpf_ntohs(udph.dest), bpf_ntohs(udph.len));

	if (bpf_ntohs(udph.source) == 53 || bpf_ntohs(udph.dest) == 53) {
		// get the dns header
		bpf_printk("We have a DNS package");
		struct dns_hdr dnsh = {};
		ret = bpf_probe_read(&dnsh, sizeof(dnsh), (struct dnsh *)(head + net_head + sizeof(iph)+ sizeof(udph)));
		if (ret) {
			bpf_printk("ERR reading dnsh");
			return ret;
		}

		// sanity check 
		// qr == 1 message is response 
		// opcode == 0 standard query
		if (dnsh.qr == 1 && dnsh.opcode == 0) {
			bpf_printk(" => We have a dns response | Transaction ID=0x%x", bpf_ntohs(dnsh.transaction_id));

			// read the domain name
			char buff[256];
			int ret = bpf_probe_read(&buff, sizeof(buff), (char *)(head + net_head + sizeof(iph) + sizeof(udph) + sizeof(dnsh)));
			if (ret) {
				bpf_printk("ERR reading dns query");
				return ret;
			}
			
			size_t len = __strlen(buff);

			// read record type and class
			uint32_t b;
			ret = bpf_probe_read(&b, sizeof(b), (uint32_t *)(head + net_head + sizeof(iph) + sizeof(udph) + sizeof(dnsh) + (len + 1)));
			if (ret) {
				bpf_printk("ERR reading dns query (fields)");
				return ret;
			}

			uint16_t record_type = bpf_ntohs(b & 0x0000FFFF);
			uint16_t class = (bpf_ntohs(b >> 16) & 0x0000FFFF);
			bpf_printk("debug dns query field :: Record=%x Class=%x", record_type, class);

			// check if record type == A and class == IN
			if (record_type == 1 && class == 1) {
				// we have a HOST record
				bpf_printk("   => We have a HOST record | Record Type=0x%x and Class=0x%x", record_type, class);
				bpf_printk("   => AnswerCount=%d Domain: %s", bpf_ntohs(dnsh.ans_count), buff);

				unsigned long offset = (unsigned long)(head + net_head + sizeof(iph) + sizeof(udph) + sizeof(dnsh) + (len + 1) + sizeof(b));
				struct dns_response resp = {};
				ret = bpf_probe_read(&resp, sizeof(resp), (struct resp *)(offset));
				if (ret) {
					bpf_printk("ERR reading dns response");
					return ret;
				}

				bpf_printk("debug dns response :: Record=%d Class=%d", resp.record_type, resp.class);
			}
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
	if (handle_event(&evt4, address, IPPROTO_UDP)) {
	            bpf_perf_event_output(ctx, &ipv4_events, BPF_F_CURRENT_CPU, &evt4, sizeof(evt4));
	}

	bpf_printk("kprobe:ip4_datagram_connect - handle event pid=%d AF=%d Proto=%d IP=%pI4", evt4.pid, evt4.af, evt4.proto, evt4.daddr);

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
	            bpf_perf_event_output(ctx, &ipv4_events, BPF_F_CURRENT_CPU, &evt4, sizeof(evt4));
	}
	bpf_printk("kprobe:tcp_v4_connect - handle event pid=%d AF=%d Proto=%d IP=%pI4", evt4.pid, evt4.af, evt4.proto, evt4.daddr);

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

	if (oldstate == BPF_TCP_ESTABLISHED){
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

	// refactor
	if (iph.version == 4){
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

	// 0 block || 1 pass
	return block;
}

//
SEC("cgroup_skb/egress")
int egress(struct __sk_buff *skb) {
	return (int)handle_pkt(skb, true);
}

char __license[] SEC("license") = "GPL";
