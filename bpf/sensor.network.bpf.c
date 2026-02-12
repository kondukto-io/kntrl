//go:build ignore

#include "headers/vmlinux.h"
/* vmlinux.h provides bool (_Bool) and all kernel types.
 * Do NOT include libc headers (stdbool.h, string.h, errno.h, etc.)
 * — they pull in arch-specific paths that break -target bpf builds. */

#include "headers/bpf_helpers.h"
#include "headers/bpf_core_read.h"
#include "headers/bpf_endian.h"
#include "headers/bpf_tracing.h"
#include "headers/dns.h"

#include "sensor.network.h"

/* ========================
 * Map Definitions (BTF style)
 * ======================== */

/* Map for allowed IP addresses from userspace */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, MAX_ENTIRES);
} allowed_ip_map SEC(".maps");

/* Map for allowed hostnames from userspace */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, MAX_HOSTNAME_LEN);
	__type(value, __u32);
	__uint(max_entries, MAX_ENTIRES);
} allowed_hosts_map SEC(".maps");

/* Map to pass mode to filter function */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} mode_map SEC(".maps");

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
 * DNS Monitoring
 * ======================== */

struct dns_event_t {
	u64 ts_us;
	u32 pid;
	u32 dns_server_ip;
	char qname[MAX_HOSTNAME_LEN];
	u16 qtype;
	u8  is_response;
} __attribute__((packed));

/* Ring buffer for DNS events */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 128 * 1024); /* 128 KB */
} dns_events SEC(".maps");

/* Map for allowed DNS servers */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} allowed_dns_servers_map SEC(".maps");

/* ========================
 * IPv6 Monitoring
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

/* Map for allowed IPv6 addresses */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, 16);
	__type(value, __u32);
	__uint(max_entries, MAX_ENTIRES);
} allowed_ipv6_map SEC(".maps");

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
} __attribute__((packed));

/* Ring buffer for process events */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 128 * 1024); /* 128 KB */
} process_events SEC(".maps");

/* Enable/disable flag for process monitoring */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} process_monitor_map SEC(".maps");

/* ========================
 * Helper Functions
 * ======================== */

static __always_inline int parse_dns_response(int ans_count, unsigned long offset) {
	unsigned long new_offset = offset;

	for (int i = 0; i < 10; i++) {
		if (ans_count == i) break;

		struct dns_response resp = {};
		int ret = bpf_probe_read(&resp, sizeof(resp), (struct resp *)(new_offset));
		if (ret) {
			bpf_printk("ERR reading dns response (answer)");
			return ret;
		}

		if (bpf_ntohs(resp.record_type) == 1 && bpf_ntohs(resp.class) == 1) {
			uint32_t address;
			ret = bpf_probe_read(&address, sizeof(address), (uint32_t *)(new_offset + sizeof(resp)));
			if (ret) {
				bpf_printk("ERR reading address (answer)");
				return ret;
			}

			__u32 val = 0;
			bpf_map_update_elem(&allowed_ip_map, &address, &val, BPF_ANY);
		}
		new_offset = (new_offset + sizeof(resp) + bpf_ntohs(resp.data_length));
	}

	return 0;
}

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
		if (*ptr < 32 || *ptr > 126)
			*ptr = '.';
		len++;
		ptr++;
	}

	return len;
}

static __always_inline int __is_allowed_host(char *hostname) {
	if (bpf_map_lookup_elem(&allowed_hosts_map, hostname) != NULL)
		return 1;

	return 0;
}

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
 * BPF Programs
 * ======================== */

SEC("kprobe/skb_consume_udp")
int kprobe__skb_consume_udp(struct pt_regs *ctx) {
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

	struct udphdr udph = {};
	ret = bpf_probe_read(&udph, sizeof(udph), (struct udph *)(head + net_head + sizeof(iph)));
	if (ret) {
		bpf_printk("ERR reading udph");
		return ret;
	}

	if (bpf_ntohs(udph.source) == 53 || bpf_ntohs(udph.dest) == 53) {
		struct dns_hdr dnsh = {};
		ret = bpf_probe_read(&dnsh, sizeof(dnsh), (struct dnsh *)(head + net_head + sizeof(iph) + sizeof(udph)));
		if (ret) {
			bpf_printk("ERR reading dnsh");
			return ret;
		}

		// qr == 1: message is response
		// opcode == 0: standard query
		if (dnsh.qr == 1 && dnsh.opcode == 0) {
			bpf_printk("dns response | Transaction ID=0x%x", bpf_ntohs(dnsh.transaction_id));

			char buff[256];
			int ret = bpf_probe_read(&buff, sizeof(buff), (char *)(head + net_head + sizeof(iph) + sizeof(udph) + sizeof(dnsh)));
			if (ret) {
				bpf_printk("ERR reading dns query");
				return ret;
			}

			size_t len = __strlen(buff);

			/* Emit DNS event to userspace */
			struct dns_event_t *dns_evt;
			dns_evt = bpf_ringbuf_reserve(&dns_events, sizeof(*dns_evt), 0);
			if (dns_evt) {
				dns_evt->ts_us = bpf_ktime_get_ns() / 1000;
				dns_evt->pid = bpf_get_current_pid_tgid() >> 32;
				dns_evt->dns_server_ip = iph.saddr;
				bpf_probe_read_kernel(&dns_evt->qname, MAX_HOSTNAME_LEN, buff);
				dns_evt->qtype = 0;
				dns_evt->is_response = 1;
				bpf_ringbuf_submit(dns_evt, 0);
			}

			/* Check if DNS server is in allowed list (if map is populated) */
			bool dns_server_allowed = true;
			if (bpf_map_lookup_elem(&allowed_dns_servers_map, &iph.saddr) == NULL) {
				/* If the map has entries but this server isn't in it, skip IP addition */
				__u32 check_key = 0;
				if (bpf_map_lookup_elem(&allowed_dns_servers_map, &check_key) != NULL) {
					dns_server_allowed = false;
				}
			}

			if (!__is_allowed_host(buff)) {
				return 0;
			}

			uint32_t rc;
			ret = bpf_probe_read(&rc, sizeof(rc), (uint32_t *)(head + net_head + sizeof(iph) + sizeof(udph) + sizeof(dnsh) + (len + 1)));
			if (ret) {
				bpf_printk("ERR reading dns query (fields)");
				return ret;
			}

			uint16_t record_type = bpf_ntohs(rc & 0x0000FFFF);
			uint16_t class = (bpf_ntohs(rc >> 16) & 0x0000FFFF);

			if (record_type == 1 && class == 1 && dns_server_allowed) {
				unsigned long offset = (unsigned long)(head + net_head + sizeof(iph) + sizeof(udph) + sizeof(dnsh) + (len + 1) + sizeof(rc));
				parse_dns_response(bpf_ntohs(dnsh.ans_count), offset);
			}
		} else if (dnsh.qr == 0) {
			/* DNS query - emit event */
			char buff[256];
			int ret = bpf_probe_read(&buff, sizeof(buff), (char *)(head + net_head + sizeof(iph) + sizeof(udph) + sizeof(dnsh)));
			if (ret) {
				return 0;
			}

			__strlen(buff);

			struct dns_event_t *dns_evt;
			dns_evt = bpf_ringbuf_reserve(&dns_events, sizeof(*dns_evt), 0);
			if (dns_evt) {
				dns_evt->ts_us = bpf_ktime_get_ns() / 1000;
				dns_evt->pid = bpf_get_current_pid_tgid() >> 32;
				dns_evt->dns_server_ip = iph.daddr;
				bpf_probe_read_kernel(&dns_evt->qname, MAX_HOSTNAME_LEN, buff);
				dns_evt->qtype = 0;
				dns_evt->is_response = 0;
				bpf_ringbuf_submit(dns_evt, 0);
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

SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(void *ctx) {
	struct trace_event_raw_inet_sock_set_state args = {};
	if (bpf_core_read(&args, sizeof(args), ctx) < 0) {
		return 0;
	}

	if (BPF_CORE_READ(&args, protocol) != IPPROTO_TCP) {
		return 0;
	}

	int oldstate;

	oldstate = BPF_CORE_READ(&args, oldstate);

	u8 daddr[16];
	__builtin_memcpy(&daddr, &args.daddr, sizeof(daddr));

	__u32 val = 0;

	if (oldstate == BPF_TCP_ESTABLISHED) {
		bpf_map_update_elem(&allowed_ip_map, &daddr, &val, BPF_ANY);
	}

	return 0;
}

/* ========================
 * Process Monitoring Programs
 * ======================== */

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx) {
	__u32 key = 0;
	__u32 *enabled = bpf_map_lookup_elem(&process_monitor_map, &key);
	if (!enabled || *enabled == 0)
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

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx) {
	__u32 key = 0;
	__u32 *enabled = bpf_map_lookup_elem(&process_monitor_map, &key);
	if (!enabled || *enabled == 0)
		return 0;

	struct process_event_t *evt;
	evt = bpf_ringbuf_reserve(&process_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	evt->ts_us = bpf_ktime_get_ns() / 1000;
	evt->pid = BPF_CORE_READ(ctx, child_pid);
	evt->ppid = BPF_CORE_READ(ctx, parent_pid);
	evt->event_type = EVENT_TYPE_FORK;

	bpf_probe_read_str(&evt->comm, TASK_COMM_LEN, ctx->child_comm);
	evt->filename[0] = '\0';

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/* ========================
 * File Access Monitoring
 * ======================== */

struct file_event_t {
	u64 ts_us;
	u32 pid;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	int flags;
} __attribute__((packed));

/* Ring buffer for file events */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 128 * 1024); /* 128 KB */
} file_events SEC(".maps");

/* Enable/disable flag for file monitoring */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} file_monitor_map SEC(".maps");

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

	/* Read filename from args[1] (user pointer) */
	char *filename_ptr;
	bpf_probe_read(&filename_ptr, sizeof(filename_ptr), (void *)ctx + 24);
	bpf_probe_read_user_str(&evt->filename, MAX_FILENAME_LEN, filename_ptr);

	/* Read flags from args[2] */
	bpf_probe_read(&evt->flags, sizeof(evt->flags), (void *)ctx + 32);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/* ========================
 * TLS SNI Inspection
 * ======================== */

struct sni_event_t {
	u64 ts_us;
	u32 pid;
	u32 daddr;
	u16 dport;
	char sni[MAX_HOSTNAME_LEN];
} __attribute__((packed));

/* Ring buffer for SNI events */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024); /* 64 KB */
} sni_events SEC(".maps");

/* ========================
 * Cgroup Egress Filter
 * ======================== */

/* Try to extract TLS SNI from a ClientHello in an IPv4 TCP packet.
 * Emits an sni_event_t if SNI is found.
 * offset: byte offset within skb where IP header starts (usually 0 for cgroup_skb)
 */
static __always_inline void try_extract_sni(struct __sk_buff *skb, struct iphdr *iph) {
	/* Only check TCP (protocol 6) */
	if (iph->protocol != IPPROTO_TCP)
		return;

	u32 ip_hdr_len = iph->ihl * 4;
	if (ip_hdr_len < 20)
		return;

	/* Read TCP header to get data offset */
	struct tcphdr tcph;
	if (bpf_skb_load_bytes(skb, ip_hdr_len, &tcph, sizeof(tcph)) < 0)
		return;

	u32 tcp_hdr_len = tcph.doff * 4;
	if (tcp_hdr_len < 20)
		return;

	u32 tls_offset = ip_hdr_len + tcp_hdr_len;

	/* Check TLS content type: 0x16 = Handshake */
	u8 content_type = 0;
	if (bpf_skb_load_bytes(skb, tls_offset, &content_type, 1) < 0)
		return;
	if (content_type != 0x16)
		return;

	/* TLS record header: type(1) + version(2) + length(2) = 5 bytes */
	/* Handshake header: type(1) + length(3) = 4 bytes */
	u32 hs_offset = tls_offset + 5;
	u8 hs_type = 0;
	if (bpf_skb_load_bytes(skb, hs_offset, &hs_type, 1) < 0)
		return;
	if (hs_type != 0x01) /* ClientHello */
		return;

	/* ClientHello: type(1) + length(3) + version(2) + random(32) = 38 bytes from hs_offset */
	u32 pos = hs_offset + 4 + 2 + 32;

	/* Session ID length */
	u8 session_id_len = 0;
	if (bpf_skb_load_bytes(skb, pos, &session_id_len, 1) < 0)
		return;
	pos += 1 + session_id_len;

	/* Cipher suites length (2 bytes, big-endian) */
	u16 cipher_len_be = 0;
	if (bpf_skb_load_bytes(skb, pos, &cipher_len_be, 2) < 0)
		return;
	u16 cipher_len = bpf_ntohs(cipher_len_be);
	pos += 2 + cipher_len;

	/* Compression methods length */
	u8 comp_len = 0;
	if (bpf_skb_load_bytes(skb, pos, &comp_len, 1) < 0)
		return;
	pos += 1 + comp_len;

	/* Extensions length (2 bytes) */
	u16 ext_len_be = 0;
	if (bpf_skb_load_bytes(skb, pos, &ext_len_be, 2) < 0)
		return;
	u16 ext_total_len = bpf_ntohs(ext_len_be);
	pos += 2;

	u32 ext_end = pos + ext_total_len;

	/* Parse extensions (bounded loop for verifier) */
	for (int i = 0; i < 20; i++) {
		if (pos + 4 > ext_end)
			break;

		u16 ext_type_be = 0;
		u16 ext_data_len_be = 0;
		if (bpf_skb_load_bytes(skb, pos, &ext_type_be, 2) < 0)
			break;
		if (bpf_skb_load_bytes(skb, pos + 2, &ext_data_len_be, 2) < 0)
			break;

		u16 ext_type = bpf_ntohs(ext_type_be);
		u16 ext_data_len = bpf_ntohs(ext_data_len_be);
		pos += 4;

		if (ext_type == 0x0000) { /* SNI extension */
			/* SNI list: total_len(2) + type(1) + name_len(2) + name */
			if (ext_data_len < 5 || pos + 5 > ext_end)
				break;

			u16 name_len_be = 0;
			if (bpf_skb_load_bytes(skb, pos + 3, &name_len_be, 2) < 0)
				break;
			u16 name_len = bpf_ntohs(name_len_be);
			if (name_len == 0 || name_len >= MAX_HOSTNAME_LEN)
				break;

			/* Use stack buffer for variable ops — the verifier
			 * forbids variable-index writes on ringbuf memory. */
			char sni_buf[MAX_HOSTNAME_LEN];
			__builtin_memset(sni_buf, 0, sizeof(sni_buf));
			if (bpf_skb_load_bytes(skb, pos + 5, sni_buf, MAX_HOSTNAME_LEN - 1) < 0)
				break;
			sni_buf[name_len & 0xFF] = '\0';

			struct sni_event_t *evt;
			evt = bpf_ringbuf_reserve(&sni_events, sizeof(*evt), 0);
			if (!evt)
				break;

			evt->ts_us = bpf_ktime_get_ns() / 1000;
			evt->pid = 0;
			evt->daddr = iph->daddr;
			evt->dport = bpf_ntohs(tcph.dest);
			__builtin_memcpy(evt->sni, sni_buf, MAX_HOSTNAME_LEN);

			bpf_ringbuf_submit(evt, 0);
			break;
		}

		pos += ext_data_len;
	}
}

static __always_inline bool handle_pkt(struct __sk_buff *skb, bool egress) {
	bool block = true;

	struct iphdr iph;
	bpf_skb_load_bytes(skb, 0, &iph, sizeof(struct iphdr));

	if (iph.version == 4) {
		bool pass = bpf_map_lookup_elem(&allowed_ip_map, &iph.saddr) || bpf_map_lookup_elem(&allowed_ip_map, &iph.daddr);

		__u32 key = 0;
		__u32 *mode;

		mode = bpf_map_lookup_elem(&mode_map, &key);
		if (mode) {
			if (*mode == MODE_ALLOW) {
				block = (*mode && pass);
			}
		}

		/* Try to extract TLS SNI from egress TCP packets */
		if (egress)
			try_extract_sni(skb, &iph);
	} else if (iph.version == 6) {
		struct ipv6hdr ip6h;
		bpf_skb_load_bytes(skb, 0, &ip6h, sizeof(ip6h));

		bool pass = bpf_map_lookup_elem(&allowed_ipv6_map, &ip6h.saddr) ||
			    bpf_map_lookup_elem(&allowed_ipv6_map, &ip6h.daddr);

		__u32 key = 0;
		__u32 *mode;

		mode = bpf_map_lookup_elem(&mode_map, &key);
		if (mode) {
			if (*mode == MODE_ALLOW) {
				block = (*mode && pass);
			}
		}
	}

	return block;
}

SEC("cgroup_skb/egress")
int egress(struct __sk_buff *skb) {
	return (int)handle_pkt(skb, true);
}

char __license[] SEC("license") = "GPL";
