#ifndef SENSOR_DNS_H
#define SENSOR_DNS_H

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
 * DNS BPF Program
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

#endif /* SENSOR_DNS_H */
