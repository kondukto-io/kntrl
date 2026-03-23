#ifndef SENSOR_CGROUP_H
#define SENSOR_CGROUP_H

/* ========================
 * Cgroup Egress Filter
 * ======================== */

/* Extract the destination port from the L4 header (TCP or UDP).
 * Returns 0 if the protocol is not TCP/UDP or on parse failure. */
static __always_inline __u16 get_dst_port(struct __sk_buff *skb, struct iphdr *iph) {
	__u32 l4_off = iph->ihl * 4;
	if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
		__u16 dport;
		if (bpf_skb_load_bytes(skb, l4_off + 2, &dport, sizeof(dport)) < 0)
			return 0;
		return __bpf_ntohs(dport);
	}
	return 0;
}

static __always_inline bool handle_pkt(struct __sk_buff *skb, bool egress) {
	bool block = true;

	struct iphdr iph;
	bpf_skb_load_bytes(skb, 0, &iph, sizeof(struct iphdr));

	if (iph.version == 4) {
		/* Always allow DNS traffic (port 53) — DNS is monitored
		 * separately by the DNS event hooks, and blocking DNS here
		 * would prevent all name resolution from working. */
		__u16 dport = get_dst_port(skb, &iph);
		if (dport == 53)
			return true;

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

/* ========================
 * Cgroup BPF Programs
 * ======================== */

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

SEC("cgroup_skb/egress")
int egress(struct __sk_buff *skb) {
	return (int)handle_pkt(skb, true);
}

#endif /* SENSOR_CGROUP_H */
