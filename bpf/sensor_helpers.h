#ifndef SENSOR_HELPERS_H
#define SENSOR_HELPERS_H

/* ========================
 * Shared Helper Functions
 * ======================== */

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
			/* DNS-resolved IPs are no longer auto-whitelisted here.
			 * Userspace policy must explicitly approve connections. */
		}
		new_offset = (new_offset + sizeof(resp) + bpf_ntohs(resp.data_length));
	}

	return 0;
}

#endif /* SENSOR_HELPERS_H */
