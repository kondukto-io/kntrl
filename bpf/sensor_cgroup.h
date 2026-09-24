#ifndef SENSOR_CGROUP_H
#define SENSOR_CGROUP_H

/* Fragments and unsupported IPv6 extension chains fail closed. */
static __always_inline bool packet_destination(struct __sk_buff *skb,
					      struct connection_key *key) {
	struct iphdr ip4 = {};
	if (bpf_skb_load_bytes(skb, 0, &ip4, sizeof(ip4)) < 0)
		return false;
	__u32 offset;
	if (ip4.version == 4) {
		if (ip4.ihl < 5 || (ip4.frag_off & bpf_htons(0x3fff)))
			return false;
		key->family = AF_INET;
		key->protocol = ip4.protocol;
		__builtin_memcpy(key->address, &ip4.daddr, 4);
		offset = ip4.ihl * 4;
	} else if (ip4.version == 6) {
		struct ipv6hdr ip6 = {};
		if (bpf_skb_load_bytes(skb, 0, &ip6, sizeof(ip6)) < 0)
			return false;
		key->family = AF_INET6;
		key->protocol = ip6.nexthdr;
		__builtin_memcpy(key->address, &ip6.daddr, 16);
		offset = sizeof(ip6);
	} else {
		return false;
	}
	if (key->protocol != IPPROTO_TCP && key->protocol != IPPROTO_UDP)
		return false;
	__u16 port;
	if (bpf_skb_load_bytes(skb, offset + 2, &port, sizeof(port)) < 0)
		return false;
	key->port = bpf_ntohs(port);
	return true;
}

static __always_inline bool handle_pkt(struct __sk_buff *skb) {
	__u32 zero = 0;
	__u32 *mode = bpf_map_lookup_elem(&mode_map, &zero);
	bool enforce = !mode || *mode == MODE_ALLOW;

	struct connection_key key = {};
	if (!packet_destination(skb, &key))
		return !enforce;

	if (key.family == AF_INET && key.protocol == IPPROTO_TCP && key.port == 443) {
		struct iphdr ip4 = {};
		if (bpf_skb_load_bytes(skb, 0, &ip4, sizeof(ip4)) == 0)
			try_extract_sni(skb, &ip4);
	}
	if (!enforce)
		return true;
	/* DNS checks precede every policy grant, including explicit IP grants. */
	if (key.port == 53) {
		struct resolver_key resolver = {.family = key.family};
		__builtin_memcpy(resolver.address, key.address, sizeof(resolver.address));
		return bpf_map_lookup_elem(&dns_resolvers, &resolver) != NULL;
	}
	key.cookie = bpf_get_socket_cookie(skb);
	if (!key.cookie)
		return false;
	return bpf_map_lookup_elem(&allowed_connections, &key) != NULL;
}

SEC("cgroup_skb/egress")
int egress(struct __sk_buff *skb) { return handle_pkt(skb); }

#endif
