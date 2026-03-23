#ifndef SENSOR_SNI_H
#define SENSOR_SNI_H

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

#endif /* SENSOR_SNI_H */
