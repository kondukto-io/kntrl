package config

// Omitted DNS configuration uses Cloudflare and Google Public DNS. Explicit
// lists replace these defaults; [] disables the port-53 exception entirely.
// Host resolv.conf is deliberately not trusted as a source of permissions.
func dnsServers(rules DNSRules) []string {
	if rules.AllowedServers != nil {
		return rules.AllowedServers
	}
	return []string{
		"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
		"2606:4700:4700::1111", "2606:4700:4700::1001",
		"2001:4860:4860::8888", "2001:4860:4860::8844",
	}
}
