package domain

import "net"

// Data represents the JSON data used in Open Policy Agent (OPA).
// In OPA, decisions are made by comparing "policy" (Rego Code) and "data" (JSON).
type Data struct {
	// The allowed hosts from the cmd package.
	// The 'parser' package will append the host machine's DNS servers.
	AllowedHosts []string `json:"allowed_hosts"`
	// Allowed IPs.
	AllowedIPs []net.IP `json:"allowed_ip_addr"`
	// Allow GitHub Meta addresses. The address list is stored
	// with Rego policies.
	// You can find the full meta list here: https://api.github.com/meta.
	AllowGithubMeta bool `json:"allow_github_meta"`
	// Allow local IP addresses.
	AllowLocalIPRanges bool `json:"allow_local_ip_ranges"`
	// Allowed process names. If empty, all processes are allowed.
	AllowedProcesses []string `json:"allowed_processes,omitempty"`
	// Allowed CIDR ranges.
	AllowedCIDRs []string `json:"allowed_cidrs,omitempty"`
	// AllowMetadata controls access to cloud metadata endpoints
	// (169.254.169.254 for AWS/GCP, 168.63.129.16 for Azure).
	AllowMetadata bool `json:"allow_metadata"`
	// AllowedIPv6s are allowed IPv6 addresses.
	AllowedIPv6s []net.IP `json:"allowed_ipv6s,omitempty"`
	// AllowedDNSServers are the allowed DNS server IPs.
	AllowedDNSServers []net.IP `json:"allowed_dns_servers,omitempty"`
}
