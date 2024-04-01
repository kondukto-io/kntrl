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
}
