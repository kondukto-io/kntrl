package config

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"strings"

	"github.com/kondukto-io/kntrl/internal/core/domain"
)

const (
	localLoopback = "127.0.0.1"
	linkLocal     = "169.254.169.254"
	azureMeta     = "168.63.129.16"
)

// ToOPAData converts a PolicyConfig into the JSON byte slice expected by policy.New().
// It performs system enrichment: DNS servers, loopback IPs, host-to-IP resolution.
func ToOPAData(cfg *PolicyConfig) ([]byte, *domain.Data, error) {
	hosts, dnsIPs := getDNSServers()

	// Merge configured hosts
	hosts = append(hosts, cfg.Rules.Network.AllowedHosts...)

	// Parse IPs: separate exact IPs from CIDRs
	var ips []net.IP
	var cidrs []string

	// Add DNS server IPs
	ips = append(ips, dnsIPs...)

	// Parse configured IPs/CIDRs
	for _, ipStr := range cfg.Rules.Network.AllowedIPs {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}
		if strings.Contains(ipStr, "/") {
			cidrs = append(cidrs, ipStr)
		} else if ip := net.ParseIP(ipStr); ip != nil {
			ips = append(ips, ip.To4())
		}
	}

	// Resolve hosts to IPs
	ips = append(ips, host2ip(hosts)...)

	// Append system IPs
	ips = append(ips,
		net.ParseIP(localLoopback).To4(),
		net.ParseIP(linkLocal).To4(),
		net.ParseIP(azureMeta).To4(),
	)

	// Determine boolean flags with defaults
	allowLocalRanges := true
	if cfg.Rules.Network.AllowLocalRanges != nil {
		allowLocalRanges = *cfg.Rules.Network.AllowLocalRanges
	}
	allowGithubMeta := false
	if cfg.Rules.Network.AllowGithubMeta != nil {
		allowGithubMeta = *cfg.Rules.Network.AllowGithubMeta
	}

	data := &domain.Data{
		AllowedHosts:       dedup(hosts),
		AllowedIPs:         ips,
		AllowGithubMeta:    allowGithubMeta,
		AllowLocalIPRanges: allowLocalRanges,
		AllowedProcesses:   cfg.Rules.Network.AllowedProcesses,
		AllowedCIDRs:       cidrs,
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, nil, err
	}

	return dataBytes, data, nil
}

func host2ip(hosts []string) (ipl []net.IP) {
	for _, h := range hosts {
		ip, err := net.LookupIP(h)
		if err != nil {
			continue
		}
		for _, v := range ip {
			if ipv4 := v.To4(); ipv4 != nil {
				ipl = append(ipl, ipv4)
			}
		}
	}
	return
}

func getDNSServers() (hosts []string, ips []net.IP) {
	const resolvconf = "/etc/resolv.conf"

	file, err := os.Open(resolvconf)
	if err != nil {
		return nil, nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) >= 2 && fields[0] == "nameserver" {
			if ok := net.ParseIP(fields[1]); ok == nil {
				hosts = append(hosts, fields[1])
			} else {
				ips = append(ips, net.ParseIP(fields[1]))
			}
		}
	}

	return hosts, ips
}
