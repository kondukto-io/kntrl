package config

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"

	"github.com/kondukto-io/kntrl/internal/core/domain"
	"github.com/kondukto-io/kntrl/pkg/github"
	"github.com/kondukto-io/kntrl/pkg/logger"
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

	// Resolve hosts to IPs (both IPv4 and IPv6)
	v4, v6 := host2ip(hosts)
	ips = append(ips, v4...)
	var ipv6s []net.IP
	ipv6s = append(ipv6s, v6...)

	// Append system IPs (loopback always allowed)
	ips = append(ips, net.ParseIP(localLoopback).To4())
	ipv6s = append(ipv6s, net.ParseIP("::1"))

	// Determine boolean flags with defaults
	allowLocalRanges := true
	if cfg.Rules.Network.AllowLocalRanges != nil {
		allowLocalRanges = *cfg.Rules.Network.AllowLocalRanges
	}
	allowGithubMeta := false
	if cfg.Rules.Network.AllowGithubMeta != nil {
		allowGithubMeta = *cfg.Rules.Network.AllowGithubMeta
	}
	allowMetadata := false
	if cfg.Rules.Network.AllowMetadata != nil {
		allowMetadata = *cfg.Rules.Network.AllowMetadata
	}

	// Fetch dynamic GitHub meta IPs if enabled
	if allowGithubMeta {
		actions, web, api, git, err := github.FetchMeta(context.Background())
		if err != nil {
			logger.Log.Warnf("failed to fetch GitHub meta (falling back to embedded data): %v", err)
		} else {
			var dynamicCIDRs []string
			dynamicCIDRs = append(dynamicCIDRs, actions...)
			dynamicCIDRs = append(dynamicCIDRs, web...)
			dynamicCIDRs = append(dynamicCIDRs, api...)
			dynamicCIDRs = append(dynamicCIDRs, git...)
			cidrs = append(cidrs, dynamicCIDRs...)
			logger.Log.Infof("fetched %d GitHub meta CIDRs dynamically", len(dynamicCIDRs))
		}
	}

	// Only add cloud metadata IPs when explicitly opted in
	if allowMetadata {
		ips = append(ips,
			net.ParseIP(linkLocal).To4(),
			net.ParseIP(azureMeta).To4(),
		)
	}

	// Parse allowed DNS servers
	var allowedDNSServers []net.IP
	for _, s := range cfg.Rules.DNS.AllowedServers {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
			allowedDNSServers = append(allowedDNSServers, ip.To4())
		}
	}

	// Convert per-process profiles
	var processProfiles []domain.ProcessProfileData
	for _, p := range cfg.Rules.Network.Profiles {
		profile := domain.ProcessProfileData{
			Process:      p.Process,
			AllowedHosts: p.AllowedHosts,
		}
		for _, ipStr := range p.AllowedIPs {
			ipStr = strings.TrimSpace(ipStr)
			if strings.Contains(ipStr, "/") {
				profile.AllowedCIDRs = append(profile.AllowedCIDRs, ipStr)
			}
		}
		processProfiles = append(processProfiles, profile)
	}

	// Convert blocked process chains
	var blockedChains []domain.BlockedProcessChain
	for _, bc := range cfg.Rules.Process.BlockedChains {
		blockedChains = append(blockedChains, domain.BlockedProcessChain{
			Process:   bc.Process,
			Ancestors: bc.Ancestors,
		})
	}

	data := &domain.Data{
		AllowedHosts:       dedup(hosts),
		AllowedIPs:         ips,
		AllowGithubMeta:    allowGithubMeta,
		AllowLocalIPRanges: allowLocalRanges,
		AllowedProcesses:   cfg.Rules.Network.AllowedProcesses,
		AllowedCIDRs:       cidrs,
		AllowMetadata:      allowMetadata,
		AllowedIPv6s:       ipv6s,
		AllowedDNSServers:  allowedDNSServers,
		ProcessProfiles:      processProfiles,
		BlockedProcessChains: blockedChains,
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, nil, err
	}

	return dataBytes, data, nil
}

func host2ip(hosts []string) (ipv4s []net.IP, ipv6s []net.IP) {
	for _, h := range hosts {
		ip, err := net.LookupIP(h)
		if err != nil {
			continue
		}
		for _, v := range ip {
			if ipv4 := v.To4(); ipv4 != nil {
				ipv4s = append(ipv4s, ipv4)
			} else if len(v) == net.IPv6len {
				ipv6s = append(ipv6s, v)
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
