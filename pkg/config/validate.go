package config

import (
	"fmt"
	"net"
	"strings"
)

// Validate checks a PolicyConfig for correctness.
func Validate(cfg *PolicyConfig) error {
	if cfg.Version != "" && cfg.Version != "1" {
		return fmt.Errorf("unsupported config version: %q (supported: \"1\")", cfg.Version)
	}

	if cfg.Mode != "" && cfg.Mode != "trace" && cfg.Mode != "monitor" {
		return fmt.Errorf("invalid mode: %q (must be \"trace\" or \"monitor\")", cfg.Mode)
	}

	for _, ip := range cfg.Rules.Network.AllowedIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		// Try parsing as CIDR
		if strings.Contains(ip, "/") {
			if _, _, err := net.ParseCIDR(ip); err != nil {
				return fmt.Errorf("invalid CIDR in allowed_ips: %q: %w", ip, err)
			}
			continue
		}
		// Try parsing as IP
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid IP address in allowed_ips: %q", ip)
		}
	}

	for _, host := range cfg.Rules.Network.AllowedHosts {
		if strings.TrimSpace(host) == "" {
			return fmt.Errorf("empty hostname in allowed_hosts")
		}
	}

	for _, proc := range cfg.Rules.Network.AllowedProcesses {
		if strings.TrimSpace(proc) == "" {
			return fmt.Errorf("empty process name in allowed_processes")
		}
	}

	for _, profile := range cfg.Rules.Network.Profiles {
		if strings.TrimSpace(profile.Process) == "" {
			return fmt.Errorf("empty process name in network profiles")
		}
	}

	for _, server := range cfg.Rules.DNS.AllowedServers {
		server = strings.TrimSpace(server)
		if server == "" {
			return fmt.Errorf("empty DNS server in allowed_servers")
		}
		if net.ParseIP(server) == nil {
			return fmt.Errorf("invalid DNS server IP: %q", server)
		}
	}

	for _, chain := range cfg.Rules.Process.BlockedChains {
		if strings.TrimSpace(chain.Process) == "" {
			return fmt.Errorf("empty process name in blocked_chains")
		}
		if len(chain.Ancestors) == 0 {
			return fmt.Errorf("blocked_chains entry for %q must have at least one ancestor", chain.Process)
		}
	}

	return nil
}
