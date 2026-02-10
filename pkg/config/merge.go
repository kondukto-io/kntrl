package config

import "strings"

// Merge combines two PolicyConfigs. override takes precedence over base.
// Slices are unioned (deduped). Booleans: override wins if non-nil.
func Merge(base, override *PolicyConfig) *PolicyConfig {
	result := *base

	if override.Version != "" {
		result.Version = override.Version
	}
	if override.Mode != "" {
		result.Mode = override.Mode
	}

	// Merge network rules
	result.Rules.Network.AllowedHosts = dedup(append(
		result.Rules.Network.AllowedHosts,
		override.Rules.Network.AllowedHosts...,
	))
	result.Rules.Network.AllowedIPs = dedup(append(
		result.Rules.Network.AllowedIPs,
		override.Rules.Network.AllowedIPs...,
	))
	result.Rules.Network.AllowedProcesses = dedup(append(
		result.Rules.Network.AllowedProcesses,
		override.Rules.Network.AllowedProcesses...,
	))

	if override.Rules.Network.AllowLocalRanges != nil {
		result.Rules.Network.AllowLocalRanges = override.Rules.Network.AllowLocalRanges
	}
	if override.Rules.Network.AllowGithubMeta != nil {
		result.Rules.Network.AllowGithubMeta = override.Rules.Network.AllowGithubMeta
	}

	return &result
}

// ApplyCLIFlags applies CLI flag values on top of a PolicyConfig.
// CLI flags have the highest precedence.
func ApplyCLIFlags(cfg *PolicyConfig, flags CLIFlags) *PolicyConfig {
	result := *cfg

	if flags.Mode != "" {
		result.Mode = flags.Mode
	}

	if flags.AllowedHosts != "" {
		for _, h := range strings.Split(flags.AllowedHosts, ",") {
			h = strings.TrimSpace(h)
			if h != "" {
				result.Rules.Network.AllowedHosts = append(result.Rules.Network.AllowedHosts, h)
			}
		}
		result.Rules.Network.AllowedHosts = dedup(result.Rules.Network.AllowedHosts)
	}

	if flags.AllowedIPs != "" {
		for _, ip := range strings.Split(flags.AllowedIPs, ",") {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				result.Rules.Network.AllowedIPs = append(result.Rules.Network.AllowedIPs, ip)
			}
		}
		result.Rules.Network.AllowedIPs = dedup(result.Rules.Network.AllowedIPs)
	}

	if flags.AllowLocalRanges != nil {
		result.Rules.Network.AllowLocalRanges = flags.AllowLocalRanges
	}
	if flags.AllowGithubMeta != nil {
		result.Rules.Network.AllowGithubMeta = flags.AllowGithubMeta
	}

	return &result
}

func dedup(s []string) []string {
	seen := make(map[string]bool, len(s))
	result := make([]string, 0, len(s))
	for _, v := range s {
		if v == "" {
			continue
		}
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}
