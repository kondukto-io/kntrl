package config

import (
	"os"
	"strings"
)

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
	if override.Rules.Network.AllowMetadata != nil {
		result.Rules.Network.AllowMetadata = override.Rules.Network.AllowMetadata
	}

	// Merge network profiles (append)
	result.Rules.Network.Profiles = append(result.Rules.Network.Profiles, override.Rules.Network.Profiles...)

	// Merge process rules
	if override.Rules.Process.Enabled != nil {
		result.Rules.Process.Enabled = override.Rules.Process.Enabled
	}
	result.Rules.Process.BlockedChains = append(
		result.Rules.Process.BlockedChains,
		override.Rules.Process.BlockedChains...,
	)
	result.Rules.Process.BlockedExecutables = dedup(append(
		result.Rules.Process.BlockedExecutables,
		override.Rules.Process.BlockedExecutables...,
	))

	// Merge DNS rules
	result.Rules.DNS.AllowedServers = dedup(append(
		result.Rules.DNS.AllowedServers,
		override.Rules.DNS.AllowedServers...,
	))

	// Merge file rules
	if override.Rules.File.Enabled != nil {
		result.Rules.File.Enabled = override.Rules.File.Enabled
	}
	result.Rules.File.MonitoredPaths = dedup(append(
		result.Rules.File.MonitoredPaths,
		override.Rules.File.MonitoredPaths...,
	))
	result.Rules.File.ProtectedPaths = dedup(append(
		result.Rules.File.ProtectedPaths,
		override.Rules.File.ProtectedPaths...,
	))
	result.Rules.File.MonitoredEnvVars = dedup(append(
		result.Rules.File.MonitoredEnvVars,
		override.Rules.File.MonitoredEnvVars...,
	))

	// Merge webhooks (append)
	result.Webhooks = append(result.Webhooks, override.Webhooks...)

	if override.APIKey != "" {
		result.APIKey = override.APIKey
	}
	if override.APIURL != "" {
		result.APIURL = override.APIURL
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
	if flags.AllowMetadata != nil {
		result.Rules.Network.AllowMetadata = flags.AllowMetadata
	}

	if flags.APIKey != "" {
		result.APIKey = flags.APIKey
	}
	if flags.APIURL != "" {
		result.APIURL = flags.APIURL
	}

	// Env var fallback (lowest priority)
	if result.APIKey == "" {
		result.APIKey = os.Getenv("KNTRL_API_KEY")
	}
	if result.APIURL == "" {
		result.APIURL = os.Getenv("KNTRL_API_URL")
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
