package config

// PolicyConfig is the top-level YAML configuration structure.
type PolicyConfig struct {
	Version string      `yaml:"version"`
	Mode    string      `yaml:"mode"`
	Rules   RulesConfig `yaml:"rules"`
}

// RulesConfig contains all rule categories.
type RulesConfig struct {
	Network NetworkRules `yaml:"network"`
	Process ProcessRules `yaml:"process"`
	DNS     DNSRules     `yaml:"dns"`
}

// DNSRules contains DNS monitoring policy rules.
type DNSRules struct {
	AllowedServers []string `yaml:"allowed_servers"`
}

// ProcessRules contains process monitoring policy rules.
type ProcessRules struct {
	Enabled *bool `yaml:"enabled"` // default true
}

// NetworkRules contains network-related policy rules.
type NetworkRules struct {
	AllowedHosts     []string `yaml:"allowed_hosts"`
	AllowedIPs       []string `yaml:"allowed_ips"`
	AllowLocalRanges *bool    `yaml:"allow_local_ranges"`
	AllowGithubMeta  *bool    `yaml:"allow_github_meta"`
	AllowMetadata    *bool    `yaml:"allow_metadata"`
	AllowedProcesses []string `yaml:"allowed_processes"`
}

// CLIFlags represents the values from cobra command flags.
type CLIFlags struct {
	AllowedHosts     string
	AllowedIPs       string
	AllowLocalRanges *bool
	AllowGithubMeta  *bool
	AllowMetadata    *bool
	Mode             string
	RulesFile        string
	RulesDir         string
}
