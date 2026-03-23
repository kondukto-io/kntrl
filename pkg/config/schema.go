package config

// PolicyConfig is the top-level YAML configuration structure.
type PolicyConfig struct {
	Version  string          `yaml:"version"`
	Mode     string          `yaml:"mode"`
	Rules    RulesConfig     `yaml:"rules"`
	Webhooks []WebhookConfig `yaml:"webhooks"`
	APIKey   string          `yaml:"api_key"`
	APIURL   string          `yaml:"api_url"`
}

// WebhookConfig represents a webhook alerting destination.
type WebhookConfig struct {
	URL     string            `yaml:"url"`
	Headers map[string]string `yaml:"headers"`
	Events  []string          `yaml:"events"` // "block", "all"
}

// RulesConfig contains all rule categories.
type RulesConfig struct {
	Network NetworkRules `yaml:"network"`
	Process ProcessRules `yaml:"process"`
	DNS     DNSRules     `yaml:"dns"`
	File    FileRules    `yaml:"file"`
}

// FileRules contains file access monitoring policy rules.
type FileRules struct {
	Enabled          *bool    `yaml:"enabled"`
	MonitoredPaths   []string `yaml:"monitored_paths"`
	ProtectedPaths   []string `yaml:"protected_paths"`
	MonitoredEnvVars []string `yaml:"monitored_env_vars"`
}

// DNSRules contains DNS monitoring policy rules.
type DNSRules struct {
	AllowedServers []string `yaml:"allowed_servers"`
}

// ProcessRules contains process monitoring policy rules.
type ProcessRules struct {
	Enabled            *bool                `yaml:"enabled"` // default true
	BlockedChains      []BlockedChainConfig `yaml:"blocked_chains"`
	BlockedExecutables []string             `yaml:"blocked_executables"`
}

// BlockedChainConfig defines a process ancestry chain to block.
type BlockedChainConfig struct {
	Process   string   `yaml:"process"`
	Ancestors []string `yaml:"ancestors"`
}

// NetworkRules contains network-related policy rules.
type NetworkRules struct {
	AllowedHosts     []string         `yaml:"allowed_hosts"`
	AllowedIPs       []string         `yaml:"allowed_ips"`
	AllowLocalRanges *bool            `yaml:"allow_local_ranges"`
	AllowGithubMeta  *bool            `yaml:"allow_github_meta"`
	AllowMetadata    *bool            `yaml:"allow_metadata"`
	AllowedProcesses []string         `yaml:"allowed_processes"`
	Profiles         []ProcessProfile `yaml:"profiles"`
}

// ProcessProfile defines per-process network access rules.
type ProcessProfile struct {
	Process      string   `yaml:"process"`
	AllowedHosts []string `yaml:"allowed_hosts"`
	AllowedIPs   []string `yaml:"allowed_ips"`
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
	APIKey           string
	APIURL           string
}
