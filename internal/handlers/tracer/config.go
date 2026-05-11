package tracer

// config.go handles all configuration loading and CLI flag parsing for the
// tracer. It supports two configuration paths:
//   - New: YAML rule files + directories (--rules-file / --rules-dir)
//   - Legacy: CLI flags only (--allowed-hosts, --allowed-ips, etc.)

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/spf13/cobra"

	"github.com/kondukto-io/kntrl/internal/core/domain"
	"github.com/kondukto-io/kntrl/pkg/config"
	"github.com/kondukto-io/kntrl/pkg/parser"
	"github.com/kondukto-io/kntrl/pkg/policy"
)

// loadRunConfig loads the full tracer configuration from either the new YAML
// config system or legacy CLI flags. It returns everything needed to initialize
// the policy engine and eBPF maps.
func loadRunConfig(cmd *cobra.Command) (
	tracerMode string,
	cmddata *domain.Data,
	dataObj []byte,
	externalRegoFiles []string,
	webhookConfigs []config.WebhookConfig,
	policyCfg *config.PolicyConfig,
	err error,
) {
	// Validate tracer mode flag.
	tracerMode, _ = cmd.Flags().GetString("mode")
	if tracerMode == "" {
		return "", nil, nil, nil, nil, nil, errors.New("[mode] flag is required")
	}
	if tracerMode != domain.TracerModeMonitor && tracerMode != domain.TracerModeTrace {
		return "", nil, nil, nil, nil, nil, fmt.Errorf("[mode] flag is invalid: %s", tracerMode)
	}

	rulesFile, _ := cmd.Flags().GetString("rules-file")
	rulesDir, _ := cmd.Flags().GetString("rules-dir")

	if rulesFile != "" || rulesDir != "" {
		// New config system: merge YAML files, directories, and CLI flag overrides.
		cliFlags := gatherCLIFlags(cmd)
		var regoFiles []string
		policyCfg, regoFiles, err = config.LoadAll(rulesFile, rulesDir, cliFlags)
		if err != nil {
			return "", nil, nil, nil, nil, nil, fmt.Errorf("config loading error: %w", err)
		}

		// Allow config file to override mode if CLI didn't set it explicitly.
		if policyCfg.Mode != "" {
			tracerMode = policyCfg.Mode
		}

		dataBytes, data, err := config.ToOPAData(policyCfg)
		if err != nil {
			return "", nil, nil, nil, nil, nil, fmt.Errorf("config conversion error: %w", err)
		}
		return tracerMode, data, dataBytes, regoFiles, policyCfg.Webhooks, policyCfg, nil
	}

	// Legacy path: build configuration from individual CLI flags.
	data, err := parseFlags(cmd)
	if err != nil {
		return "", nil, nil, nil, nil, nil, fmt.Errorf("data json error: %w", err)
	}

	obj, err := json.Marshal(data)
	if err != nil {
		return "", nil, nil, nil, nil, nil, fmt.Errorf("error converting dataobj: %w", err)
	}
	return tracerMode, data, obj, nil, nil, nil, nil
}

// gatherCLIFlags collects all relevant CLI flag values into a CLIFlags struct
// for use by the config loader. Boolean pointer flags are only set if the user
// explicitly passed them on the command line (Changed check).
func gatherCLIFlags(cmd *cobra.Command) config.CLIFlags {
	flags := config.CLIFlags{}

	flags.AllowedHosts, _ = cmd.Flags().GetString("allowed-hosts")
	flags.AllowedIPs, _ = cmd.Flags().GetString("allowed-ips")
	flags.Mode, _ = cmd.Flags().GetString("mode")
	flags.RulesFile, _ = cmd.Flags().GetString("rules-file")
	flags.RulesDir, _ = cmd.Flags().GetString("rules-dir")
	flags.APIKey, _ = cmd.Flags().GetString("api-key")
	flags.APIURL, _ = cmd.Flags().GetString("api-url")

	if cmd.Flags().Changed("allow-local-ranges") {
		val, _ := cmd.Flags().GetBool("allow-local-ranges")
		flags.AllowLocalRanges = &val
	}
	if cmd.Flags().Changed("allow-github-meta") {
		val, _ := cmd.Flags().GetBool("allow-github-meta")
		flags.AllowGithubMeta = &val
	}
	if cmd.Flags().Changed("allow-metadata") {
		val, _ := cmd.Flags().GetBool("allow-metadata")
		flags.AllowMetadata = &val
	}

	return flags
}

// loadConfig performs a full configuration reload from YAML files and CLI
// flags, returning a fresh policy engine and data struct. Used during
// SIGHUP-triggered hot reloads.
func loadConfig(rulesFile, rulesDir string, cliFlags config.CLIFlags, bundleFS fs.FS, externalRegoFiles []string) (*policy.Policy, *domain.Data, error) {
	policyCfg, regoFiles, err := config.LoadAll(rulesFile, rulesDir, cliFlags)
	if err != nil {
		return nil, nil, fmt.Errorf("config loading error: %w", err)
	}

	regoFiles = append(regoFiles, externalRegoFiles...)

	dataBytes, data, err := config.ToOPAData(policyCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("config conversion error: %w", err)
	}

	newPolicy, err := policy.New(bundleFS, dataBytes, policy.WithExternalRego(regoFiles))
	if err != nil {
		return nil, nil, fmt.Errorf("policy init error: %w", err)
	}
	newPolicy.AddQuery("data.kntrl.policy")

	return newPolicy, data, nil
}

// getProcessConfig reads the --monitor-processes flag from the CLI command.
// Returns (value, true) if the flag exists, or (true, false) as default.
func getProcessConfig(cmd *cobra.Command) (bool, bool) {
	monitorProcesses, err := cmd.Flags().GetBool("monitor-processes")
	if err != nil {
		return true, false // default to enabled
	}
	return monitorProcesses, true
}

// resolveCloudConfig determines the API key and URL for cloud uploads.
// It prefers values from the YAML config, falling back to CLI flags
// and environment variables (KNTRL_API_KEY, KNTRL_API_URL).
func resolveCloudConfig(cmd *cobra.Command, policyCfg *config.PolicyConfig, rulesFile, rulesDir string) (string, string) {
	if (rulesFile != "" || rulesDir != "") && policyCfg != nil {
		return policyCfg.APIKey, policyCfg.APIURL
	}
	// Legacy mode: CLI flags with environment variable fallback.
	key, _ := cmd.Flags().GetString("api-key")
	url, _ := cmd.Flags().GetString("api-url")
	if key == "" {
		key = os.Getenv("KNTRL_API_KEY")
	}
	if url == "" {
		url = os.Getenv("KNTRL_API_URL")
	}
	return key, url
}

// parseFlags builds a Data struct from legacy CLI flags (--allowed-hosts,
// --allowed-ips, etc.) for backward compatibility with the old flag-only
// configuration mode.
func parseFlags(cmd *cobra.Command) (*domain.Data, error) {
	allowedHosts, _ := cmd.Flags().GetString("allowed-hosts")
	allowedIPs, _ := cmd.Flags().GetString("allowed-ips")

	if allowedIPs == "" && allowedHosts == "" {
		return nil, errors.New("no allowed hostname or IP addresses provided")
	}

	ghmeta, err := cmd.Flags().GetBool("allow-github-meta")
	if err != nil {
		return nil, err
	}
	localranges, err := cmd.Flags().GetBool("allow-local-ranges")
	if err != nil {
		return nil, err
	}
	allowmeta, err := cmd.Flags().GetBool("allow-metadata")
	if err != nil {
		return nil, err
	}

	return parser.ToDataJson(
		allowedHosts,
		allowedIPs,
		ghmeta,
		localranges,
		allowmeta,
	), nil
}
