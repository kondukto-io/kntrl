package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFile_ValidYAML(t *testing.T) {
	cfg, err := LoadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}

	if cfg.Version != "1" {
		t.Errorf("expected version '1', got %q", cfg.Version)
	}
	if cfg.Mode != "trace" {
		t.Errorf("expected mode 'trace', got %q", cfg.Mode)
	}
	if len(cfg.Rules.Network.AllowedHosts) != 2 {
		t.Errorf("expected 2 allowed hosts, got %d", len(cfg.Rules.Network.AllowedHosts))
	}
	if len(cfg.Rules.Network.AllowedIPs) != 2 {
		t.Errorf("expected 2 allowed IPs, got %d", len(cfg.Rules.Network.AllowedIPs))
	}
	if cfg.Rules.Network.AllowLocalRanges == nil || *cfg.Rules.Network.AllowLocalRanges != true {
		t.Error("expected allow_local_ranges to be true")
	}
	if cfg.Rules.Network.AllowGithubMeta == nil || *cfg.Rules.Network.AllowGithubMeta != false {
		t.Error("expected allow_github_meta to be false")
	}
	if len(cfg.Rules.Network.AllowedProcesses) != 2 {
		t.Errorf("expected 2 allowed processes, got %d", len(cfg.Rules.Network.AllowedProcesses))
	}
}

func TestLoadFile_MinimalYAML(t *testing.T) {
	cfg, err := LoadFile("testdata/minimal.yaml")
	if err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}

	if cfg.Version != "1" {
		t.Errorf("expected version '1', got %q", cfg.Version)
	}
	if cfg.Rules.Network.AllowLocalRanges != nil {
		t.Error("expected allow_local_ranges to be nil (unset)")
	}
	if len(cfg.Rules.Network.AllowedHosts) != 1 {
		t.Errorf("expected 1 allowed host, got %d", len(cfg.Rules.Network.AllowedHosts))
	}
}

func TestLoadFile_NonExistent(t *testing.T) {
	_, err := LoadFile("testdata/does_not_exist.yaml")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	cfg, err := LoadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}
	if err := Validate(cfg); err != nil {
		t.Errorf("Validate failed for valid config: %v", err)
	}
}

func TestValidate_InvalidIP(t *testing.T) {
	cfg, err := LoadFile("testdata/invalid_ip.yaml")
	if err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}
	if err := Validate(cfg); err == nil {
		t.Error("expected validation error for invalid IP")
	}
}

func TestValidate_InvalidVersion(t *testing.T) {
	cfg := &PolicyConfig{Version: "99"}
	if err := Validate(cfg); err == nil {
		t.Error("expected validation error for invalid version")
	}
}

func TestValidate_InvalidMode(t *testing.T) {
	cfg := &PolicyConfig{Mode: "invalid"}
	if err := Validate(cfg); err == nil {
		t.Error("expected validation error for invalid mode")
	}
}

func TestMerge_SliceUnion(t *testing.T) {
	base := &PolicyConfig{
		Rules: RulesConfig{
			Network: NetworkRules{
				AllowedHosts: []string{"a.com", "b.com"},
			},
		},
	}
	override := &PolicyConfig{
		Rules: RulesConfig{
			Network: NetworkRules{
				AllowedHosts: []string{"b.com", "c.com"},
			},
		},
	}

	result := Merge(base, override)
	if len(result.Rules.Network.AllowedHosts) != 3 {
		t.Errorf("expected 3 hosts after merge, got %d: %v", len(result.Rules.Network.AllowedHosts), result.Rules.Network.AllowedHosts)
	}
}

func TestMerge_BoolOverride(t *testing.T) {
	tr := true
	fa := false

	base := &PolicyConfig{
		Rules: RulesConfig{
			Network: NetworkRules{
				AllowLocalRanges: &tr,
			},
		},
	}
	override := &PolicyConfig{
		Rules: RulesConfig{
			Network: NetworkRules{
				AllowLocalRanges: &fa,
			},
		},
	}

	result := Merge(base, override)
	if result.Rules.Network.AllowLocalRanges == nil || *result.Rules.Network.AllowLocalRanges != false {
		t.Error("expected allow_local_ranges to be false after override")
	}
}

func TestMerge_BoolNilNoOverride(t *testing.T) {
	tr := true

	base := &PolicyConfig{
		Rules: RulesConfig{
			Network: NetworkRules{
				AllowLocalRanges: &tr,
			},
		},
	}
	override := &PolicyConfig{}

	result := Merge(base, override)
	if result.Rules.Network.AllowLocalRanges == nil || *result.Rules.Network.AllowLocalRanges != true {
		t.Error("expected allow_local_ranges to remain true when override is nil")
	}
}

func TestApplyCLIFlags_OverridesYAML(t *testing.T) {
	cfg := &PolicyConfig{
		Mode: "monitor",
		Rules: RulesConfig{
			Network: NetworkRules{
				AllowedHosts: []string{"a.com"},
			},
		},
	}

	fa := false
	flags := CLIFlags{
		Mode:            "trace",
		AllowedHosts:    "b.com,c.com",
		AllowGithubMeta: &fa,
	}

	result := ApplyCLIFlags(cfg, flags)
	if result.Mode != "trace" {
		t.Errorf("expected mode 'trace', got %q", result.Mode)
	}
	if len(result.Rules.Network.AllowedHosts) != 3 {
		t.Errorf("expected 3 hosts, got %d", len(result.Rules.Network.AllowedHosts))
	}
	if result.Rules.Network.AllowGithubMeta == nil || *result.Rules.Network.AllowGithubMeta != false {
		t.Error("expected allow_github_meta to be false")
	}
}

func TestLoadDir_MixedFiles(t *testing.T) {
	// Create a temporary directory with yaml and rego files
	dir := t.TempDir()

	yamlContent := `version: "1"
rules:
  network:
    allowed_hosts:
      - "test.com"
`
	regoContent := `package kntrl.network["custom"]
import rego.v1
policy if { true }
`
	os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(yamlContent), 0644)
	os.WriteFile(filepath.Join(dir, "custom.rego"), []byte(regoContent), 0644)
	os.WriteFile(filepath.Join(dir, "skip.txt"), []byte("ignored"), 0644)

	cfg, regoFiles, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir failed: %v", err)
	}

	if len(cfg.Rules.Network.AllowedHosts) != 1 {
		t.Errorf("expected 1 host, got %d", len(cfg.Rules.Network.AllowedHosts))
	}
	if len(regoFiles) != 1 {
		t.Errorf("expected 1 rego file, got %d", len(regoFiles))
	}
}

func TestLoadDir_SkipsTestRego(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "rule.rego"), []byte("package test"), 0644)
	os.WriteFile(filepath.Join(dir, "rule_test.rego"), []byte("package test"), 0644)

	_, regoFiles, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir failed: %v", err)
	}

	if len(regoFiles) != 1 {
		t.Errorf("expected 1 rego file (test should be skipped), got %d", len(regoFiles))
	}
}
