package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadFile reads a single YAML rules file and returns a PolicyConfig.
func LoadFile(path string) (*PolicyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file %s: %w", path, err)
	}

	var cfg PolicyConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML in %s: %w", path, err)
	}

	return &cfg, nil
}

// LoadDir scans a directory for .yaml/.yml files (merged) and .rego files
// (collected as paths). Returns the merged config and list of external .rego paths.
func LoadDir(dirPath string) (*PolicyConfig, []string, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read rules directory %s: %w", dirPath, err)
	}

	var merged PolicyConfig
	var regoFiles []string

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		fullPath := filepath.Join(dirPath, entry.Name())
		ext := strings.ToLower(filepath.Ext(entry.Name()))

		switch ext {
		case ".yaml", ".yml":
			cfg, err := LoadFile(fullPath)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to load %s: %w", fullPath, err)
			}
			merged = *Merge(&merged, cfg)

		case ".rego":
			// Skip test files
			if strings.HasSuffix(entry.Name(), "_test.rego") {
				continue
			}
			regoFiles = append(regoFiles, fullPath)
		}
	}

	return &merged, regoFiles, nil
}

// LoadAll orchestrates loading from all sources and returns the final merged
// config plus a list of external .rego file paths.
func LoadAll(rulesFile, rulesDir string, flags CLIFlags) (*PolicyConfig, []string, error) {
	var merged PolicyConfig
	var regoFiles []string

	// Load from rules file
	if rulesFile != "" {
		cfg, err := LoadFile(rulesFile)
		if err != nil {
			return nil, nil, err
		}
		merged = *Merge(&merged, cfg)
	}

	// Load from rules directory
	if rulesDir != "" {
		dirCfg, dirRego, err := LoadDir(rulesDir)
		if err != nil {
			return nil, nil, err
		}
		merged = *Merge(&merged, dirCfg)
		regoFiles = append(regoFiles, dirRego...)
	}

	// Apply CLI flags as highest precedence
	merged = *ApplyCLIFlags(&merged, flags)

	// Validate
	if err := Validate(&merged); err != nil {
		return nil, nil, fmt.Errorf("config validation error: %w", err)
	}

	return &merged, regoFiles, nil
}
