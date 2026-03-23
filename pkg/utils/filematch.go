package utils

import (
	"path/filepath"
	"strings"
)

// MatchesMonitoredPath checks if filename matches any monitored path.
//
// Matching strategies (evaluated in order):
//  1. Exact match: "/etc/shadow" matches "/etc/shadow"
//  2. Prefix match: "/root/.ssh/" matches "/root/.ssh/id_rsa"
//  3. Suffix match: "/.npmrc" matches "/home/user/.npmrc"
//  4. Contains match: "/.ssh/" matches "/home/user/.ssh/id_rsa"
//
// The suffix/contains rules allow home-relative patterns like "/.npmrc"
// or "/.aws/" to match files under any user's home directory.
func MatchesMonitoredPath(filename string, monitoredPaths []string) (bool, string) {
	cleaned := filepath.Clean(filename)
	for _, p := range monitoredPaths {
		// Exact match
		if p == cleaned {
			return true, p
		}

		isDir := strings.HasSuffix(p, "/")

		// Prefix match for directory patterns
		if isDir && strings.HasPrefix(cleaned, p) {
			return true, p
		}

		// Suffix match: "/.npmrc" matches "/home/user/.npmrc"
		// Contains match: "/.ssh/" matches "/home/user/.ssh/id_rsa"
		if isDir {
			if strings.Contains(cleaned, p) {
				return true, p
			}
		} else {
			if strings.HasSuffix(cleaned, p) {
				return true, p
			}
		}
	}
	return false, ""
}
