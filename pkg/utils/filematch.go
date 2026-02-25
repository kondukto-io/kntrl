package utils

import (
	"path/filepath"
	"strings"
)

// MatchesMonitoredPath checks if filename matches any monitored path.
// - Exact match: "/etc/shadow" matches "/etc/shadow"
// - Prefix match: "/root/.ssh/" matches "/root/.ssh/id_rsa"
func MatchesMonitoredPath(filename string, monitoredPaths []string) (bool, string) {
	cleaned := filepath.Clean(filename)
	for _, p := range monitoredPaths {
		if p == cleaned {
			return true, p
		}
		if strings.HasSuffix(p, "/") && strings.HasPrefix(cleaned, p) {
			return true, p
		}
	}
	return false, ""
}
