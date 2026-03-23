package utils

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

var environRegexp = regexp.MustCompile(`^/proc/(\d+|self)/environ$`)

// IsEnvironFile checks if path is /proc/*/environ (including /proc/self/environ).
func IsEnvironFile(path string) bool {
	return environRegexp.MatchString(path)
}

// FindMatchingEnvVars reads /proc/<pid>/environ and returns which of the
// monitored var names are present. Only reads var NAMES, never logs values.
func FindMatchingEnvVars(pid uint32, monitoredVars []string) []string {
	if len(monitoredVars) == 0 {
		return nil
	}

	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return nil // process may have exited
	}

	// /proc/<pid>/environ is null-byte separated KEY=VALUE pairs
	envKeys := make(map[string]struct{})
	for _, entry := range strings.Split(string(data), "\x00") {
		if idx := strings.IndexByte(entry, '='); idx > 0 {
			envKeys[entry[:idx]] = struct{}{}
		}
	}

	var matched []string
	for _, v := range monitoredVars {
		if _, ok := envKeys[v]; ok {
			matched = append(matched, v)
		}
	}
	return matched
}
