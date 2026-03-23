package utils

import (
	"fmt"
	"os"
	"path/filepath"
)

// ResolveCommFromExe reads /proc/[pid]/exe to get the real executable name,
// bypassing the spoofable comm field from BPF (which can be changed via prctl).
func ResolveCommFromExe(pid uint32) string {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return filepath.Base(exe)
}
