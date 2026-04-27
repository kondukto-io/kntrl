package tracer

// helpers.go contains small utility functions used across the tracer package.

import (
	"encoding/binary"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/kondukto-io/kntrl/pkg/logger"
)

// readyEnvVar names the environment variable through which the daemoniser
// passes the readiness pipe file descriptor to this process. Kept in sync
// with cmd/cli's readyEnv.
const readyEnvVar = "KNTRL_READY_FD"

// signalReady writes a single byte to the readiness pipe inherited from the
// parent and unsets the env var so child processes don't try to write to the
// same fd.
func signalReady() {
	fdStr := os.Getenv(readyEnvVar)
	if fdStr == "" {
		return
	}
	os.Unsetenv(readyEnvVar)

	fd, err := strconv.Atoi(fdStr)
	if err != nil {
		logger.Log.Warnf("invalid %s value %q: %v", readyEnvVar, fdStr, err)
		return
	}
	f := os.NewFile(uintptr(fd), "ready")
	if f == nil {
		logger.Log.Warnf("invalid readiness fd %d", fd)
		return
	}
	defer f.Close()
	if _, err := f.Write([]byte{1}); err != nil {
		logger.Log.Warnf("failed to signal readiness on fd %d: %v", fd, err)
	}
}

// trimNullBytesLong converts a byte slice to a string, stopping at the first
// NUL byte. Used to extract C-style strings from fixed-size BPF event fields
// (e.g. filenames, command names) that are zero-padded.
func trimNullBytesLong(p []byte) string {
	for i, v := range p {
		if v == 0 {
			return string(p[:i])
		}
	}
	return string(p)
}

// fmtEnvVars formats a list of matched environment variable names for log
// output. Returns an empty string if no vars matched, or " env=[VAR1,VAR2]"
// for inclusion in log lines.
func fmtEnvVars(vars []string) string {
	if len(vars) == 0 {
		return ""
	}
	return " env=[" + strings.Join(vars, ",") + "]"
}

// isAllowedHost checks whether the given domain matches any of the configured
// allowed hosts. Supports exact match and suffix match for wildcard-style
// entries that start with "." (e.g. ".github.com" matches "api.github.com").
func (rt *tracerRuntime) isAllowedHost(domain string) bool {
	for _, h := range rt.cmddata.AllowedHosts {
		if h == domain {
			return true
		}
		if strings.HasPrefix(h, ".") && strings.HasSuffix(domain, h) {
			return true
		}
	}
	return false
}

// addResolvedIPsToMaps resolves the domain to IPs and adds them to the BPF
// allowed IP maps. This ensures the cgroup SKB filter allows packets to IPs
// that were resolved at runtime (which may differ from startup resolution).
func (rt *tracerRuntime) addResolvedIPsToMaps(domain string) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return
	}
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil && rt.allowedIPMap != nil {
			ipUint32 := binary.LittleEndian.Uint32(ipv4)
			if err := rt.allowedIPMap.Put(ipUint32, uint32(1)); err != nil {
				logger.Log.Debugf("dns: failed to add resolved IP %s to allowed map: %v", ip, err)
			} else {
				logger.Log.Infof("dns: proactively allowed IP %s for %s", ip, domain)
			}
		} else if len(ip) == net.IPv6len && rt.allowedIPv6Map != nil {
			var key [16]byte
			copy(key[:], ip)
			if err := rt.allowedIPv6Map.Put(key, uint32(1)); err != nil {
				logger.Log.Debugf("dns: failed to add resolved IPv6 %s to allowed map: %v", ip, err)
			}
		}
	}
}
