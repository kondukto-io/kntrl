package tracer

// helpers.go contains small utility functions used across the tracer package.

import (
	"encoding/binary"
	"net"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/kondukto-io/kntrl/pkg/logger"
)

// logRuntimeEnvironment emits a short summary of the kernel/eBPF environment
// at info level. The intent is to surface prerequisites operators commonly
// get wrong (cgroup v2 mount, BTF availability, memlock limit, effective
// uid) in the daemon log before any BPF call has a chance to fail.
func logRuntimeEnvironment() {
	logger.Log.Info("kntrl runtime environment:")

	if u, err := user.Current(); err == nil {
		logger.Log.Infof("  user: %s (uid=%s gid=%s)", u.Username, u.Uid, u.Gid)
	}

	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		logger.Log.Infof("  kernel: %s (%s)", strings.TrimSpace(string(data)), runtime.GOARCH)
	}

	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err == nil {
		logger.Log.Infof("  memlock: cur=%d max=%d", lim.Cur, lim.Max)
	}

	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		logger.Log.Info("  cgroup v2: mounted at /sys/fs/cgroup")
	} else {
		logger.Log.Warn("  cgroup v2: /sys/fs/cgroup does not look like a unified hierarchy; egress filtering will fail")
	}

	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		logger.Log.Info("  BTF: /sys/kernel/btf/vmlinux available")
	} else {
		logger.Log.Warn("  BTF: /sys/kernel/btf/vmlinux missing; CO-RE relocations may fail on older kernels")
	}
}

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
