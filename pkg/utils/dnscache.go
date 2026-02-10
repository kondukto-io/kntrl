package utils

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	dnsCacheTTL     = 5 * time.Minute
	dnsLookupTimeout = 150 * time.Millisecond
)

type dnsCacheEntry struct {
	names     []string
	err       error
	expiresAt time.Time
}

var (
	dnsCache   = make(map[string]dnsCacheEntry)
	dnsCacheMu sync.RWMutex
)

// LookupAndTrimCached performs a cached, timeout-bounded reverse DNS lookup.
// Results are cached for 5 minutes. Lookups that exceed 150ms are abandoned.
func LookupAndTrimCached(ip net.IP) ([]string, error) {
	key := ip.String()

	// Check cache
	dnsCacheMu.RLock()
	entry, ok := dnsCache[key]
	dnsCacheMu.RUnlock()

	if ok && time.Now().Before(entry.expiresAt) {
		return entry.names, entry.err
	}

	// Cache miss or expired — perform lookup with timeout
	ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
	defer cancel()

	resolver := net.DefaultResolver
	names, err := resolver.LookupAddr(ctx, key)
	if err != nil {
		// Cache the failure too, to avoid repeated slow lookups
		dnsCacheMu.Lock()
		dnsCache[key] = dnsCacheEntry{names: names, err: err, expiresAt: time.Now().Add(30 * time.Second)}
		dnsCacheMu.Unlock()
		return names, err
	}

	for k, v := range names {
		names[k] = strings.TrimSuffix(v, ".")
	}

	dnsCacheMu.Lock()
	dnsCache[key] = dnsCacheEntry{names: names, err: nil, expiresAt: time.Now().Add(dnsCacheTTL)}
	dnsCacheMu.Unlock()

	return names, nil
}
