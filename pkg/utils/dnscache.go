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

	// Forward DNS cache: IP string → domain name (populated from BPF DNS events)
	fwdDNSCache   = make(map[string]dnsCacheEntry)
	fwdDNSCacheMu sync.RWMutex

	// Async DNS worker channel
	dnsChan     chan string
	dnsOnce     sync.Once
)

// StartDNSWorker initializes the async DNS worker goroutine. Safe to call multiple times.
func StartDNSWorker() {
	dnsOnce.Do(func() {
		dnsChan = make(chan string, 256)
		go func() {
			for domain := range dnsChan {
				CacheDNSDomain(domain)
			}
		}()
	})
}

// CacheDNSDomainAsync queues a domain for async DNS resolution.
// Non-blocking: drops the request if the channel is full.
func CacheDNSDomainAsync(domain string) {
	select {
	case dnsChan <- domain:
	default:
		// Channel full, drop to avoid blocking the hot path
	}
}

// CacheDNSDomain resolves a domain name and caches IP → domain mappings.
// Called when a DNS response event is observed from BPF.
func CacheDNSDomain(domain string) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil {
		return
	}

	fwdDNSCacheMu.Lock()
	defer fwdDNSCacheMu.Unlock()
	for _, ipStr := range ips {
		entry, ok := fwdDNSCache[ipStr]
		if ok && time.Now().Before(entry.expiresAt) {
			// Append domain if not already present
			found := false
			for _, n := range entry.names {
				if n == domain {
					found = true
					break
				}
			}
			if !found {
				entry.names = append(entry.names, domain)
				entry.expiresAt = time.Now().Add(dnsCacheTTL)
				fwdDNSCache[ipStr] = entry
			}
		} else {
			fwdDNSCache[ipStr] = dnsCacheEntry{
				names:     []string{domain},
				expiresAt: time.Now().Add(dnsCacheTTL),
			}
		}
	}
}

// LookupAndTrimCached performs a cached, timeout-bounded reverse DNS lookup.
// It first checks the forward DNS cache (populated from BPF DNS events),
// then falls back to reverse DNS. Results are cached for 5 minutes.
func LookupAndTrimCached(ip net.IP) ([]string, error) {
	key := ip.String()

	// Check forward DNS cache first (from observed DNS responses)
	fwdDNSCacheMu.RLock()
	fwdEntry, ok := fwdDNSCache[key]
	fwdDNSCacheMu.RUnlock()
	if ok && time.Now().Before(fwdEntry.expiresAt) {
		return fwdEntry.names, nil
	}

	// Check reverse DNS cache
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
