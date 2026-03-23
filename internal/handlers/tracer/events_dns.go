package tracer

// events_dns.go handles DNS query and response events captured by the eBPF
// program. It maintains a short-lived deduplication window to avoid flooding
// the report with repeated lookups for the same domain, and populates the
// forward DNS cache so that subsequent network connection events can resolve
// IPs back to their original domain names.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/kondukto-io/kntrl/internal/core/domain"
	"github.com/kondukto-io/kntrl/pkg/logger"
	"github.com/kondukto-io/kntrl/pkg/utils"
)

// dnsEventLoop reads DNS events from the ring buffer and processes both
// queries and responses. It filters out internal/reverse DNS lookups and
// deduplicates events within a 2-second window to reduce noise.
//
// For DNS responses, it synchronously populates the forward DNS cache so that
// when the subsequent TCP/TLS connection event arrives, the IP can be mapped
// back to the original domain name instead of falling through to reverse DNS
// (which often returns CDN hostnames).
func (rt *tracerRuntime) dnsEventLoop(reader *ringbuf.Reader) {
	// Dedup map: tracks the last time each domain+direction was seen.
	dnsDedup := make(map[string]time.Time)
	const dnsDedupTTL = 2 * time.Second

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			logger.Log.Errorf("failed to read dns ringbuf event: %v", err)
			continue
		}

		var event domain.DNSEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			logger.Log.Debugf("failed to parse dns event: %v", err)
			continue
		}

		qname := strings.TrimPrefix(trimNullBytesLong(event.Qname[:]), ".")

		// Skip reverse DNS (PTR) lookups and internal domains — only forward
		// queries are relevant for security monitoring.
		if strings.Contains(qname, "in-addr.arpa") ||
			strings.Contains(qname, "ip6.arpa") ||
			strings.HasSuffix(qname, ".internal") ||
			qname == "" {
			continue
		}

		// Deduplicate: skip if the same domain+direction was seen within the TTL window.
		now := time.Now()
		isResp := event.IsResponse == 1
		dedupKey := qname + "|q"
		if isResp {
			dedupKey = qname + "|r"
		}
		if lastSeen, ok := dnsDedup[dedupKey]; ok && now.Sub(lastSeen) < dnsDedupTTL {
			continue
		}
		dnsDedup[dedupKey] = now

		reportEvent := domain.DNSReportEvent{
			ProcessID:   event.Pid,
			DNSServer:   utils.IntToIP(event.DNSServerIP).String(),
			QueryDomain: qname,
			QueryType:   event.Qtype,
			IsResponse:  event.IsResponse == 1,
			TimestampUs: event.TsUs,
		}

		// Cache IP→domain mapping synchronously for DNS responses.
		// This MUST be synchronous (not async) to avoid a race where the TCP
		// connect kprobe fires before the async worker populates the cache,
		// causing LookupAndTrimCached to fall through to reverse DNS (PTR)
		// which returns CDN hostnames instead of the original domain.
		if reportEvent.IsResponse && reportEvent.QueryDomain != "" {
			utils.CacheDNSDomain(reportEvent.QueryDomain)

			// Proactively update the BPF allowed IP maps when a DNS response
			// is observed for an allowed host. This prevents a race condition
			// where the cgroup SKB filter drops the first SYN packet because
			// the runtime-resolved IP differs from the startup-resolved IP
			// (common with CDN/load-balanced hosts like github.com).
			if rt.isAllowedHost(qname) {
				rt.addResolvedIPsToMaps(qname)
			}
		}

		rt.report.WriteDNSEvent(reportEvent)
		if rt.cloudClient != nil {
			rt.cloudClient.Send("dns", int64(event.TsUs), reportEvent)
		}
		logger.Log.Infof("[dns] pid=%d server=%s domain=%s response=%v",
			event.Pid, reportEvent.DNSServer, reportEvent.QueryDomain, reportEvent.IsResponse)
	}
}
