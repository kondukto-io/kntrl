package tracer

// events_sni.go handles TLS Server Name Indication (SNI) events captured by
// the eBPF program from the TLS ClientHello handshake. SNI reveals the actual
// domain a client is connecting to before encryption starts, which is more
// reliable than reverse DNS for identifying destinations behind CDNs/load
// balancers.

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/kondukto-io/kntrl/internal/core/domain"
	"github.com/kondukto-io/kntrl/pkg/logger"
	"github.com/kondukto-io/kntrl/pkg/utils"
)

// sniEventLoop reads SNI events from the ring buffer and populates the forward
// DNS cache with SNI→IP mappings. This ensures that when subsequent IPv4
// connection events arrive, the IP can be resolved to the real domain name
// (from SNI) instead of falling through to reverse DNS which often returns
// CDN hostnames (e.g. "cdn-123.cloudfront.net" instead of "api.example.com").
func (rt *tracerRuntime) sniEventLoop(reader *ringbuf.Reader) {
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			logger.Log.Errorf("failed to read sni ringbuf event: %v", err)
			continue
		}

		var event domain.SNIEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			logger.Log.Debugf("failed to parse sni event: %v", err)
			continue
		}

		sni := trimNullBytesLong(event.SNI[:])
		if sni != "" {
			// Cache the SNI→IP mapping so that the IPv4 event handler can
			// resolve this IP to the real domain without reverse DNS.
			ipStr := utils.IntToIP(event.Daddr).String()
			utils.CacheSNI(ipStr, sni)
		}
		logger.Log.Infof("[sni] pid=%d dst=%s:%d sni=%s",
			event.Pid, utils.IntToIP(event.Daddr), event.Dport, sni)
	}
}
