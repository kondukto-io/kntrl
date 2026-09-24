package tracer

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/kondukto-io/kntrl/internal/core/domain"
)

// evaluateConnection publishes a grant only for the socket that generated the
// event. Denials revoke that key; no destination can grant another socket access.
func (rt *tracerRuntime) evaluateConnection(event domain.ReportEvent, cookie uint64, proto uint8) (bool, error) {
	rt.networkMu.Lock()
	defer rt.networkMu.Unlock()
	ip := net.ParseIP(event.DestinationAddress)
	if event.DestinationPort == 53 {
		for _, resolver := range rt.cmddata.AllowedDNSServers {
			if resolver.Equal(ip) {
				return true, nil
			}
		}
		return false, nil
	}
	if cookie == 0 || ip == nil {
		return false, fmt.Errorf("missing socket identity or destination")
	}
	key := domain.ConnectionKey{Cookie: cookie, Port: event.DestinationPort, Protocol: proto, Family: 10}
	if v4 := ip.To4(); v4 != nil {
		key.Family = 2
		copy(key.Address[:], v4)
	} else {
		copy(key.Address[:], ip.To16())
	}
	// Evaluate the full input. The former cache omitted policy-relevant fields.
	allowed, err := rt.policyPtr.Load().EvalEvent(context.Background(), event)
	if err != nil || !allowed {
		deleteErr := rt.connections.Delete(key)
		if deleteErr != nil && !errors.Is(deleteErr, ebpf.ErrKeyNotExist) {
			return false, fmt.Errorf("revoke socket grant: %w", deleteErr)
		}
		return false, err
	}
	if err := rt.connections.Put(key, uint32(1)); err != nil {
		return false, fmt.Errorf("publish socket grant: %w", err)
	}
	return true, nil
}
