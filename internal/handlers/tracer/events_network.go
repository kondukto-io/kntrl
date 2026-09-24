package tracer

// events_network.go handles IPv4 and IPv6 network connection events from the
// eBPF ring buffers. For each connection event, it resolves the destination IP
// to a domain name (using the DNS cache or reverse DNS), evaluates the OPA
// policy, and publishes or revokes a grant for that socket and destination.

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/kondukto-io/kntrl/internal/core/domain"
	"github.com/kondukto-io/kntrl/pkg/logger"
	"github.com/kondukto-io/kntrl/pkg/utils"
	"github.com/kondukto-io/kntrl/pkg/webhook"
)

// ipv4EventLoop is the main blocking event loop that reads IPv4 network
// connection events from the ring buffer. It runs on the main goroutine
// and blocks until the ring buffer is closed (on shutdown).
//
// For each event it:
//  1. Resolves the destination IP to domain name(s) via cached DNS
//  2. Checks DNS traffic against the configured resolver list
//  3. Evaluates OPA policy in trace mode (pass-through in monitor mode)
//  4. Updates the socket-scoped BPF grant map
//  5. Reports the event to file, cloud, and webhooks
func (rt *tracerRuntime) ipv4EventLoop(reader *ringbuf.Reader) {
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			logger.Log.Errorf("failed to read ringbuf event: %v", err)
			continue
		}

		var event domain.IP4Event
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			logger.Log.Printf("failed to parse ringbuf event: %v", err)
			continue
		}

		domainAddress := utils.IntToIP(event.Daddr)
		domainNames, err := utils.LookupAndTrimCached(domainAddress)
		if err != nil {
			logger.Log.Debugf("failed to lookup domain: [%s] %v", domainAddress.String(), err)
			domainNames = append(domainNames, ".")
		}

		// Resolve the actual executable name from /proc/<pid>/exe, falling
		// back to the kernel-reported task name.
		var policyStatus = domain.EventPolicyStatusPass
		taskname := utils.TrimNullBytes(event.Task)
		if exeName := utils.ResolveCommFromExe(event.Pid); exeName != "" {
			taskname = exeName
		}

		protocol := utils.GetProtocol(event.Proto)

		var reportEvent = domain.ReportEvent{
			ProcessID:          event.Pid,
			TaskName:           taskname,
			Protocol:           protocol,
			DestinationAddress: utils.IntToIP(event.Daddr).String(),
			DestinationPort:    event.Dport,
			Domains:            domainNames,
			Policy:             policyStatus,
			Ancestors:          rt.procTree.GetAncestors(event.Pid, 32),
		}

		if rt.tracerMode != domain.TracerModeMonitor {
			result, err := rt.evaluateConnection(reportEvent, event.Cookie, event.Proto)
			policyStatus = domain.EventPolicyStatusBlock
			if err != nil {
				logger.Log.Warnf("connection policy failed: %v", err)
			}
			if result {
				policyStatus = domain.EventPolicyStatusPass
			}
			reportEvent.Policy = policyStatus
		}

		// Write to report file.
		rt.report.WriteEvent(reportEvent)

		// Stream to cloud if configured.
		if rt.cloudClient != nil {
			rt.cloudClient.Send("network", int64(event.TsUs), reportEvent)
		}

		// Send webhook alert for all network events (both pass and block).
		if rt.webhookClient != nil {
			rt.webhookClient.Send(webhook.Event{
				Type:      policyStatus,
				Timestamp: int64(event.TsUs),
				Data:      reportEvent,
			})
		}

		logger.Log.Infof("[%d]%s -> %s:%d (%s) [%s]| %s",
			event.Pid, taskname, utils.IntToIP(event.Daddr),
			event.Dport, domainNames, protocol, policyStatus)
	}
}

// ipv6EventLoop processes IPv6 network connection events. It works the same
// as the IPv4 loop but handles 128-bit destination addresses.
func (rt *tracerRuntime) ipv6EventLoop(reader *ringbuf.Reader) {
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			logger.Log.Errorf("failed to read ipv6 ringbuf event: %v", err)
			continue
		}

		var event domain.IP6Event
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			logger.Log.Debugf("failed to parse ipv6 event: %v", err)
			continue
		}

		domainAddress := utils.BytesToIPv6(event.Daddr)
		domainNames, err := utils.LookupAndTrimCached(domainAddress)
		if err != nil {
			logger.Log.Debugf("failed to lookup ipv6 domain: [%s] %v", domainAddress.String(), err)
			domainNames = append(domainNames, ".")
		}

		taskname := utils.TrimNullBytes(event.Task)
		if exeName := utils.ResolveCommFromExe(event.Pid); exeName != "" {
			taskname = exeName
		}

		protocol := utils.GetProtocol(event.Proto)
		var policyStatus = domain.EventPolicyStatusPass

		var reportEvent = domain.ReportEvent{
			ProcessID:          event.Pid,
			TaskName:           taskname,
			Protocol:           protocol,
			DestinationAddress: domainAddress.String(),
			DestinationPort:    event.Dport,
			Domains:            domainNames,
			Policy:             policyStatus,
			Ancestors:          rt.procTree.GetAncestors(event.Pid, 32),
		}

		if rt.tracerMode != domain.TracerModeMonitor {
			result, err := rt.evaluateConnection(reportEvent, event.Cookie, event.Proto)
			policyStatus = domain.EventPolicyStatusBlock
			if err != nil {
				logger.Log.Warnf("IPv6 connection policy failed: %v", err)
			}
			if result {
				policyStatus = domain.EventPolicyStatusPass
			}
			reportEvent.Policy = policyStatus
		}

		rt.report.WriteEvent(reportEvent)
		if rt.cloudClient != nil {
			rt.cloudClient.Send("network", int64(event.TsUs), reportEvent)
		}
		logger.Log.Infof("[%d]%s -> %s:%d (%s) [%s/ipv6]| %s",
			event.Pid, taskname, domainAddress, event.Dport, domainNames, protocol, policyStatus)
	}
}
