package tracer

// events_network.go handles IPv4 and IPv6 network connection events from the
// eBPF ring buffers. For each connection event, it resolves the destination IP
// to a domain name (using the DNS cache or reverse DNS), evaluates the OPA
// policy, and either allows or blocks the connection by updating the BPF map.

import (
	"bytes"
	"context"
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
//  2. Skips DNS traffic (port 53) since that's handled by the DNS monitor
//  3. Evaluates OPA policy in trace mode (pass-through in monitor mode)
//  4. Updates the BPF allowed-IP map for passing connections
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

		// Skip DNS traffic — already captured by the DNS event monitor.
		if event.Dport == 53 {
			continue
		}

		// Resolve the actual executable name from /proc/<pid>/exe, falling
		// back to the kernel-reported task name.
		var policyStatus = domain.EventPolicyStatusPass
		taskname := utils.TrimNullBytes(event.Task)
		if exeName := utils.ResolveCommFromExe(event.Pid); exeName != "" {
			taskname = exeName
		}
		if taskname == progName {
			continue
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

		// In trace mode, evaluate OPA policy and update the BPF allow map
		// for connections that pass. In monitor mode, everything passes.
		if rt.tracerMode != domain.TracerModeMonitor {
			result, err := rt.policyPtr.Load().EvalEventCached(context.Background(), reportEvent)
			if err != nil {
				logger.Log.Warnf("policy eval failed (skipping): %v", err)
				continue
			}
			if result {
				policyStatus = domain.EventPolicyStatusPass
				if err := rt.allowedIPMap.Put(event.Daddr, uint32(1)); err != nil {
					logger.Log.Warnf("failed to update allow list (map): %v", err)
				} else {
					logger.Log.Infof("ip [%d] added into allowed list", event.Daddr)
				}
			} else {
				policyStatus = domain.EventPolicyStatusBlock
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
// as the IPv4 loop but handles 128-bit addresses and updates the IPv6 allow map.
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
		if taskname == progName {
			continue
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
			result, err := rt.policyPtr.Load().EvalEventCached(context.Background(), reportEvent)
			if err != nil {
				logger.Log.Debugf("ipv6 policy eval failed: %v", err)
				continue
			}
			if result {
				policyStatus = domain.EventPolicyStatusPass
				// Dynamically allow this IPv6 address in the BPF map.
				if rt.allowedIPv6Map != nil {
					var addrKey [16]byte
					copy(addrKey[:], event.Daddr[:])
					if err := rt.allowedIPv6Map.Put(addrKey, uint32(1)); err != nil {
						logger.Log.Warnf("failed to update ipv6 allow list: %v", err)
					}
				}
			} else {
				policyStatus = domain.EventPolicyStatusBlock
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
