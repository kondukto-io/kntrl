package tracer

// events_process.go handles process lifecycle events (fork, exec) from the
// eBPF ring buffer. It maintains the process tree, detects blocked processes
// (both BPF-level and ancestry-based), and monitors environment variable
// inheritance at exec time.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/kondukto-io/kntrl/internal/core/domain"
	"github.com/kondukto-io/kntrl/pkg/logger"
	"github.com/kondukto-io/kntrl/pkg/utils"
	"github.com/kondukto-io/kntrl/pkg/webhook"
)

// processEventLoop reads process events (fork/exec) from the ring buffer and:
//  1. Updates the process ancestry tree for later ancestor-based lookups
//  2. Checks if exec events were already blocked by BPF (kernel-side kill)
//  3. Performs userspace ancestry-based blocking in trace mode
//  4. Detects inherited environment variables at exec time
//  5. Reports all events to file, cloud, and webhooks
func (rt *tracerRuntime) processEventLoop(reader *ringbuf.Reader) {
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			logger.Log.Errorf("failed to read process ringbuf event: %v", err)
			continue
		}

		var event domain.ProcessEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			logger.Log.Debugf("failed to parse process event: %v", err)
			continue
		}

		eventTypeStr := "fork"
		if event.EventType == domain.ProcessEventTypeExec {
			eventTypeStr = "exec"
		}

		// Convert NUL-separated argv to a human-readable space-separated string.
		// ArgsLen from BPF marks the boundary before environment variables.
		argEnd := int(event.ArgsLen)
		if argEnd > len(event.Args) {
			argEnd = len(event.Args)
		}
		argsBytes := bytes.TrimRight(event.Args[:argEnd], "\x00")
		argsStr := strings.ReplaceAll(string(argsBytes), "\x00", " ")

		reportEvent := domain.ProcessReportEvent{
			ProcessID:   event.Pid,
			ParentPID:   event.PPid,
			EventType:   eventTypeStr,
			Comm:        utils.TrimNullBytes(event.Comm),
			Filename:    trimNullBytesLong(event.Filename[:]),
			Args:        argsStr,
			TimestampUs: event.TsUs,
		}

		// Update process tree with every fork/exec so ancestry queries stay current.
		rt.procTree.Update(event.Pid, event.PPid, reportEvent.Comm)

		// Process blocking: only applies to exec events.
		if event.EventType == domain.ProcessEventTypeExec {
			reportEvent.Ancestors = rt.procTree.GetAncestors(event.Pid, 32)

			if event.Blocked == 1 {
				// BPF already killed this process at the kernel level.
				reportEvent.Policy = domain.EventPolicyStatusBlock
				logger.Log.Warnf("[process:block:bpf] pid=%d comm=%s KILLED", event.Pid, reportEvent.Comm)
			} else if rt.tracerMode == domain.TracerModeTrace && isAncestryBlocked(reportEvent.Comm, reportEvent.Ancestors, rt.cmddata.BlockedProcessChains) {
				// Ancestry-based blocking: kill the process from userspace when
				// its command + ancestor chain matches a blocked pattern.
				syscall.Kill(int(event.Pid), syscall.SIGKILL)
				reportEvent.Policy = domain.EventPolicyStatusBlock
				logger.Log.Warnf("[process:block:ancestry] pid=%d comm=%s ancestors=%v KILLED",
					event.Pid, reportEvent.Comm, reportEvent.Ancestors)
			}
		}

		rt.report.WriteProcessEvent(reportEvent)
		if rt.cloudClient != nil {
			rt.cloudClient.Send("process", int64(event.TsUs), reportEvent)
		}

		// Send webhook alerts only for blocked process events.
		if rt.webhookClient != nil && reportEvent.Policy == domain.EventPolicyStatusBlock {
			rt.webhookClient.Send(webhook.Event{
				Type:      "process_block",
				Timestamp: int64(event.TsUs),
				Data:      reportEvent,
			})
		}

		if reportEvent.Policy != domain.EventPolicyStatusBlock {
			logger.Log.Infof("[process] %s pid=%d ppid=%d comm=%s file=%s args=%q",
				eventTypeStr, event.Pid, event.PPid, reportEvent.Comm, reportEvent.Filename, reportEvent.Args)
		}

		// Detect inherited environment variables at exec time by reading
		// /proc/<pid>/environ before the process has a chance to clear them.
		if eventTypeStr == "exec" && len(rt.monitoredEnvVars) > 0 {
			if vars := utils.FindMatchingEnvVars(event.Pid, rt.monitoredEnvVars); len(vars) > 0 {
				rt.report.WriteFileEvent(domain.FileReportEvent{
					ProcessID:      event.Pid,
					Comm:           utils.TrimNullBytes(event.Comm),
					Filename:       "[inherited]",
					TimestampUs:    event.TsUs,
					Policy:         "flag",
					MatchedEnvVars: vars,
				})
				logger.Log.Infof("[env] pid=%d comm=%s inherited env vars: %v",
					event.Pid, reportEvent.Comm, vars)
			}
		}
	}
}

// isAncestryBlocked checks if a process with the given command name and
// ancestor list matches any configured blocked process chain. A chain matches
// when the process name equals chain.Process AND all required ancestors are
// present in the actual ancestry (order-independent).
func isAncestryBlocked(comm string, ancestors []string, chains []domain.BlockedProcessChain) bool {
	for _, chain := range chains {
		if chain.Process != comm {
			continue
		}
		allFound := true
		for _, required := range chain.Ancestors {
			found := false
			for _, actual := range ancestors {
				if required == actual {
					found = true
					break
				}
			}
			if !found {
				allFound = false
				break
			}
		}
		if allFound {
			return true
		}
	}
	return false
}
