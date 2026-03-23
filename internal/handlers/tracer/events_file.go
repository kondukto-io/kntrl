package tracer

// events_file.go handles file operation events (open, rename, unlink, access)
// from the eBPF ring buffer. It applies path-based filtering to reduce noise,
// detects environment variable access via /proc/*/environ reads, and reports
// both flagged and blocked file operations.

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

// fileEventLoop reads file operation events from the ring buffer and applies
// path-based filtering. Events that don't match any monitored path pattern are
// dropped (unless they were already blocked by BPF). Matched events are flagged
// in the report, and /proc/*/environ accesses trigger env var detection.
func (rt *tracerRuntime) fileEventLoop(reader *ringbuf.Reader) {
	hasPathFilter := len(rt.monitoredPaths) > 0

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			logger.Log.Errorf("failed to read file ringbuf event: %v", err)
			continue
		}

		var event domain.FileEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			logger.Log.Debugf("failed to parse file event: %v", err)
			continue
		}

		comm := utils.TrimNullBytes(event.Comm)
		if comm == progName {
			continue // Skip kntrl's own file operations.
		}

		filename := trimNullBytesLong(event.Filename[:])

		// Map the numeric operation type to a human-readable string.
		var opStr string
		switch event.Op {
		case domain.FileOpRename:
			opStr = "rename"
		case domain.FileOpUnlink:
			opStr = "unlink"
		case domain.FileOpAccess:
			opStr = "access"
		default:
			opStr = "open"
		}

		// BPF-blocked events always pass through to the report. For non-blocked
		// events, apply the path filter: only events matching a monitored path
		// (or /proc/*/environ when env var monitoring is active) are reported.
		isFileBlocked := event.Blocked == 1
		if !isFileBlocked {
			isEnvFile := len(rt.monitoredEnvVars) > 0 && utils.IsEnvironFile(filename)
			var matched bool
			var matchedRule string
			if hasPathFilter {
				matched, matchedRule = utils.MatchesMonitoredPath(filename, rt.monitoredPaths)
			}
			if !matched && !isEnvFile {
				logger.Log.Debugf("[file:skip] pid=%d comm=%s file=%s (no match)", event.Pid, comm, filename)
				continue
			}
			if matched {
				logger.Log.Debugf("[file:match] pid=%d comm=%s file=%s matched=%s", event.Pid, comm, filename, matchedRule)
			}
		}

		reportEvent := domain.FileReportEvent{
			ProcessID:   event.Pid,
			Comm:        comm,
			Filename:    filename,
			Flags:       event.Flags,
			TimestampUs: event.TsUs,
			Policy:      "flag",
			Operation:   opStr,
		}

		if isFileBlocked {
			reportEvent.Policy = domain.EventPolicyStatusBlock
			reportEvent.Blocked = true
			logger.Log.Warnf("[file:block:bpf] pid=%d comm=%s file=%s op=%s KILLED",
				event.Pid, comm, filename, opStr)
		}

		// Detect environment variable access when a process reads
		// /proc/*/environ and we have env vars configured for monitoring.
		isEnvFile := len(rt.monitoredEnvVars) > 0 && utils.IsEnvironFile(filename)
		if isEnvFile {
			if vars := utils.FindMatchingEnvVars(event.Pid, rt.monitoredEnvVars); len(vars) > 0 {
				reportEvent.MatchedEnvVars = vars
			}
		}

		rt.report.WriteFileEvent(reportEvent)
		if rt.cloudClient != nil {
			rt.cloudClient.Send("file", int64(event.TsUs), reportEvent)
		}

		// Send webhook alerts for both flagged and blocked file events.
		if rt.webhookClient != nil {
			eventType := "file_flag"
			if isFileBlocked {
				eventType = "file_block"
			}
			rt.webhookClient.Send(webhook.Event{
				Type:      eventType,
				Timestamp: int64(event.TsUs),
				Data:      reportEvent,
			})
		}

		if !isFileBlocked {
			logger.Log.Infof("[file] pid=%d comm=%s file=%s op=%s policy=flag%s",
				event.Pid, comm, filename, opStr, fmtEnvVars(reportEvent.MatchedEnvVars))
		}
	}
}
