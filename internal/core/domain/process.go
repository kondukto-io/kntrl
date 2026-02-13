package domain

// ProcessEvent is the raw eBPF process event structure.
type ProcessEvent struct {
	TsUs      uint64
	Pid       uint32
	PPid      uint32
	EventType uint8
	Comm      [16]byte
	Filename  [256]byte
	Args      [256]byte
	ArgsLen   uint16
}

// ProcessReportEvent is the JSON-serializable process event for reporting.
type ProcessReportEvent struct {
	ProcessID   uint32 `json:"pid"`
	ParentPID   uint32 `json:"ppid"`
	EventType   string `json:"event_type"` // "fork" or "exec"
	Comm        string `json:"comm"`
	Filename    string `json:"filename,omitempty"`
	Args        string `json:"args,omitempty"`
	TimestampUs uint64 `json:"ts_us"`
}

const (
	ProcessEventTypeFork = 1
	ProcessEventTypeExec = 2
)
