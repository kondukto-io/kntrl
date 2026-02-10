package domain

// FileEvent is the raw eBPF file access event structure.
type FileEvent struct {
	TsUs     uint64
	Pid      uint32
	Comm     [16]byte
	Filename [256]byte
	Flags    int32
}

// FileReportEvent is the JSON-serializable file event for reporting.
type FileReportEvent struct {
	ProcessID   uint32 `json:"pid"`
	Comm        string `json:"comm"`
	Filename    string `json:"filename"`
	Flags       int32  `json:"flags"`
	TimestampUs uint64 `json:"ts_us"`
}
