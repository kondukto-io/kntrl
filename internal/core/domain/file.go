package domain

// FileEvent is the raw eBPF file access event structure.
type FileEvent struct {
	TsUs     uint64
	Pid      uint32
	Comm     [16]byte
	Filename [256]byte
	Flags    int32
	Blocked  uint8
	Op       uint8
}

// FileReportEvent is the JSON-serializable file event for reporting.
type FileReportEvent struct {
	ProcessID      uint32   `json:"pid"`
	Comm           string   `json:"comm"`
	Filename       string   `json:"filename"`
	Flags          int32    `json:"flags"`
	TimestampUs    uint64   `json:"ts_us"`
	Policy         string   `json:"policy"`
	MatchedEnvVars []string `json:"matched_env_vars,omitempty"`
	Blocked        bool     `json:"blocked,omitempty"`
	Operation      string   `json:"operation,omitempty"`
}

const (
	FileOpOpen   = 0
	FileOpRename = 1
	FileOpUnlink = 2
)
