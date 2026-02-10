package domain

// SNIEvent is the raw eBPF TLS SNI event structure.
type SNIEvent struct {
	TsUs  uint64
	Pid   uint32
	Daddr uint32
	Dport uint16
	SNI   [256]byte
}

// SNIReportEvent is the JSON-serializable SNI event for reporting.
type SNIReportEvent struct {
	ProcessID          uint32 `json:"pid"`
	DestinationAddress string `json:"daddr"`
	DestinationPort    uint16 `json:"dport"`
	SNI                string `json:"sni"`
	TimestampUs        uint64 `json:"ts_us"`
}
