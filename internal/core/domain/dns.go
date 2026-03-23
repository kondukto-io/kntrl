package domain

// DNSEvent is the raw eBPF DNS event structure.
type DNSEvent struct {
	TsUs        uint64
	Pid         uint32
	DNSServerIP uint32
	Qname       [256]byte
	Qtype       uint16
	IsResponse  uint8
}

// DNSReportEvent is the JSON-serializable DNS event for reporting.
type DNSReportEvent struct {
	ProcessID   uint32 `json:"pid"`
	DNSServer   string `json:"dns_server"`
	QueryDomain string `json:"query_domain"`
	QueryType   uint16 `json:"query_type"`
	IsResponse  bool   `json:"is_response"`
	TimestampUs uint64 `json:"ts_us"`
}
