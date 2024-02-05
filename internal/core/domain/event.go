package domain

// Event is a common event interface
type Event struct {
	TsUs uint64   //
	Pid  uint32   // process id
	Af   uint16   // Address Family
	Task [16]byte // task name
}

// IP4Event represents a socket connect event from AF_INET(4)
type IP4Event struct {
	Event
	Daddr uint32 // Destination address
	Dport uint16 // Destination port
	// Saddr uint32
	// Sport uint16
}

// ReportEvent represents a report event
type ReportEvent struct {
	ProcessID          uint32   `json:"pid"`
	TaskName           string   `json:"task_name"`
	Protocol           string   `json:"proto"`
	DestinationAddress string   `json:"daddr"`
	DestinationPort    uint16   `json:"dport"`
	Domains            []string `json:"domains"`
	Policy             string   `json:"policy"`
}

const (
	// EventPolicyStatusPass is the pass status of the event
	EventPolicyStatusPass = "pass"

	// EventPolicyStatusBlock is the block status of the event
	EventPolicyStatusBlock = "block"
)

const (
	// EventProtocolTCP is the TCP protocol
	EventProtocolTCP = "tcp"
)

const (
	// ModeTypeMonitor is the monitor mode
	ModeTypeMonitor = "monitor"

	// ModeTypePrevent is the prevent mode
	ModeTypePrevent = "prevent"

	// ModeIndexMonitor is the index of the monitor mode
	ModeIndexMonitor = 0

	// ModeIndexPrevent is the index of the prevent mode
	ModeIndexPrevent = 1
)
