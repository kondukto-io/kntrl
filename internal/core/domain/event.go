package domain

// Event is a common event interface
type Event struct {
	TsUs  uint64   //
	Pid   uint32   // process id
	Af    uint16   // Address Family
	Task  [16]byte // task name
	Proto uint8    // Protocol name
}

// IP4Event represents a socket connect event from AF_INET(4)
type IP4Event struct {
	Event
	Daddr uint32 // Destination address
	Dport uint16 // Destination port
	// Saddr uint32
	// Sport uint16
}

// IP6Event represents a socket connect event from AF_INET6
type IP6Event struct {
	Event
	Daddr [16]byte // IPv6 destination address
	Dport uint16   // Destination port
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
	SNI                string   `json:"sni,omitempty"`
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
	EventProtocolUDP = "udp"
)
