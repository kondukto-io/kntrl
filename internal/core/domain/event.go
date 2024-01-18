package domain

// Event is a common event interface
type Event struct {
	TsUs uint64
	Pid  uint32
	Af   uint16 // Address Family
	Task [16]byte
}

// IP4Event represents a socket connect event from AF_INET(4)
type IP4Event struct {
	Event
	Daddr uint32
	Dport uint16
	//Saddr uint32
	//Sport uint16
}
