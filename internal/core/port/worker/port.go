package worker 

import (
	"net"
)

type UseCase interface {
	// Prepare prapares ebpf collections
	Prepare(program []byte) error
	// Start starts the prevent mode
	Start(allowedIPS []net.IP, outputDir string, program []byte) error
}
