package ebpfman

import (
	"github.com/cilium/ebpf"
)

// EBPF is the struct for the EBPF collection
type EBPF struct {
	Collection *ebpf.Collection
	Spec       *ebpf.CollectionSpec
}

// New returns a new EBPF collection
func New() *EBPF {
	return &EBPF{}
}

// Clean cleans up the EBPF collection
func (e *EBPF) Clean() {
	e.Collection.Close()
}
