package ebpfman

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
)

// Load loads the EBPF collection
// func (e *EBPF) Load(collection string) error {
func (e *EBPF) Load(collection []byte) error {
	var err error

	rd := bytes.NewReader(collection)

	e.Spec, err = ebpf.LoadCollectionSpecFromReader(rd)
	if err != nil {
		return fmt.Errorf("failed to load collection spec: %w", err)
	}

	e.Collection, err = ebpf.NewCollection(e.Spec)
	if err != nil {
		return fmt.Errorf("failed to create a new collection: %w", err)
	}

	return nil
}
