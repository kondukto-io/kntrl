package events

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/kondukto-io/kntrl/pkg/logger"
)

// Load loads the EBPF collection
// func (e *EBPF) Load(collection string) error {
func (e *EbpfRepo) load(collection []byte) error {
	var err error
	rd := bytes.NewReader(collection)
	e.Spec, err = ebpf.LoadCollectionSpecFromReader(rd)
	if err != nil {
		logger.Log.Fatalf("failed to loading collection spec: %v", err)
		return fmt.Errorf("failed to loading collection spec: %v", err)
	}

	e.Collection, err = ebpf.NewCollection(e.Spec)
	if err != nil {
		logger.Log.Fatalf("failed to create a new collection: %v", err)
		return fmt.Errorf("failed to create a new collection: %v", err)
	}

	return nil
}
