package ebpfman

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/kondukto-io/kntrl/pkg/logger"
)

// Load loads the EBPF collection
func (e *EBPF) Load(collection string) error {
	var err error
	e.Spec, err = ebpf.LoadCollectionSpec(collection)
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
