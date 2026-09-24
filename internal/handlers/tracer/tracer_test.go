//go:build ebpf

package tracer

import (
	"testing"

	"github.com/kondukto-io/kntrl/internal/core/domain"
	ebpfman "github.com/kondukto-io/kntrl/pkg/ebpf"
)

func TestEBPFLoad(t *testing.T) {
	var ebpfClient = ebpfman.New()
	if err := ebpfClient.Load(prog); err != nil {
		t.Fatalf("failed to load ebpf program: %s", err)
	}
	defer ebpfClient.Clean()

	requiredMaps := []string{
		domain.EBPFCollectionMapMode,
		domain.EBPFCollectionMapConnections,
		domain.EBPFCollectionMapAllowedHost,
		domain.EBPFCollectionMapIPV4Events,
	}
	for _, name := range requiredMaps {
		if _, ok := ebpfClient.Collection.Maps[name]; !ok {
			t.Errorf("expected map %q not found in collection", name)
		}
	}

	if len(ebpfClient.Spec.Programs) == 0 {
		t.Error("no programs found in eBPF spec")
	}
}

func TestModeMapUpdate(t *testing.T) {
	var ebpfClient = ebpfman.New()
	if err := ebpfClient.Load(prog); err != nil {
		t.Fatalf("failed to load ebpf program: %s", err)
	}
	defer ebpfClient.Clean()

	modeMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapMode]
	if err := modeMap.Put(uint32(0), uint32(domain.TracerModeIndexTrace)); err != nil {
		t.Fatalf("failed to set mode: %v", err)
	}

	var val uint32
	if err := modeMap.Lookup(uint32(0), &val); err != nil {
		t.Fatalf("failed to lookup mode: %v", err)
	}
	if val != uint32(domain.TracerModeIndexTrace) {
		t.Errorf("expected mode %d, got %d", domain.TracerModeIndexTrace, val)
	}
}
