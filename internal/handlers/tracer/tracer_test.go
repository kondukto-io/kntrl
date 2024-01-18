package tracer

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/kondukto-io/kntrl/internal/core/domain"
	ebpfman "github.com/kondukto-io/kntrl/pkg/ebpf"
)

func TestPolicyCheck(t *testing.T) {
	var ebpfClient = ebpfman.New()
	if err := ebpfClient.Load(prog); err != nil {
		t.Fatalf("failed to load ebpf program: %s", err)
	}

	allowMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapAllow]

	allowedIPS := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("192.168.0.1"),
	}

	event1DomainNames := []string{"status.github.com"}
	event1DestionationAddress := binary.BigEndian.Uint32(net.IP{127, 0, 0, 1}.To16()[12:16])
	println(event1DestionationAddress)
	result := policyCheck(allowMap, allowedIPS, event1DomainNames, event1DestionationAddress)

	if result != domain.EventPolicyStatusPass {
		t.Errorf("Expected policy status to be '%s', got '%s'", domain.EventPolicyStatusPass, result)
	}

	event2DestionationAddress := binary.BigEndian.Uint32(net.IP{192, 168, 0, 2}.To16()[12:16])
	event2DomainNames := []string{"google.com"}

	result = policyCheck(allowMap, allowedIPS, event2DomainNames, event2DestionationAddress)

	if result != domain.EventPolicyStatusBlock {
		t.Errorf("Expected policy status to be '%s', got '%s'", domain.EventPolicyStatusBlock, result)
	}
}
