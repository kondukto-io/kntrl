package prevent

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/kondukto-io/kntrl/internal/core/domain"

	eventusecase "github.com/kondukto-io/kntrl/internal/core/usecase/event"
	eventrepo "github.com/kondukto-io/kntrl/internal/repository/events"
)

func TestPolicyCheck(t *testing.T) {
	var (
		// go:embed bpf_bpfel_x86.o
		prog []byte
	)

	var eventRepo = eventrepo.New()
	var eventUC = eventusecase.New(eventRepo)

	var worker = useCase{
		eventUC:   eventUC,
		eventRepo: eventRepo,
	}

	if err := worker.Prepare(prog); err != nil {
		t.Fatalf("failed to load program: %v", err)
	}

	allowedIPS := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("192.168.0.1"),
	}

	event1DomainNames := []string{"status.github.com"}
	event1DestionationAddress := binary.BigEndian.Uint32(net.IP{127, 0, 0, 1}.To16()[12:16])
	println(event1DestionationAddress)
	result := worker.policyCheck(allowedIPS, event1DomainNames, event1DestionationAddress)

	if result != domain.EventPolicyStatusPass {
		t.Errorf("Expected policy status to be '%s', got '%s'", domain.EventPolicyStatusPass, result)
	}

	event2DestionationAddress := binary.BigEndian.Uint32(net.IP{192, 168, 0, 2}.To16()[12:16])
	event2DomainNames := []string{"google.com"}

	result = worker.policyCheck(allowedIPS, event2DomainNames, event2DestionationAddress)

	if result != domain.EventPolicyStatusBlock {
		t.Errorf("Expected policy status to be '%s', got '%s'", domain.EventPolicyStatusBlock, result)
	}
}
