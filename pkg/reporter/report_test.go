package reporter

import (
	"os"
	"testing"

	"github.com/kondukto-io/kntrl/internal/core/domain"
)

func TestNewReporter(t *testing.T) {
	// Test case 1: outputFileName is empty
	report := NewReporter("")
	if report.Err != nil {
		t.Errorf("Expected error to be nil, got '%s'", report.Err)
	} else {
		if report.outputFileName != "/tmp/kntrl.out" {
			t.Errorf("Expected outputFileName to be '/tmp/kntrl.out', got '%s'", report.outputFileName)
		} else {
			os.Remove(report.outputFileName)
		}
	}

	// Test case 2: outputFileName is not empty
	report = NewReporter("/tmp/a/b/kntrl.out")
	if report.Err != nil {
		t.Errorf("Expected error to be nil, got '%s'", report.Err)
	} else {
		if report.outputFileName != "/tmp/a/b/kntrl.out" {
			t.Errorf("Expected outputFileName to be '/tmp/a/b/kntrl.out', got '%s'", report.outputFileName)
		} else {
			os.Remove(report.outputFileName)
		}
	}

	println(report.outputFileName)
}

func TestReporter_WriteEvent(t *testing.T) {
	report := NewReporter("/tmp/c/kntrl.out")
	if report.Err != nil {
		t.Errorf("Expected error to be nil, got '%s'", report.Err)
	}

	type caseData struct {
		event domain.ReportEvent
	}

	var cases = []caseData{
		{
			event: domain.ReportEvent{
				ProcessID:          234,
				TaskName:           "",
				Protocol:           domain.EventProtocolTCP,
				DestinationAddress: "127.0.0.1",
				DestinationPort:    80,
				Domains:            []string{"kondukto.io"},
				Policy:             domain.EventPolicyStatusBlock,
			},
		},
		{
			event: domain.ReportEvent{
				ProcessID:          215,
				TaskName:           "",
				Protocol:           domain.EventProtocolTCP,
				DestinationAddress: "127.0.0.1",
				DestinationPort:    443,
				Domains:            []string{"kondukto.io"},
				Policy:             domain.EventPolicyStatusPass,
			},
		},
	}

	for _, c := range cases {
		report.WriteEvent(c.event)
	}

	report.Close()
}
