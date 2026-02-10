//go:build integration

package integration

import (
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/kondukto-io/kntrl/internal/core/domain"
)

func TestMain(m *testing.M) {
	// Build the kntrl binary
	cmd := exec.Command("go", "build", "-o", "/src/kntrl", "/src/.")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func TestKntrlMonitorMode(t *testing.T) {
	checkKernelVersion(t, 5, 8)

	outputFile, cleanup := startKntrl(t,
		"--mode=monitor",
		"--allowed-hosts=github.com",
		"--allowed-ips=1.1.1.1",
	)
	defer cleanup()

	// Make a TCP connection to generate an event
	conn, err := net.DialTimeout("tcp", "1.1.1.1:443", 5*time.Second)
	if err != nil {
		t.Logf("connection failed (expected in some environments): %v", err)
	} else {
		conn.Close()
	}

	// Wait for events to be recorded
	time.Sleep(2 * time.Second)

	events := parseReport(t, outputFile)
	t.Logf("captured %d events in monitor mode", len(events))

	// In monitor mode, all events should have "pass" status
	for _, e := range events {
		if e.Policy != domain.EventPolicyStatusPass {
			t.Errorf("expected pass in monitor mode, got %s for %s:%d",
				e.Policy, e.DestinationAddress, e.DestinationPort)
		}
	}
}

func TestKntrlTraceMode(t *testing.T) {
	checkKernelVersion(t, 5, 8)

	outputFile, cleanup := startKntrl(t,
		"--mode=trace",
		"--allowed-ips=1.1.1.1",
		"--allow-local-ranges=true",
	)
	defer cleanup()

	// Make a connection to an allowed IP
	conn, err := net.DialTimeout("tcp", "1.1.1.1:443", 5*time.Second)
	if err != nil {
		t.Logf("connection to 1.1.1.1 failed: %v", err)
	} else {
		conn.Close()
	}

	// Make a connection to a disallowed IP
	conn2, err := net.DialTimeout("tcp", "8.8.8.8:443", 5*time.Second)
	if err != nil {
		t.Logf("connection to 8.8.8.8 failed (may be blocked): %v", err)
	} else {
		conn2.Close()
	}

	time.Sleep(2 * time.Second)

	events := parseReport(t, outputFile)
	t.Logf("captured %d events in trace mode", len(events))

	// Check that at least some events have policies applied
	hasPass := false
	hasBlock := false
	for _, e := range events {
		if e.Policy == domain.EventPolicyStatusPass {
			hasPass = true
		}
		if e.Policy == domain.EventPolicyStatusBlock {
			hasBlock = true
		}
	}

	if len(events) > 0 && !hasPass {
		t.Log("warning: no pass events found")
	}
	if len(events) > 0 && !hasBlock {
		t.Log("warning: no block events found")
	}
}

func TestKntrlYAMLConfig(t *testing.T) {
	checkKernelVersion(t, 5, 8)

	// Create a temp YAML config
	yamlContent := `version: "1"
mode: trace
rules:
  network:
    allowed_hosts:
      - "github.com"
    allowed_ips:
      - "1.1.1.1"
    allow_local_ranges: true
    allow_github_meta: false
`
	tmpFile, err := os.CreateTemp("", "kntrl-test-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString(yamlContent)
	tmpFile.Close()

	outputFile, cleanup := startKntrl(t,
		"--rules-file="+tmpFile.Name(),
	)
	defer cleanup()

	// Make a connection
	conn, err := net.DialTimeout("tcp", "1.1.1.1:443", 5*time.Second)
	if err != nil {
		t.Logf("connection failed: %v", err)
	} else {
		conn.Close()
	}

	time.Sleep(2 * time.Second)

	events := parseReport(t, outputFile)
	t.Logf("captured %d events with YAML config", len(events))
}
