//go:build integration

package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/kondukto-io/kntrl/internal/core/domain"
)

// startKntrl starts the kntrl binary and returns the output file path and cleanup function.
func startKntrl(t *testing.T, args ...string) (outputFile string, cleanup func()) {
	t.Helper()

	outputFile = fmt.Sprintf("/tmp/kntrl-test-%d.out", time.Now().UnixNano())
	allArgs := append([]string{"start", "-o", outputFile}, args...)

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "/src/kntrl", allArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start kntrl: %v", err)
	}

	// Wait for kntrl to initialize
	time.Sleep(3 * time.Second)

	return outputFile, func() {
		// Send SIGTERM for graceful shutdown
		if cmd.Process != nil {
			cmd.Process.Signal(syscall.SIGTERM)
		}
		cancel()
		cmd.Wait()
		os.Remove(outputFile)
	}
}

// parseReport reads the kntrl output file and returns events.
func parseReport(t *testing.T, path string) []domain.ReportEvent {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open report file: %v", err)
	}
	defer file.Close()

	var events []domain.ReportEvent
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event domain.ReportEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		events = append(events, event)
	}

	return events
}

// checkKernelVersion verifies the running kernel supports required eBPF features.
func checkKernelVersion(t *testing.T, minMajor, minMinor int) {
	t.Helper()
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		t.Fatalf("uname failed: %v", err)
	}

	// Convert int8 array to string
	release := ""
	for _, b := range uname.Release {
		if b == 0 {
			break
		}
		release += string(rune(b))
	}

	var major, minor int
	fmt.Sscanf(release, "%d.%d", &major, &minor)
	if major < minMajor || (major == minMajor && minor < minMinor) {
		t.Skipf("kernel %d.%d < required %d.%d, skipping eBPF test", major, minor, minMajor, minMinor)
	}
}
