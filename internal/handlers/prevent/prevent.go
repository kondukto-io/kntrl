package prevent

import (
	_ "embed"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kondukto-io/kntrl/internal/core/port/worker"
	"github.com/kondukto-io/kntrl/pkg/logger"
	"github.com/kondukto-io/kntrl/pkg/utils"
)

var (
	//go:embed bpf_bpfel_x86.o
	prog []byte
)

// Run starts the prevent mode
// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target=$GOARCH  -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../../../bpf/bpf.c -- -I $BPF_HEADERS
func Run(cmd cobra.Command, uc worker.UseCase) error {
	if err := uc.Prepare(prog); err != nil {
		return fmt.Errorf("failed to prepare the worker: %w", err)
	}

	var allowedHosts = cmd.Flag("hosts").Value.String()
	if allowedHosts == "" {
		logger.Log.Debugf("no host provided allowed")
	}

	allowedIPS, err := utils.ParseHosts(allowedHosts)
	if err != nil {
		return fmt.Errorf("failed to parse allowed hosts: %w", err)
	}

	if !utils.IsRoot() {
		return errors.New("you need root privileges to run this program")
	}

	var outputDir = cmd.Flag("output-file-name").Value.String()

	return uc.Start(allowedIPS, outputDir, prog)
}
