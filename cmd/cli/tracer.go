package cli

import (
	"github.com/kondukto-io/kntrl/internal/handlers/tracer"
	"github.com/spf13/cobra"
)

func initTracerCommand() *cobra.Command {
	tracerCMD := &cobra.Command{
		Use:   "run",
		Short: "Starts the TCP/UDP tracer",
		Run: func(cmd *cobra.Command, args []string) {
			if err := tracer.Run(*cmd); err != nil {
				qwe(exitCodeError, err, "failed to run tracer")
			}
		},
	}

	tracerCMD.Flags().String("mode", "monitor", "trace || monitor")
	tracerCMD.Flags().String("hosts", "", "enter ip or hostname (192.168.0.100, example.com, .github.com)")
	tracerCMD.Flags().StringP("output-file-name", "o", "/tmp/kntrl.out", "output file name")

	return tracerCMD
}
