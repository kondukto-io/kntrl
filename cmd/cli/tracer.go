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
	tracerCMD.Flags().Bool("allow-local-ranges", true, "allows access to local IP ranges")
	tracerCMD.Flags().Bool("allow-github-meta", false, "allows access to GitHub meta IP ranges (https://api.github.com/meta)")
	tracerCMD.Flags().String("allowed-hosts", "", "enter allowed hostnames (example.com, .github.com)")
	tracerCMD.MarkFlagRequired("allowed-hosts")
	tracerCMD.Flags().String("allowed-ips", "", "enter allowed IP addresses")
	tracerCMD.MarkFlagRequired("allowed-ips")
	tracerCMD.Flags().StringP("output-file-name", "o", "/tmp/kntrl.out", "output file name")

	return tracerCMD
}
