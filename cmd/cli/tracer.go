package cli

import (
	"os"
	"os/exec"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/kondukto-io/kntrl/internal/handlers/tracer"
)

const pidfile = "/var/run/kntrl.pid"

func initTracerCommand() *cobra.Command {
	tracerCMD := &cobra.Command{
		Use:   "run",
		Short: "Starts the TCP/UDP tracer",
		Run: func(cmd *cobra.Command, args []string) {
			if err := tracer.Run(*cmd); err != nil {
				qwe(exitCodeError, err, "failed to run tracer")
			}
			// if daemonize == true
			// call func daemonize ( args... )
		},
	}

	tracerCMD.Flags().String("mode", "monitor", "trace || monitor")
	tracerCMD.Flags().String("hosts", "", "enter ip or hostname (192.168.0.100, example.com, .github.com)")
	tracerCMD.Flags().Bool("allow-local-ranges", true, "allows access to local IP ranges")
	tracerCMD.Flags().Bool("allow-github-meta", false, "allows access to GitHub meta IP ranges (https://api.github.com/meta)")
	tracerCMD.Flags().Bool("daemonize", false, "daemonize process")
	tracerCMD.Flags().String("allowed-hosts", "", "enter allowed hostnames (example.com, .github.com)")
	tracerCMD.Flags().String("allowed-ips", "", "enter allowed IP addresses")
	tracerCMD.Flags().StringP("output-file-name", "o", "/tmp/kntrl.out", "output file name")

	return tracerCMD
}

func daemonize(command string, args []string) error {
	switch command {
	case "start":
		if _, err := os.Stat(pidfile); err == nil {
			qwm(1, "Already running or pidfile exist.")
		}

		cmd := exec.Command(os.Args[0], args...)
		// sudo ./kntrl run --mode=trace --allowed-hosts=download.kondukto.io --allow-github-meta=true
		cmd.Start()
		savePID(cmd.Process.Pid)
		qwm(0, "process started")
	}

	return nil
}

func savePID(pid int) {
	file, err := os.Create(pidfile)
	if err != nil {
		qwe(exitCodeError, err, "Unable to write pid file")
	}
	defer file.Close()

	_, err = file.WriteString(strconv.Itoa(pid))
	if err != nil {
		qwe(exitCodeError, err, "Unable to write pid file")
	}

	file.Sync()
}
