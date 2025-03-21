package cli

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/kondukto-io/kntrl/internal/handlers/tracer"
)

const pidfile = "/var/run/kntrl.pid"

func initTracerCommand() *cobra.Command {
	tracerCMD := &cobra.Command{
		Use:   "run",
		Short: "Starts the TCP/UDP tracer",
		Run: func(cmd *cobra.Command, args []string) {
			daemonMode, _ := cmd.Flags().GetBool("daemonize")
			if daemonMode {
				if err := daemonize("start", os.Args[1:]); err != nil {
					qwe(exitCodeError, err, "failed to daemonize")
				}
				return
			}

			if err := tracer.Run(*cmd); err != nil {
				qwe(exitCodeError, err, "failed to run tracer")
			}
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
			return err
		}

		filteredArgs := make([]string, 0, len(args))
		for i := 0; i < len(args); i++ {
			if args[i] == "--daemonize" {
				continue
			}
			filteredArgs = append(filteredArgs, args[i])
		}

		cmd := exec.Command(os.Args[0], filteredArgs...)
		cmd.Stdout = nil
		cmd.Stderr = nil
		cmd.Stdin = nil

		if err := cmd.Start(); err != nil {
			return err
		}

		savePID(cmd.Process.Pid)
		qwm(0, "Process started with PID: "+strconv.Itoa(cmd.Process.Pid))

	case "stop":
		data, err := os.ReadFile(pidfile)
		if err != nil {
			return err
		}

		pid, err := strconv.Atoi(string(data))
		if err != nil {
			return err
		}

		process, err := os.FindProcess(pid)
		if err != nil {
			return err
		}

		if err := process.Kill(); err != nil {
			return err
		}

		if err := os.Remove(pidfile); err != nil {
			return err
		}

		qwm(0, "Process stopped")

	case "status":
		if _, err := os.Stat(pidfile); err != nil {
			qwm(0, "Not running")
			return nil
		}

		data, err := os.ReadFile(pidfile)
		if err != nil {
			return err
		}

		pid, err := strconv.Atoi(string(data))
		if err != nil {
			return err
		}

		process, err := os.FindProcess(pid)
		if err != nil {
			qwm(0, "Not running")
			return nil
		}

		if err := process.Signal(syscall.Signal(0)); err != nil {
			qwm(0, "Not running")
			if err := os.Remove(pidfile); err != nil {
				return err
			}
			return nil
		}

		qwm(0, "Running with PID: "+strconv.Itoa(pid))
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
