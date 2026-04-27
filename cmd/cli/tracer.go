package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/kondukto-io/kntrl/internal/handlers/tracer"
)

const (
	pidfile = "/var/run/kntrl.pid"
	logfile = "/var/log/kntrl.log"
)

var daemon = false

func initTracerCommand() *cobra.Command {
	tracerCMD := &cobra.Command{
		Use:   "start",
		Short: "Start kntrl",
		Run: func(cmd *cobra.Command, args []string) {
			daemonMode, _ := cmd.Flags().GetBool("daemonize")
			if daemonMode {
				daemon = true
				if err := daemonize(os.Args[1:]); err != nil {
					qwe(exitCodeError, err, "failed to daemonize")
				}
				return
			}

			if err := tracer.Run(*cmd); err != nil {
				qwe(exitCodeError, err, "failed to run kntrl")
			}
		},
	}

	tracerCMD.Flags().String("mode", "monitor", "trace || monitor")
	tracerCMD.Flags().Bool("allow-local-ranges", true, "allows access to local IP ranges")
	tracerCMD.Flags().Bool("allow-github-meta", false, "allows access to GitHub meta IP ranges (https://api.github.com/meta)")
	tracerCMD.Flags().Bool("allow-metadata", false, "allows access to cloud metadata endpoints (169.254.169.254, 168.63.129.16)")
	tracerCMD.Flags().Bool("monitor-processes", true, "enable process monitoring (fork/exec tracking)")
	tracerCMD.Flags().Bool("daemonize", false, "daemonize process")
	tracerCMD.Flags().String("allowed-hosts", "", "enter allowed hostnames (example.com, .github.com)")
	tracerCMD.Flags().String("allowed-ips", "", "enter allowed IP addresses")
	tracerCMD.Flags().StringP("output-file-name", "o", "/tmp/kntrl.out", "output file name")
	tracerCMD.Flags().String("rules-file", "", "path to a YAML rules file")
	tracerCMD.Flags().String("rules-dir", "", "path to a directory of .yaml and/or .rego rule files")
	tracerCMD.Flags().Bool("pretty", false, "pretty-print process events as a tree")
	tracerCMD.Flags().String("api-key", "", "API key for cloud report upload")
	tracerCMD.Flags().String("api-url", "", "API URL for cloud report upload")

	return tracerCMD
}

func daemonize(args []string) error {
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

	logFile, err := os.OpenFile(logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open daemon log file %s: %w", logfile, err)
	}
	defer logFile.Close()

	cmd := exec.Command(os.Args[0], filteredArgs...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil

	if err := cmd.Start(); err != nil {
		return err
	}

	savePID(cmd.Process.Pid)
	qwm(0, fmt.Sprintf("Process started with PID: %d (logs: %s)", cmd.Process.Pid, logfile))

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
