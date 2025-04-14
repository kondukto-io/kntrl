package cli

import (
	"os"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"
)

func initStatusCommand() *cobra.Command {
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Print kntrl daemon status",
		Run: func(cmd *cobra.Command, args []string) {
			if _, err := os.Stat(pidfile); err != nil {
				qwm(0, "kntrl is not running!")
			}

			data, err := os.ReadFile(pidfile)
			if err != nil {
				qwe(127, err, "failed to read pidfile")
			}

			pid, err := strconv.Atoi(string(data))
			if err != nil {
				qwe(127, err, "failed to convert pid")
			}

			process, err := os.FindProcess(pid)
			if err != nil {
				qwe(127, err, "failed to find process id -- is kntrl running?")
			}

			if err := process.Signal(syscall.Signal(0)); err != nil {
				qwm(127, "kntrl is not running!")

				if err := os.Remove(pidfile); err != nil {
					qwe(127, err, "failed to remove pidfile")
				}
			}

			qwm(0, "Running with PID: "+strconv.Itoa(pid))

		},
	}

	return statusCmd
}
