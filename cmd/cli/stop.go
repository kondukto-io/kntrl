package cli

import (
	"fmt"
	"os"
	"strconv"

	"github.com/kondukto-io/kntrl/pkg/reporter"

	"github.com/spf13/cobra"
)

func initStopCommand() *cobra.Command {
	statusCmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop kntrl daemon",
		Run: func(cmd *cobra.Command, args []string) {
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

			if err := process.Kill(); err != nil {
				qwe(127, err, "failed to kill the process id")
			}

			if err := os.Remove(pidfile); err != nil {
				qwe(127, err, "failed to remove pidfile")
			}

			fmt.Printf("Process id [%s] stopped", string(data))
			reporter.LoadAndPrint()
		},
	}

	return statusCmd
}
