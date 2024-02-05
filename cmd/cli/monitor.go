package cli

import (
	eventusecase "github.com/kondukto-io/kntrl/internal/core/usecase/event"
	monitorusecase "github.com/kondukto-io/kntrl/internal/core/usecase/monitor"
	monitorhandler "github.com/kondukto-io/kntrl/internal/handlers/monitor"
	eventrepo "github.com/kondukto-io/kntrl/internal/repository/events"
	"github.com/spf13/cobra"
)

func initMonitorCommand() *cobra.Command {
	monitorCMD := &cobra.Command{
		Use:   "monitor",
		Short: "Starts the TCP/UDP monitor",
		Run: func(cmd *cobra.Command, args []string) {
			var eventRepo = eventrepo.New()
			var eventUC = eventusecase.New(eventRepo)
			var uc = monitorusecase.New(eventUC, eventRepo)
			if err := monitorhandler.Run(*cmd, uc); err != nil {
				qwe(exitCodeError, err, "failed to run monitor")
			}
		},
	}

	monitorCMD.Flags().String("hosts", "", "enter ip or hostname (192.168.0.100, example.com, .github.com)")
	monitorCMD.Flags().StringP("output-file-name", "o", "/tmp/kntrl.out", "output file name")

	return monitorCMD
}
