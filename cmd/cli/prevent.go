package cli

import (
	eventusecase "github.com/kondukto-io/kntrl/internal/core/usecase/event"
	preventusecase "github.com/kondukto-io/kntrl/internal/core/usecase/prevent"
	preventhandler "github.com/kondukto-io/kntrl/internal/handlers/prevent"
	eventrepo "github.com/kondukto-io/kntrl/internal/repository/events"
	"github.com/spf13/cobra"
)

func initPreventCommand() *cobra.Command {
	preventCMD := &cobra.Command{
		Use:   "prevent",
		Short: "Starts the TCP/UDP prevention",
		Run: func(cmd *cobra.Command, args []string) {
			var eventRepo = eventrepo.New()
			var eventUC = eventusecase.New(eventRepo)
			var uc = preventusecase.New(eventUC, eventRepo)
			if err := preventhandler.Run(*cmd, uc); err != nil {
				qwe(exitCodeError, err, "failed to run prevent")
			}
		},
	}

	preventCMD.Flags().String("hosts", "", "enter ip or hostname (192.168.0.100, example.com, .github.com)")
	preventCMD.Flags().StringP("output-file-name", "o", "/tmp/kntrl.out", "output file name")

	return preventCMD
}
