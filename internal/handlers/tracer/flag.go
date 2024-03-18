package tracer

import (
	"errors"

	"github.com/spf13/cobra"
)

func parseFlags(cmd *cobra.Command, mode string, dc []byte) error {
	mode = cmd.Flag("mode").Value.String()
	if mode == "" {
		return errors.New("[mode] flag is required")
	}

	var allowedHosts = cmd.Flag("allowed-hosts").Value.String()
	var allowedIPAddr = cmd.Flag("allowed-ips").Value.String()

	if allowedIPAddr == "" || allowedHosts == "" {
		return errors.New("no allowed hosts or IP addreses provided")
	}

	return nil
}
