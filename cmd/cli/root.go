package cli

import (
	"fmt"
	"os"

	"github.com/kondukto-io/kntrl/pkg/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	exitCodeSuccess = 0
	exitCodeError   = 1
)

var (
	verbose   bool
	version   string
	commit    string
	buildDate string
)

var rootCmd = cobra.Command{
	Use:     "kntrl",
	Short:   "Runtime security tool to control and monitor egress/ingress traffic in CI/CD runners",
	Version: versionFormatter(version, commit, buildDate),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		var logLevel = "info"
		if verbose {
			logLevel = "debug"
		}

		logger.SetLevel(logLevel)
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "more logs")

	_ = viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(args []string) {
	rootCmd.SetArgs(args)

	rootCmd.AddCommand(initTracerCommand())

	if err := rootCmd.Execute(); err != nil {
		qwe(exitCodeError, err, "failed to execute root command")
	}
}

func versionFormatter(ver, commit, buildDate string) string {
	if ver == "" && buildDate == "" && commit == "" {
		return "kntrl version (built from source)"
	}

	return fmt.Sprintf("%s (build date: %s commit: %s)", ver, buildDate, commit)
}

// qwe quits with error. If there are messages, wraps error with message
func qwe(code int, err error, messages ...string) {
	for _, m := range messages {
		err = fmt.Errorf("%s: %w", m, err)
	}

	logger.Log.Errorf("%v", err)
	os.Exit(code)
}

// qwm quits with message
func qwm(code int, message string) {
	logger.Log.Info(message)
	os.Exit(code)
}
