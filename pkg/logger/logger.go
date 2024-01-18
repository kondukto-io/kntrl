package logger

import (
	"github.com/sirupsen/logrus"
)

var (
	// Log is the logger
	Log *logrus.Logger
)

func init() {
	Log = logrus.New()
	Log.Formatter = &logrus.TextFormatter{}
	// Log.SetReportCaller(true)
}

// SetLevel sets the log level
func SetLevel(level string) {
	l, err := logrus.ParseLevel(level)
	if err != nil {
		Log.SetLevel(logrus.InfoLevel)
	}

	Log.SetLevel(l)
}
