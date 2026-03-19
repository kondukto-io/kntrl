package tracer

// helpers.go contains small utility functions used across the tracer package.

import "strings"

// trimNullBytesLong converts a byte slice to a string, stopping at the first
// NUL byte. Used to extract C-style strings from fixed-size BPF event fields
// (e.g. filenames, command names) that are zero-padded.
func trimNullBytesLong(p []byte) string {
	for i, v := range p {
		if v == 0 {
			return string(p[:i])
		}
	}
	return string(p)
}

// fmtEnvVars formats a list of matched environment variable names for log
// output. Returns an empty string if no vars matched, or " env=[VAR1,VAR2]"
// for inclusion in log lines.
func fmtEnvVars(vars []string) string {
	if len(vars) == 0 {
		return ""
	}
	return " env=[" + strings.Join(vars, ",") + "]"
}
