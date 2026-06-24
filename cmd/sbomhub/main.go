package main

import (
	"errors"
	"os"

	"github.com/youichi-uda/sbomhub-cli/cmd/sbomhub/commands"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// exitCoder lets a command request a specific process exit code while
// still returning an error through the cobra RunE contract. Used by
// `sbomhub scan --fail-on` so CI workflows can distinguish:
//
//   - 1 threshold violation (vulnerabilities at/above --fail-on)
//   - 2 wait-for-scan timed out (or background scan failed server-side)
//   - 3 API / upload / configuration error
//
// Commands that don't implement this fall back to exit 1, preserving the
// previous behaviour.
type exitCoder interface {
	ExitCode() int
}

func main() {
	commands.SetVersion(version, commit, date)
	if err := commands.Execute(); err != nil {
		var ec exitCoder
		if errors.As(err, &ec) {
			os.Exit(ec.ExitCode())
		}
		os.Exit(1)
	}
}
