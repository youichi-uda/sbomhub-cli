package main

import (
	"os"

	"github.com/youichi-uda/sbomhub-cli/cmd/sbomhub/commands"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	commands.SetVersion(version, commit, date)
	if err := commands.Execute(); err != nil {
		os.Exit(1)
	}
}
