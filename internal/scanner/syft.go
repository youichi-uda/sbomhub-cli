package scanner

import (
	"fmt"
	"os/exec"
)

// SyftScanner implements Scanner using Syft
type SyftScanner struct{}

func (s *SyftScanner) Name() string {
	return "syft"
}

func (s *SyftScanner) Available() bool {
	return commandExists("syft")
}

func (s *SyftScanner) Scan(path string, format string) ([]byte, error) {
	outputFormat := "cyclonedx-json"
	if format == "spdx" {
		outputFormat = "spdx-json"
	}

	cmd := exec.Command("syft", path, "-o", outputFormat, "--quiet")
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("syft 実行エラー: %s", string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("syft 実行エラー: %w", err)
	}

	return output, nil
}
