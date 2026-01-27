package scanner

import (
	"fmt"
	"os/exec"
)

// TrivyScanner implements Scanner using Trivy
type TrivyScanner struct{}

func (s *TrivyScanner) Name() string {
	return "trivy"
}

func (s *TrivyScanner) Available() bool {
	return commandExists("trivy")
}

func (s *TrivyScanner) Scan(path string, format string) ([]byte, error) {
	outputFormat := "cyclonedx"
	if format == "spdx" {
		outputFormat = "spdx-json"
	}

	cmd := exec.Command("trivy", "fs", path, "--format", outputFormat, "--quiet")
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("trivy 実行エラー: %s", string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("trivy 実行エラー: %w", err)
	}

	return output, nil
}
