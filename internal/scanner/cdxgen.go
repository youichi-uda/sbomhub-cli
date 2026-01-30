package scanner

import (
	"fmt"
	"os/exec"
)

// CdxgenScanner implements Scanner using cdxgen
type CdxgenScanner struct{}

func (s *CdxgenScanner) Name() string {
	return "cdxgen"
}

func (s *CdxgenScanner) Available() bool {
	return commandExists("cdxgen")
}

func (s *CdxgenScanner) Scan(path string, format string) ([]byte, error) {
	args := []string{"-o", "-", path}

	// Note: cdxgen doesn't natively support SPDX output.
	// Format parameter is ignored; CycloneDX is always used.
	_ = format

	cmd := exec.Command("cdxgen", args...)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("cdxgen 実行エラー: %s", string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("cdxgen 実行エラー: %w", err)
	}

	return output, nil
}
