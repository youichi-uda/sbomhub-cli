package scanner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	// Note: cdxgen doesn't natively support SPDX output.
	// Format parameter is ignored; CycloneDX is always used.
	_ = format

	// Use temporary file instead of stdout (-o -)
	// cdxgen's stdout mode includes ANSI escape codes which corrupts JSON output
	tempDir, err := os.MkdirTemp("", "sbomhub-cdxgen-*")
	if err != nil {
		return nil, fmt.Errorf("一時ディレクトリ作成エラー: %w", err)
	}
	defer os.RemoveAll(tempDir)

	outputFile := filepath.Join(tempDir, "sbom.json")
	args := []string{"-o", outputFile, path}

	cmd := exec.Command("cdxgen", args...)
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("cdxgen 実行エラー: %s", string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("cdxgen 実行エラー: %w", err)
	}

	output, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("SBOM読み込みエラー: %w", err)
	}

	return output, nil
}
