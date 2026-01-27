package scanner

import (
	"fmt"
	"os/exec"
)

// Scanner interface for SBOM generation tools
type Scanner interface {
	// Name returns the scanner name
	Name() string
	// Available checks if the scanner is available on the system
	Available() bool
	// Scan generates an SBOM from the given path
	Scan(path string, format string) ([]byte, error)
}

// New creates a new scanner based on the tool name
// If tool is empty, it auto-detects the available tool
func New(tool string) (Scanner, error) {
	if tool != "" {
		switch tool {
		case "syft":
			s := &SyftScanner{}
			if !s.Available() {
				return nil, fmt.Errorf("syft がインストールされていません")
			}
			return s, nil
		case "trivy":
			s := &TrivyScanner{}
			if !s.Available() {
				return nil, fmt.Errorf("trivy がインストールされていません")
			}
			return s, nil
		case "cdxgen":
			s := &CdxgenScanner{}
			if !s.Available() {
				return nil, fmt.Errorf("cdxgen がインストールされていません")
			}
			return s, nil
		default:
			return nil, fmt.Errorf("サポートされていないツール: %s (syft/trivy/cdxgen)", tool)
		}
	}

	// 自動検出
	scanners := []Scanner{
		&SyftScanner{},
		&TrivyScanner{},
		&CdxgenScanner{},
	}

	for _, s := range scanners {
		if s.Available() {
			return s, nil
		}
	}

	return nil, fmt.Errorf("SBOM生成ツールが見つかりません。syft, trivy, または cdxgen をインストールしてください")
}

// commandExists checks if a command exists on the system
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
