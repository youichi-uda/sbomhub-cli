package scanner

import (
	"testing"
)

func TestNewScanner(t *testing.T) {
	tests := []struct {
		name    string
		tool    string
		wantErr bool
	}{
		{
			name:    "unknown tool",
			tool:    "unknown-tool",
			wantErr: true,
		},
		{
			name:    "empty tool auto-detect",
			tool:    "",
			wantErr: false, // May or may not error depending on installed tools
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.tool == "unknown-tool" {
				_, err := New(tt.tool)
				if err == nil {
					t.Error("New() expected error for unknown tool")
				}
			}
			// Skip auto-detect test as it depends on installed tools
		})
	}
}

func TestNewScannerSpecificTools(t *testing.T) {
	// Test that specifying an unavailable tool gives proper error
	tools := []string{"syft", "trivy", "cdxgen"}

	for _, tool := range tools {
		t.Run(tool, func(t *testing.T) {
			scanner, err := New(tool)
			if err != nil {
				// Tool not installed - expected
				t.Logf("%s not installed: %v", tool, err)
				return
			}

			// Tool is installed - verify name
			if scanner.Name() != tool {
				t.Errorf("Name() = %q, want %q", scanner.Name(), tool)
			}
		})
	}
}

func TestCommandExists(t *testing.T) {
	// Test with a command that should exist on all systems
	exists := commandExists("go")
	if !exists {
		t.Error("commandExists('go') = false, expected true")
	}

	// Test with a command that shouldn't exist
	notExists := commandExists("definitely-not-a-real-command-12345")
	if notExists {
		t.Error("commandExists('definitely-not-a-real-command-12345') = true, expected false")
	}
}

func TestSyftScanner(t *testing.T) {
	s := &SyftScanner{}

	if s.Name() != "syft" {
		t.Errorf("Name() = %q, want syft", s.Name())
	}

	// Available() depends on system state
	available := s.Available()
	t.Logf("SyftScanner.Available() = %v", available)
}

func TestTrivyScanner(t *testing.T) {
	s := &TrivyScanner{}

	if s.Name() != "trivy" {
		t.Errorf("Name() = %q, want trivy", s.Name())
	}

	available := s.Available()
	t.Logf("TrivyScanner.Available() = %v", available)
}

func TestCdxgenScanner(t *testing.T) {
	s := &CdxgenScanner{}

	if s.Name() != "cdxgen" {
		t.Errorf("Name() = %q, want cdxgen", s.Name())
	}

	available := s.Available()
	t.Logf("CdxgenScanner.Available() = %v", available)
}

func TestScanWithUnavailableTool(t *testing.T) {
	// Test Scan with a tool that's not installed
	tools := []struct {
		name    string
		scanner Scanner
	}{
		{"syft", &SyftScanner{}},
		{"trivy", &TrivyScanner{}},
		{"cdxgen", &CdxgenScanner{}},
	}

	for _, tt := range tools {
		t.Run(tt.name, func(t *testing.T) {
			if tt.scanner.Available() {
				// Skip if tool is installed
				t.Skipf("%s is installed, skipping unavailable test", tt.name)
			}

			_, err := tt.scanner.Scan(".", "cyclonedx")
			if err == nil {
				t.Errorf("%s.Scan() expected error when tool unavailable", tt.name)
			}
		})
	}
}

func TestScannerInterface(t *testing.T) {
	// Verify all scanners implement the interface
	var _ Scanner = &SyftScanner{}
	var _ Scanner = &TrivyScanner{}
	var _ Scanner = &CdxgenScanner{}
}
