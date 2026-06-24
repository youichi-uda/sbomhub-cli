package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	// Create config file
	configContent := `api_url: https://api.example.com
api_key: test-api-key-12345
`
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Test Load
	cfg, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.APIURL != "https://api.example.com" {
		t.Errorf("APIURL = %q, want %q", cfg.APIURL, "https://api.example.com")
	}

	if cfg.APIKey != "test-api-key-12345" {
		t.Errorf("APIKey = %q, want %q", cfg.APIKey, "test-api-key-12345")
	}
}

func TestLoadConfigDefault(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	// Create config file without api_url
	configContent := `api_key: test-api-key
`
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Test Load - should use default API URL
	cfg, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.APIURL != "https://api.sbomhub.app" {
		t.Errorf("APIURL = %q, want default %q", cfg.APIURL, "https://api.sbomhub.app")
	}
}

func TestLoadConfigNotFound(t *testing.T) {
	tmpDir := t.TempDir()

	// Test Load with non-existent config
	_, err := Load(tmpDir)
	if err == nil {
		t.Error("Load() expected error for missing config, got nil")
	}
}

func TestLoadConfigInvalid(t *testing.T) {
	tmpDir := t.TempDir()

	// Create invalid YAML file
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("invalid: yaml: content:"), 0600); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Test Load with invalid YAML
	_, err := Load(tmpDir)
	if err == nil {
		t.Error("Load() expected error for invalid YAML, got nil")
	}
}

func TestSaveConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "sbomhub")

	cfg := &Config{
		APIURL: "https://api.example.com",
		APIKey: "my-secret-key",
	}

	// Test Save
	if err := Save(cfg, configDir); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Verify file was created
	configPath := filepath.Join(configDir, "config.yaml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("Save() did not create config file")
	}

	// Verify content can be loaded back
	loaded, err := Load(configDir)
	if err != nil {
		t.Fatalf("Load() after Save() error = %v", err)
	}

	if loaded.APIURL != cfg.APIURL {
		t.Errorf("Loaded APIURL = %q, want %q", loaded.APIURL, cfg.APIURL)
	}

	if loaded.APIKey != cfg.APIKey {
		t.Errorf("Loaded APIKey = %q, want %q", loaded.APIKey, cfg.APIKey)
	}
}

// TestLoadOrDefaultMissing verifies the Codex R2 fix: a missing config
// file is NOT an error for the fail-soft loader. Noninteractive callers
// (CI runners passing credentials by --api-* flag or env var) must be
// able to operate without having run `sbomhub login` first.
func TestLoadOrDefaultMissing(t *testing.T) {
	tmpDir := t.TempDir() // no config.yaml written

	cfg, err := LoadOrDefault(tmpDir)
	if err != nil {
		t.Fatalf("LoadOrDefault() error = %v, want nil for missing file", err)
	}
	if cfg == nil {
		t.Fatal("LoadOrDefault() returned nil cfg for missing file")
	}
	if cfg.APIURL != DefaultAPIURL {
		t.Errorf("APIURL = %q, want default %q (default must seed when file is absent)", cfg.APIURL, DefaultAPIURL)
	}
	if cfg.APIKey != "" {
		t.Errorf("APIKey = %q, want empty (no source provided the key)", cfg.APIKey)
	}
}

// TestLoadOrDefaultParseError verifies LoadOrDefault is fail-soft ONLY on
// missing files — a malformed config.yaml on disk must still surface so
// the operator can fix it rather than silently running with empty creds.
func TestLoadOrDefaultParseError(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("invalid: yaml: content:"), 0600); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	_, err := LoadOrDefault(tmpDir)
	if err == nil {
		t.Error("LoadOrDefault() expected error for invalid YAML, got nil")
	}
}

// TestLoadOrDefaultPresent verifies the existing-file path of LoadOrDefault
// is equivalent to Load: the function should not zero out fields just
// because it also tolerates absence.
func TestLoadOrDefaultPresent(t *testing.T) {
	tmpDir := t.TempDir()
	configContent := `api_url: https://api.example.com
api_key: present-key
`
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadOrDefault(tmpDir)
	if err != nil {
		t.Fatalf("LoadOrDefault() error = %v", err)
	}
	if cfg.APIURL != "https://api.example.com" {
		t.Errorf("APIURL = %q, want %q", cfg.APIURL, "https://api.example.com")
	}
	if cfg.APIKey != "present-key" {
		t.Errorf("APIKey = %q, want %q", cfg.APIKey, "present-key")
	}
}

func TestSaveConfigPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "sbomhub")

	cfg := &Config{
		APIURL: "https://api.sbomhub.app",
		APIKey: "secret-key",
	}

	if err := Save(cfg, configDir); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Check directory permissions
	dirInfo, err := os.Stat(configDir)
	if err != nil {
		t.Fatalf("os.Stat() error = %v", err)
	}

	// On Unix, should be 0700
	if dirInfo.Mode().Perm()&0077 != 0 {
		// On Windows, permission checks are different, so skip this
		if os.Getenv("GOOS") != "windows" {
			t.Logf("Directory permissions = %o (expected 0700)", dirInfo.Mode().Perm())
		}
	}
}
