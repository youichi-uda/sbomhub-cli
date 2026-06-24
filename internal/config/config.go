package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents CLI configuration
type Config struct {
	APIURL string `yaml:"api_url"`
	APIKey string `yaml:"api_key"`
}

// DefaultAPIURL is the URL used when neither config nor CLI/env provides
// one. Exported so callers (login, doctor) can format identical hints.
const DefaultAPIURL = "https://api.sbomhub.app"

// Load loads configuration from the specified directory. Missing files are
// reported as an error — callers that want to operate without a config
// file (e.g. CI runners that pass credentials via flags or environment
// variables only) should use LoadOrDefault instead.
func Load(configDir string) (*Config, error) {
	configPath := filepath.Join(configDir, "config.yaml")

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("設定ファイルが見つかりません: %s", configPath)
		}
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("設定ファイルの解析に失敗しました: %w", err)
	}

	// デフォルト値
	if cfg.APIURL == "" {
		cfg.APIURL = DefaultAPIURL
	}

	return &cfg, nil
}

// LoadOrDefault is the fail-soft variant of Load: when the config file is
// missing, an empty *Config (with DefaultAPIURL applied) is returned with
// a nil error. Parse errors on an existing file are still propagated.
//
// This exists so noninteractive flows (`--api-url` / `--api-key` flags or
// SBOMHUB_API_URL / SBOMHUB_API_KEY env vars) keep working on systems
// where the operator never ran `sbomhub login` — e.g. ephemeral CI
// runners. Callers are expected to layer their own flag/env overrides on
// top of the returned config and validate the final result themselves.
func LoadOrDefault(configDir string) (*Config, error) {
	cfg, err := Load(configDir)
	if err == nil {
		return cfg, nil
	}

	configPath := filepath.Join(configDir, "config.yaml")
	if _, statErr := os.Stat(configPath); os.IsNotExist(statErr) {
		// Treat "no file" as "empty cfg" so callers can still honour
		// CLI flags / env vars. Any other Load error (parse failure,
		// permission denied on an existing file, etc.) bubbles up.
		return &Config{APIURL: DefaultAPIURL}, nil
	}
	return nil, err
}

// Save saves configuration to the specified directory
func Save(cfg *Config, configDir string) error {
	// ディレクトリ作成
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("ディレクトリの作成に失敗しました: %w", err)
	}

	configPath := filepath.Join(configDir, "config.yaml")

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("設定のシリアライズに失敗しました: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("設定ファイルの書き込みに失敗しました: %w", err)
	}

	return nil
}
