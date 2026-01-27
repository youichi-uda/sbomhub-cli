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

// Load loads configuration from the specified directory
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
		cfg.APIURL = "https://api.sbomhub.app"
	}

	return &cfg, nil
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
