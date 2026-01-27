package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/youichi-uda/sbomhub-cli/internal/config"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "現在の設定を表示",
	RunE:  runConfig,
}

func init() {
	rootCmd.AddCommand(configCmd)
}

func runConfig(cmd *cobra.Command, args []string) error {
	configDir := filepath.Join(os.Getenv("HOME"), ".sbomhub")
	if os.Getenv("USERPROFILE") != "" {
		configDir = filepath.Join(os.Getenv("USERPROFILE"), ".sbomhub")
	}

	cfg, err := config.Load(configDir)
	if err != nil {
		return fmt.Errorf("設定の読み込みに失敗しました: %w", err)
	}

	fmt.Println("SBOMHub CLI 設定")
	fmt.Println("-----------------")
	fmt.Printf("API URL: %s\n", cfg.APIURL)
	
	// API Keyをマスク表示
	maskedKey := maskAPIKey(cfg.APIKey)
	fmt.Printf("API Key: %s\n", maskedKey)
	
	fmt.Printf("設定ファイル: %s/config.yaml\n", configDir)

	return nil
}

func maskAPIKey(key string) string {
	if key == "" {
		return "(未設定)"
	}
	if len(key) <= 8 {
		return strings.Repeat("*", len(key))
	}
	return key[:4] + strings.Repeat("*", len(key)-8) + key[len(key)-4:]
}
