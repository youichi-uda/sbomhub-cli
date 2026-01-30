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
	Long: `設定を表示または変更します。

使用例:
  sbomhub config              # 現在の設定を表示
  sbomhub config get api_url  # api_urlの値を取得
  sbomhub config set api_url https://api.sbomhub.app  # api_urlを設定`,
	RunE: runConfig,
}

var configGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "設定値を取得",
	Long: `指定したキーの設定値を取得します。

取得可能なキー:
  api_url  - SBOMHub API URL
  api_key  - API Key (マスク表示)`,
	Args: cobra.ExactArgs(1),
	RunE: runConfigGet,
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "設定値を設定",
	Long: `指定したキーに値を設定します。

設定可能なキー:
  api_url  - SBOMHub API URL
  api_key  - API Key`,
	Args: cobra.ExactArgs(2),
	RunE: runConfigSet,
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configGetCmd)
	configCmd.AddCommand(configSetCmd)
}

func getConfigDir() string {
	configDir := filepath.Join(os.Getenv("HOME"), ".sbomhub")
	if os.Getenv("USERPROFILE") != "" {
		configDir = filepath.Join(os.Getenv("USERPROFILE"), ".sbomhub")
	}
	return configDir
}

func runConfig(cmd *cobra.Command, args []string) error {
	configDir := getConfigDir()

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

func runConfigGet(cmd *cobra.Command, args []string) error {
	key := strings.ToLower(args[0])
	configDir := getConfigDir()

	cfg, err := config.Load(configDir)
	if err != nil {
		return fmt.Errorf("設定の読み込みに失敗しました: %w", err)
	}

	switch key {
	case "api_url":
		fmt.Println(cfg.APIURL)
	case "api_key":
		maskedKey := maskAPIKey(cfg.APIKey)
		fmt.Println(maskedKey)
	default:
		return fmt.Errorf("不明なキー: %s (有効なキー: api_url, api_key)", key)
	}

	return nil
}

func runConfigSet(cmd *cobra.Command, args []string) error {
	key := strings.ToLower(args[0])
	value := args[1]
	configDir := getConfigDir()

	cfg, err := config.Load(configDir)
	if err != nil {
		// 設定ファイルがない場合は新規作成
		cfg = &config.Config{
			APIURL: "https://api.sbomhub.app",
		}
	}

	switch key {
	case "api_url":
		cfg.APIURL = value
		printSuccess("api_url を設定しました: %s", value)
	case "api_key":
		cfg.APIKey = value
		printSuccess("api_key を設定しました: %s", maskAPIKey(value))
	default:
		return fmt.Errorf("不明なキー: %s (有効なキー: api_url, api_key)", key)
	}

	if err := config.Save(cfg, configDir); err != nil {
		return fmt.Errorf("設定の保存に失敗しました: %w", err)
	}

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
