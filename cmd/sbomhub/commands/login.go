package commands

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/youichi-uda/sbomhub-cli/internal/config"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "SBOMHubにログイン（API Keyを設定）",
	Long: `SBOMHubのAPI Keyを設定します。

API Keyは https://sbomhub.app/settings/api-keys から取得できます。`,
	RunE: runLogin,
}

func init() {
	rootCmd.AddCommand(loginCmd)
}

func runLogin(cmd *cobra.Command, args []string) error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("SBOMHub CLI ログイン")
	fmt.Println("--------------------")
	fmt.Println()
	fmt.Println("API Keyを入力してください。")
	fmt.Println("API Keyは https://sbomhub.app/settings/api-keys から取得できます。")
	fmt.Println()
	fmt.Print("API Key: ")

	apiKeyInput, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("入力の読み取りに失敗しました: %w", err)
	}

	apiKeyInput = strings.TrimSpace(apiKeyInput)
	if apiKeyInput == "" {
		return fmt.Errorf("API Keyが入力されていません")
	}

	// API URLの設定（オプション）
	apiURLInput := "https://api.sbomhub.app"
	fmt.Printf("API URL [%s]: ", apiURLInput)
	urlInput, _ := reader.ReadString('\n')
	urlInput = strings.TrimSpace(urlInput)
	if urlInput != "" {
		apiURLInput = urlInput
	}

	// 設定を保存
	cfg := &config.Config{
		APIURL: apiURLInput,
		APIKey: apiKeyInput,
	}

	configDir := filepath.Join(os.Getenv("HOME"), ".sbomhub")
	if os.Getenv("USERPROFILE") != "" {
		configDir = filepath.Join(os.Getenv("USERPROFILE"), ".sbomhub")
	}

	if err := config.Save(cfg, configDir); err != nil {
		return fmt.Errorf("設定の保存に失敗しました: %w", err)
	}

	fmt.Println()
	printSuccess("ログインが完了しました！")
	printInfo("設定ファイル: %s/config.yaml", configDir)

	return nil
}
