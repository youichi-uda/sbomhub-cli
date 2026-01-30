package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/youichi-uda/sbomhub-cli/internal/config"
)

var (
	logoutAll bool
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "SBOMHubからログアウト（API Keyをクリア）",
	Long: `保存されているAPI Keyをクリアします。

デフォルトではAPI Keyのみをクリアします。
--all フラグを使用すると設定ファイル全体を削除します。`,
	RunE: runLogout,
}

func init() {
	rootCmd.AddCommand(logoutCmd)
	logoutCmd.Flags().BoolVar(&logoutAll, "all", false, "設定ファイル全体を削除")
}

func runLogout(cmd *cobra.Command, args []string) error {
	configDir := filepath.Join(os.Getenv("HOME"), ".sbomhub")
	if os.Getenv("USERPROFILE") != "" {
		configDir = filepath.Join(os.Getenv("USERPROFILE"), ".sbomhub")
	}

	configPath := filepath.Join(configDir, "config.yaml")

	if logoutAll {
		// 設定ファイル全体を削除
		if err := os.Remove(configPath); err != nil {
			if os.IsNotExist(err) {
				printInfo("設定ファイルが見つかりません: %s", configPath)
				return nil
			}
			return fmt.Errorf("設定ファイルの削除に失敗しました: %w", err)
		}
		printSuccess("設定ファイルを削除しました: %s", configPath)
		return nil
	}

	// API Keyのみをクリア
	cfg, err := config.Load(configDir)
	if err != nil {
		if os.IsNotExist(err) {
			printInfo("設定ファイルが見つかりません")
			return nil
		}
		return fmt.Errorf("設定の読み込みに失敗しました: %w", err)
	}

	if cfg.APIKey == "" {
		printInfo("API Keyは既にクリアされています")
		return nil
	}

	// API Keyをクリアして保存
	cfg.APIKey = ""
	if err := config.Save(cfg, configDir); err != nil {
		return fmt.Errorf("設定の保存に失敗しました: %w", err)
	}

	printSuccess("ログアウトしました")
	printInfo("API URLは保持されています: %s", cfg.APIURL)
	printInfo("再度ログインするには 'sbomhub login' を実行してください")

	return nil
}
