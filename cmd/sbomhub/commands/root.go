package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"

	cfgFile string
	apiURL  string
	apiKey  string
)

var rootCmd = &cobra.Command{
	Use:   "sbomhub",
	Short: "SBOMHub CLI - SBOM管理ダッシュボード用CLIツール",
	Long: `SBOMHub CLIは、Syft/Trivy/cdxgen等のSBOM生成ツールをラップし、
生成からSBOMHubへのアップロードまでを1コマンドで実行するツールです。

使用例:
  sbomhub scan .                    # カレントディレクトリをスキャン
  sbomhub scan . --project my-app   # プロジェクト指定でスキャン
  sbomhub check ./sbom.json         # 既存SBOMの脆弱性チェック`,
}

func Execute() error {
	return rootCmd.Execute()
}

func SetVersion(v, c, d string) {
	version = v
	commit = c
	date = d
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "設定ファイルのパス (デフォルト: ~/.sbomhub/config.yaml)")
	rootCmd.PersistentFlags().StringVar(&apiURL, "api-url", "", "SBOMHub API URL")
	rootCmd.PersistentFlags().StringVar(&apiKey, "api-key", "", "SBOMHub API Key (環境変数 SBOMHUB_API_KEY でも指定可)")
}

func initConfig() {
	// 環境変数からAPI Keyを取得
	if apiKey == "" {
		apiKey = os.Getenv("SBOMHUB_API_KEY")
	}
}

func printError(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+msg+"\n", args...)
}

func printSuccess(msg string, args ...interface{}) {
	fmt.Printf("✓ "+msg+"\n", args...)
}

func printInfo(msg string, args ...interface{}) {
	fmt.Printf(msg+"\n", args...)
}
