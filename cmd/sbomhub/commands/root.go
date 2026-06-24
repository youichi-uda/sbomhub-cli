package commands

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/youichi-uda/sbomhub-cli/internal/config"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"

	cfgFile string
	apiURL  string
	apiKey  string

	// Global output flags
	quietFlag   bool
	verboseFlag bool
	jsonFlag    bool
)

var rootCmd = &cobra.Command{
	Use:   "sbomhub",
	Short: "SBOMHub CLI - SBOM管理ダッシュボード用CLIツール",
	Long: `SBOMHub CLIは、Syft/Trivy/cdxgen等のSBOM生成ツールをラップし、
生成からSBOMHubへのアップロードまでを1コマンドで実行するツールです。

使用例:
  sbomhub scan .                    # カレントディレクトリをスキャン
  sbomhub scan . --project my-app   # プロジェクト指定でスキャン
  sbomhub check ./sbom.json         # 既存SBOMの脆弱性チェック

グローバルフラグ:
  --quiet, -q    エラー以外の出力を抑制
  --verbose, -v  詳細出力
  --json         JSON形式で出力`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Initialize output configuration from global flags
		InitOutputConfig(quietFlag, verboseFlag, jsonFlag)
	},
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

	// Config flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "設定ファイルのパス (デフォルト: ~/.sbomhub/config.yaml)")
	rootCmd.PersistentFlags().StringVar(&apiURL, "api-url", "", "SBOMHub API URL")
	rootCmd.PersistentFlags().StringVar(&apiKey, "api-key", "", "SBOMHub API Key (環境変数 SBOMHUB_API_KEY でも指定可)")

	// Global output flags
	rootCmd.PersistentFlags().BoolVarP(&quietFlag, "quiet", "q", false, "エラー以外の出力を抑制")
	rootCmd.PersistentFlags().BoolVarP(&verboseFlag, "verbose", "v", false, "詳細出力")
	rootCmd.PersistentFlags().BoolVar(&jsonFlag, "json", false, "JSON形式で出力")
}

func initConfig() {
	// 環境変数から API Key / URL を取得 (CLI flag が空のときだけ反映)。
	// resolveCredentials も同じ env を読むが、 ここで一度 global へ
	// 折り込んでおくと、 resolveCredentials を経由しない経路 (将来の
	// 直接 apiKey/apiURL 参照) でも env が効くようになる。
	if apiKey == "" {
		apiKey = os.Getenv("SBOMHUB_API_KEY")
	}
	if apiURL == "" {
		apiURL = os.Getenv("SBOMHUB_API_URL")
	}
}

func printSuccess(msg string, args ...interface{}) {
	out := GetOutputConfig()
	out.PrintSuccess(msg, args...)
}

func printInfo(msg string, args ...interface{}) {
	out := GetOutputConfig()
	out.PrintInfo(msg, args...)
}

// resolveCredentials merges credential sources into a single *config.Config
// suitable for instantiating api.Client.
//
// Source precedence (highest wins):
//  1. CLI flag       (--api-url / --api-key)
//  2. Environment    (SBOMHUB_API_URL / SBOMHUB_API_KEY)
//  3. Config file    (~/.sbomhub/config.yaml)
//  4. Built-in       (config.DefaultAPIURL for APIURL; APIKey has none)
//
// The config file is loaded fail-soft: a missing ~/.sbomhub/config.yaml is
// NOT an error here, so noninteractive callers (CI runners that only set
// env vars / flags) work without first running `sbomhub login`. Parse
// failures on an existing file are still surfaced.
//
// The returned *config.Config is non-nil on success but its APIKey may be
// empty — callers are responsible for the final "is the credential
// actually present" check so they can produce a command-specific message
// (and exit code).
func resolveCredentials(configDir string) (*config.Config, error) {
	cfg, err := config.LoadOrDefault(configDir)
	if err != nil {
		return nil, err
	}

	// Env layer (only used when the config file did not already set the
	// value; the CLI-flag layer below still wins over both).
	if envURL := os.Getenv("SBOMHUB_API_URL"); envURL != "" {
		cfg.APIURL = envURL
	}
	if envKey := os.Getenv("SBOMHUB_API_KEY"); envKey != "" {
		cfg.APIKey = envKey
	}

	// CLI-flag layer. The initConfig hook below already folds
	// SBOMHUB_API_KEY into the apiKey global when no --api-key was given,
	// so re-applying it here is safe (env→global→env is idempotent) but
	// keeps the precedence explicit and survives any future change to the
	// initConfig hook.
	if apiURL != "" {
		cfg.APIURL = apiURL
	}
	if apiKey != "" {
		cfg.APIKey = apiKey
	}

	if cfg.APIURL == "" {
		cfg.APIURL = config.DefaultAPIURL
	}
	return cfg, nil
}
