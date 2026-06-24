package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/youichi-uda/sbomhub-cli/internal/api"
	"github.com/youichi-uda/sbomhub-cli/internal/scanner"
)

var checkCmd = &cobra.Command{
	Use:   "check [path]",
	Short: "ディレクトリまたはSBOMファイルの脆弱性をチェック（アップロードなし）",
	Long: `指定したパスまたはSBOMファイルの脆弱性をチェックします。
アップロードは行いません。

使用例:
  sbomhub check .                # カレントディレクトリ
  sbomhub check ./sbom.json      # 既存のSBOMファイル`,
	Args: cobra.MaximumNArgs(1),
	RunE: runCheck,
}

func init() {
	rootCmd.AddCommand(checkCmd)
}

func runCheck(cmd *cobra.Command, args []string) error {
	// チェック対象パスの決定
	checkPath := "."
	if len(args) > 0 {
		checkPath = args[0]
	}

	absPath, err := filepath.Abs(checkPath)
	if err != nil {
		return fmt.Errorf("パスの解決に失敗しました: %w", err)
	}

	// パスの存在確認
	info, err := os.Stat(absPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("パスが存在しません: %s", absPath)
	}

	var sbomData []byte

	// ファイルかディレクトリかで処理を分岐
	if info.IsDir() {
		fmt.Printf("📦 スキャン中: %s\n", absPath)
		
		s, err := scanner.New("")
		if err != nil {
			return fmt.Errorf("スキャナーの初期化に失敗しました: %w", err)
		}

		sbomData, err = s.Scan(absPath, "cyclonedx")
		if err != nil {
			return fmt.Errorf("スキャンに失敗しました: %w", err)
		}
	} else {
		// SBOMファイルを読み込み
		fmt.Printf("📄 SBOMファイル読み込み: %s\n", absPath)
		sbomData, err = os.ReadFile(absPath)
		if err != nil {
			return fmt.Errorf("ファイルの読み込みに失敗しました: %w", err)
		}
	}

	// コンポーネント数を表示
	componentCount := countComponentsCheck(sbomData)
	fmt.Printf("📋 コンポーネント数: %d\n", componentCount)
	fmt.Println()

	// 設定の解決: config file → env → CLI flag の precedence で merge する
	// (Codex R9 fix)。 R2-2e で scan に導入した resolveCredentials を check
	// にも適用、 SBOMHUB_API_URL / SBOMHUB_API_KEY と --api-url / --api-key
	// が config file 不在でも一貫して効くようにする。 self-host 用途で
	// `SBOMHUB_API_URL=http://localhost:8080 sbomhub check .` が動く前提。
	cfg, err := resolveCredentials(getConfigDir())
	if err != nil {
		return fmt.Errorf("設定の読み込みに失敗しました: %w", err)
	}
	if cfg.APIKey == "" {
		return fmt.Errorf("API Keyが設定されていません。 'sbomhub login' で対話設定するか、 --api-key フラグ・ 環境変数 SBOMHUB_API_KEY を指定してください")
	}
	if cfg.APIURL == "" {
		return fmt.Errorf("API URLが設定されていません。 'sbomhub login' で設定するか、 --api-url フラグ・ 環境変数 SBOMHUB_API_URL を指定してください")
	}

	// API クライアントの作成
	client := api.NewClient(cfg.APIURL, cfg.APIKey)

	fmt.Println("🔍 脆弱性チェック中...")
	fmt.Println()

	// チェック
	result, err := client.CheckVulnerabilities(sbomData)
	if err != nil {
		return fmt.Errorf("脆弱性チェックに失敗しました: %w", err)
	}

	// 結果表示
	if result.Total == 0 {
		printSuccess("脆弱性は検出されませんでした！")
	} else {
		fmt.Printf("⚠️  %d件の脆弱性が検出されました\n", result.Total)
		fmt.Println()

		if result.Critical > 0 {
			fmt.Printf("  🔴 Critical: %d\n", result.Critical)
		}
		if result.High > 0 {
			fmt.Printf("  🟠 High: %d\n", result.High)
		}
		if result.Medium > 0 {
			fmt.Printf("  🟡 Medium: %d\n", result.Medium)
		}
		if result.Low > 0 {
			fmt.Printf("  🟢 Low: %d\n", result.Low)
		}
	}

	return nil
}

func countComponentsCheck(sbomData []byte) int {
	var sbom map[string]interface{}
	if err := json.Unmarshal(sbomData, &sbom); err != nil {
		return 0
	}

	if components, ok := sbom["components"].([]interface{}); ok {
		return len(components)
	}

	if packages, ok := sbom["packages"].([]interface{}); ok {
		return len(packages)
	}

	return 0
}
