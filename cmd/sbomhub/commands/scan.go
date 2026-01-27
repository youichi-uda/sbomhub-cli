package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/youichi-uda/sbomhub-cli/internal/api"
	"github.com/youichi-uda/sbomhub-cli/internal/config"
	"github.com/youichi-uda/sbomhub-cli/internal/scanner"
)

var (
	scanProject string
	scanTool    string
	scanFormat  string
	scanOutput  string
	scanFailOn  string
	scanDryRun  bool
	scanNotify  bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "ディレクトリまたはコンテナイメージをスキャンしてSBOMを生成・アップロード",
	Long: `指定したパスをスキャンしてSBOMを生成し、SBOMHubにアップロードします。

使用例:
  sbomhub scan .                           # カレントディレクトリ
  sbomhub scan ./my-app                    # 指定ディレクトリ
  sbomhub scan ./my-app --project my-app   # プロジェクト指定
  sbomhub scan ./image.tar                 # コンテナイメージ`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&scanProject, "project", "p", "", "プロジェクト名またはID")
	scanCmd.Flags().StringVarP(&scanTool, "tool", "t", "", "使用するツール (syft/trivy/cdxgen, デフォルト: 自動検出)")
	scanCmd.Flags().StringVarP(&scanFormat, "format", "f", "cyclonedx", "出力フォーマット (cyclonedx/spdx)")
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "", "ローカルにも保存するファイルパス")
	scanCmd.Flags().StringVar(&scanFailOn, "fail-on", "", "指定した重大度以上の脆弱性でexit 1 (critical/high/medium/low)")
	scanCmd.Flags().BoolVar(&scanDryRun, "dry-run", false, "アップロードせずSBOM生成のみ")
	scanCmd.Flags().BoolVar(&scanNotify, "notify", false, "脆弱性検出時に通知")
}

func runScan(cmd *cobra.Command, args []string) error {
	// スキャン対象パスの決定
	scanPath := "."
	if len(args) > 0 {
		scanPath = args[0]
	}

	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return fmt.Errorf("パスの解決に失敗しました: %w", err)
	}

	// パスの存在確認
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return fmt.Errorf("パスが存在しません: %s", absPath)
	}

	fmt.Printf("📦 スキャン開始: %s\n", absPath)
	fmt.Println()

	// スキャナーの選択
	s, err := scanner.New(scanTool)
	if err != nil {
		return fmt.Errorf("スキャナーの初期化に失敗しました: %w", err)
	}

	fmt.Printf("🔍 ツール: %s\n", s.Name())

	// スキャン実行
	startTime := time.Now()
	sbomData, err := s.Scan(absPath, scanFormat)
	if err != nil {
		return fmt.Errorf("スキャンに失敗しました: %w", err)
	}
	elapsed := time.Since(startTime)

	fmt.Printf("⏱️  スキャン時間: %s\n", elapsed.Round(time.Millisecond))

	// コンポーネント数を表示
	componentCount := countComponents(sbomData)
	fmt.Printf("📋 コンポーネント数: %d\n", componentCount)
	fmt.Println()

	// ローカル保存
	if scanOutput != "" {
		if err := os.WriteFile(scanOutput, sbomData, 0644); err != nil {
			return fmt.Errorf("ファイルの保存に失敗しました: %w", err)
		}
		printSuccess("SBOMを保存しました: %s", scanOutput)
	}

	// dry-runならここで終了
	if scanDryRun {
		printInfo("--dry-run が指定されているため、アップロードをスキップしました")
		return nil
	}

	// 設定の読み込み
	configDir := filepath.Join(os.Getenv("HOME"), ".sbomhub")
	if os.Getenv("USERPROFILE") != "" {
		configDir = filepath.Join(os.Getenv("USERPROFILE"), ".sbomhub")
	}

	cfg, err := config.Load(configDir)
	if err != nil {
		return fmt.Errorf("設定の読み込みに失敗しました。'sbomhub login' を実行してください: %w", err)
	}

	// API Key の確認
	if apiKey != "" {
		cfg.APIKey = apiKey
	}
	if cfg.APIKey == "" {
		return fmt.Errorf("API Keyが設定されていません。'sbomhub login' を実行するか --api-key を指定してください")
	}

	// API クライアントの作成
	client := api.NewClient(cfg.APIURL, cfg.APIKey)

	// プロジェクト名の決定
	projectName := scanProject
	if projectName == "" {
		// ディレクトリ名をプロジェクト名として使用
		projectName = filepath.Base(absPath)
		if projectName == "." || projectName == "/" {
			cwd, _ := os.Getwd()
			projectName = filepath.Base(cwd)
		}
	}

	fmt.Printf("📤 アップロード中: プロジェクト '%s'\n", projectName)

	// アップロード
	result, err := client.UploadSBOM(projectName, sbomData, scanFormat)
	if err != nil {
		return fmt.Errorf("アップロードに失敗しました: %w", err)
	}

	fmt.Println()
	printSuccess("アップロード完了！")
	fmt.Println()

	// 結果表示
	fmt.Println("┌─────────────────────────────────────────────────────────┐")
	fmt.Println("│ スキャン完了                                            │")
	fmt.Println("├─────────────────────────────────────────────────────────┤")
	fmt.Printf("│ コンポーネント: %-40d │\n", componentCount)
	if result.VulnerabilityCount > 0 {
		vulnSummary := formatVulnSummary(result)
		fmt.Printf("│ 脆弱性: %-48s │\n", vulnSummary)
	} else {
		fmt.Printf("│ 脆弱性: %-48s │\n", "なし ✅")
	}
	fmt.Println("│                                                         │")
	fmt.Printf("│ URL: %-51s │\n", result.URL)
	fmt.Println("└─────────────────────────────────────────────────────────┘")

	// fail-on チェック
	if scanFailOn != "" && result.VulnerabilityCount > 0 {
		if shouldFail(result, strings.ToLower(scanFailOn)) {
			return fmt.Errorf("--fail-on %s: 指定された重大度以上の脆弱性が検出されました", scanFailOn)
		}
	}

	return nil
}

func countComponents(sbomData []byte) int {
	var sbom map[string]interface{}
	if err := json.Unmarshal(sbomData, &sbom); err != nil {
		return 0
	}

	// CycloneDX
	if components, ok := sbom["components"].([]interface{}); ok {
		return len(components)
	}

	// SPDX
	if packages, ok := sbom["packages"].([]interface{}); ok {
		return len(packages)
	}

	return 0
}

func formatVulnSummary(result *api.UploadResult) string {
	parts := []string{}
	if result.Critical > 0 {
		parts = append(parts, fmt.Sprintf("%d Critical", result.Critical))
	}
	if result.High > 0 {
		parts = append(parts, fmt.Sprintf("%d High", result.High))
	}
	if result.Medium > 0 {
		parts = append(parts, fmt.Sprintf("%d Medium", result.Medium))
	}
	if result.Low > 0 {
		parts = append(parts, fmt.Sprintf("%d Low", result.Low))
	}
	return strings.Join(parts, ", ")
}

func shouldFail(result *api.UploadResult, failOn string) bool {
	switch failOn {
	case "critical":
		return result.Critical > 0
	case "high":
		return result.Critical > 0 || result.High > 0
	case "medium":
		return result.Critical > 0 || result.High > 0 || result.Medium > 0
	case "low":
		return result.VulnerabilityCount > 0
	}
	return false
}
