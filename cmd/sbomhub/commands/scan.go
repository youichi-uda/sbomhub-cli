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
	"github.com/youichi-uda/sbomhub-cli/internal/scanner"
	"github.com/youichi-uda/sbomhub-cli/internal/severity"
)

// Exit codes used by `scan`. Documented here so CI authors can branch on
// them. See also the `--fail-on` documentation in init().
//
//	0 — success (no threshold violation, or --fail-on not set)
//	1 — threshold violation: vulnerabilities at or above --fail-on found
//	2 — wait-for-scan timed out, or background scan reported "failed"
//	3 — API / upload / configuration error
//
// Callers should not rely on exit codes outside [0,3]; cobra may map
// validation errors to 1 itself, but the runScan body uses ScanError to
// pick the intentional code.
const (
	exitSuccess           = 0
	exitThresholdExceeded = 1
	exitScanTimeout       = 2
	exitAPIError          = 3
)

// scanExitError lets runScan signal a specific exit code to main() while
// still using the normal cobra/errors return path. main.go inspects it
// via errors.As.
type scanExitError struct {
	code int
	msg  string
}

func (e *scanExitError) Error() string { return e.msg }
func (e *scanExitError) ExitCode() int { return e.code }

var (
	scanProject      string
	scanTool         string
	scanFormat       string
	scanOutput       string
	scanFailOn       string
	scanDryRun       bool
	scanNotify       bool
	scanWaitForScan  bool
	scanWaitTimeout  time.Duration
	scanPollInterval time.Duration
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "ディレクトリまたはコンテナイメージをスキャンしてSBOMを生成・アップロード",
	Long: `指定したパスをスキャンしてSBOMを生成し、SBOMHubにアップロードします。

使用例:
  sbomhub scan .                                 # カレントディレクトリ
  sbomhub scan ./my-app                          # 指定ディレクトリ
  sbomhub scan ./my-app --project my-app         # プロジェクト指定
  sbomhub scan ./image.tar                       # コンテナイメージ
  sbomhub scan . --fail-on critical              # critical あれば exit 1
  sbomhub scan . --fail-on high --wait-timeout 10m

Exit codes:
  0  正常終了 (脆弱性 threshold 違反なし、 もしくは --fail-on 未指定)
  1  --fail-on で指定した重大度以上の脆弱性を検出
  2  スキャン待機タイムアウト or サーバ側スキャンが失敗
  3  API / アップロード / 設定エラー`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&scanProject, "project", "p", "", "プロジェクト名またはID")
	scanCmd.Flags().StringVarP(&scanTool, "tool", "t", "", "使用するツール (syft/trivy/cdxgen, デフォルト: 自動検出)")
	scanCmd.Flags().StringVarP(&scanFormat, "format", "f", "cyclonedx", "出力フォーマット (cyclonedx/spdx)")
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "", "ローカルにも保存するファイルパス")
	scanCmd.Flags().StringVar(&scanFailOn, "fail-on", "", "指定した重大度以上の脆弱性で exit 1 (critical/high/medium/low/kev)。 --wait-for-scan=true (default) が必須")
	scanCmd.Flags().BoolVar(&scanDryRun, "dry-run", false, "アップロードせずSBOM生成のみ")
	scanCmd.Flags().BoolVar(&scanNotify, "notify", false, "脆弱性検出時に通知")
	scanCmd.Flags().BoolVar(&scanWaitForScan, "wait-for-scan", true, "アップロード後にサーバ側の脆弱性スキャン完了を待つ (--fail-on と併用する場合は true 必須、 false を渡すと起動拒否)")
	scanCmd.Flags().DurationVar(&scanWaitTimeout, "wait-timeout", 5*time.Minute, "サーバ側スキャン完了を待つ最大時間")
	scanCmd.Flags().DurationVar(&scanPollInterval, "poll-interval", 5*time.Second, "スキャン状態の polling 間隔")
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

	// --fail-on の早期検証: 値が正しくなければアップロードする前に拒否する。
	failOnLevel := severity.LevelNone
	if scanFailOn != "" {
		failOnLevel = severity.Parse(scanFailOn)
		if failOnLevel == severity.LevelNone {
			return fmt.Errorf("--fail-on の値が不正です: %q (有効値: critical/high/medium/low/kev)", scanFailOn)
		}
	}

	// Codex R3 fix: --fail-on requires waiting for the server-side
	// vulnerability scan to finish — that is the only path that produces
	// the severity counts the threshold check evaluates against. If the
	// user (or a CI template) passes --wait-for-scan=false alongside
	// --fail-on we previously silently returned success (exit 0) after
	// upload, which let critical findings slip past a gated pipeline.
	// Fail-fast at startup with a usage error so the misconfiguration is
	// obvious instead of fail-soft into a green build.
	if failOnLevel != severity.LevelNone && !scanWaitForScan {
		return fmt.Errorf("--fail-on requires --wait-for-scan=true; either drop --wait-for-scan=false (it defaults to true) or remove --fail-on")
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

	// 設定の解決: config file → env → CLI flag の precedence で merge する。
	// config file が無くても flag/env だけで動く (Codex R2 fix): CI runner
	// のような ephemeral 環境向け。
	configDir := filepath.Join(os.Getenv("HOME"), ".sbomhub")
	if os.Getenv("USERPROFILE") != "" {
		configDir = filepath.Join(os.Getenv("USERPROFILE"), ".sbomhub")
	}

	cfg, err := resolveCredentials(configDir)
	if err != nil {
		return &scanExitError{
			code: exitAPIError,
			msg:  fmt.Sprintf("設定の読み込みに失敗しました: %v", err),
		}
	}
	if cfg.APIKey == "" {
		return &scanExitError{
			code: exitAPIError,
			msg:  "API Keyが設定されていません。 'sbomhub login' で対話設定するか、 --api-key フラグ・ 環境変数 SBOMHUB_API_KEY を指定してください",
		}
	}
	if cfg.APIURL == "" {
		return &scanExitError{
			code: exitAPIError,
			msg:  "API URLが設定されていません。 'sbomhub login' で設定するか、 --api-url フラグ・ 環境変数 SBOMHUB_API_URL を指定してください",
		}
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
		return &scanExitError{code: exitAPIError, msg: fmt.Sprintf("アップロードに失敗しました: %v", err)}
	}

	fmt.Println()
	printSuccess("アップロード完了！")
	fmt.Println()

	// --fail-on が指定されていればサーバ側スキャン完了を polling、
	// それ以外は upload までで終わって従来通り即時 return。
	var summary *api.VulnerabilitySummary
	var scanTimedOut bool
	var scanFailedMsg string
	if failOnLevel != severity.LevelNone && scanWaitForScan {
		summary, scanTimedOut, scanFailedMsg = waitForScanCompletion(client, result.ProjectID, result.SBOMID)
	}

	// 結果表示
	printResultBox(componentCount, result, summary)

	// --fail-on の判定
	if failOnLevel == severity.LevelNone {
		return nil
	}

	// Defensive guard: runScan's startup check already rejects
	// --fail-on with --wait-for-scan=false, so this branch should be
	// unreachable. Kept as a safety net so future refactors can't
	// silently re-introduce the fail-soft slip-through.
	if !scanWaitForScan {
		return &scanExitError{
			code: exitAPIError,
			msg:  "--fail-on requires --wait-for-scan=true (internal invariant violated)",
		}
	}

	if scanTimedOut {
		// 設計判断: timeout 時は --fail-on は trip させない。 false negative
		// (本当はあった脆弱性を見逃す) は許容、 false positive (clean な
		// CI を不当に止める) は避ける。 ユーザーは exit 2 を見て CI 側で
		// 明示的に判断する。
		return &scanExitError{
			code: exitScanTimeout,
			msg:  fmt.Sprintf("--wait-timeout %s 以内にサーバ側脆弱性スキャンが完了しませんでした。 --fail-on は評価されていません", scanWaitTimeout),
		}
	}
	if scanFailedMsg != "" {
		return &scanExitError{
			code: exitScanTimeout,
			msg:  fmt.Sprintf("サーバ側脆弱性スキャンが失敗しました: %s。 --fail-on は評価されていません", scanFailedMsg),
		}
	}
	if summary == nil {
		return &scanExitError{code: exitAPIError, msg: "スキャン結果の取得に失敗しました"}
	}

	// Codex R1 fix: KEV is sourced from the scan-status response (server
	// joins vulnerabilities.in_kev). The canonical upload endpoint does
	// NOT populate result.KEVCount — relying on it left `--fail-on kev`
	// silently never tripping. Older servers (pre Trust Rescue R1) that
	// omit the field will report KEV=0, in which case --fail-on kev is a
	// no-op against that deployment.
	counts := severity.Counts{
		Critical: summary.Critical,
		High:     summary.High,
		Medium:   summary.Medium,
		Low:      summary.Low,
		Unknown:  summary.Unknown,
		KEV:      summary.KEV,
	}
	if severity.ShouldFail(counts, failOnLevel) {
		return &scanExitError{
			code: exitThresholdExceeded,
			msg:  fmt.Sprintf("--fail-on %s: 指定された重大度以上の脆弱性が検出されました (critical=%d high=%d medium=%d low=%d unknown=%d kev=%d)", scanFailOn, counts.Critical, counts.High, counts.Medium, counts.Low, counts.Unknown, counts.KEV),
		}
	}

	return nil
}

// waitForScanCompletion polls GET /api/v1/projects/:id/sboms/:sbom_id/scan-status
// until it reports a terminal state ("completed" or "failed"), or until
// --wait-timeout elapses. Polling cadence is --poll-interval. Returns:
//
//   - summary:        latest counts on success (status=completed)
//   - timedOut:       true if the timeout fired first
//   - failedErrorMsg: non-empty if server reported the scan failed
//
// On transient API errors the function logs a brief notice and keeps
// polling rather than aborting; the network may flap mid-CI and we
// prefer to ride that out within the user's wait-timeout budget.
func waitForScanCompletion(client *api.Client, projectID, sbomID string) (summary *api.VulnerabilitySummary, timedOut bool, failedErrorMsg string) {
	deadline := time.Now().Add(scanWaitTimeout)
	tick := scanPollInterval
	if tick <= 0 {
		tick = 5 * time.Second
	}

	fmt.Printf("⏳ サーバ側脆弱性スキャン待機中 (timeout=%s, interval=%s)...\n", scanWaitTimeout, tick)

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, true, ""
		}

		status, err := client.GetScanStatus(projectID, sbomID)
		if err != nil {
			fmt.Printf("   ⚠️  scan-status 取得エラー (継続して再試行): %v\n", err)
		} else {
			elapsed := scanWaitTimeout - remaining
			fmt.Printf("   状態: %-9s 経過: %4s / %s  (critical=%d high=%d medium=%d low=%d unknown=%d kev=%d total=%d)\n",
				status.Status, elapsed.Round(time.Second), scanWaitTimeout,
				status.Vulnerabilities.Critical, status.Vulnerabilities.High,
				status.Vulnerabilities.Medium, status.Vulnerabilities.Low,
				status.Vulnerabilities.Unknown,
				status.Vulnerabilities.KEV, status.Vulnerabilities.Total)

			switch status.Status {
			case "completed":
				return &status.Vulnerabilities, false, ""
			case "failed":
				return &status.Vulnerabilities, false, fallbackString(status.Error, "unspecified server-side scan failure")
			}
		}

		sleep := tick
		if sleep > remaining {
			sleep = remaining
		}
		time.Sleep(sleep)
	}
}

func fallbackString(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func printResultBox(componentCount int, result *api.UploadResult, summary *api.VulnerabilitySummary) {
	fmt.Println("┌─────────────────────────────────────────────────────────┐")
	fmt.Println("│ スキャン完了                                            │")
	fmt.Println("├─────────────────────────────────────────────────────────┤")
	fmt.Printf("│ コンポーネント: %-40d │\n", componentCount)
	vulnSummary := formatScanVulnSummary(result, summary)
	fmt.Printf("│ 脆弱性: %-48s │\n", vulnSummary)
	fmt.Println("│                                                         │")
	fmt.Printf("│ URL: %-51s │\n", result.URL)
	fmt.Println("└─────────────────────────────────────────────────────────┘")
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

// formatScanVulnSummary builds the per-severity line shown in the result
// box. Server-side scan counts (from scan-status polling) take priority
// when available; otherwise the legacy `UploadResult` fields are used —
// those are zero today because the canonical upload endpoint does not
// return counts, but keeping the fallback preserves graceful behaviour
// against future server versions.
//
// KEV count: when scan-status `summary` is available we trust its KEV
// bucket (joined server-side against vulnerabilities.in_kev). When only
// the legacy `result.KEVCount` is available we fall back to it; that
// field is left at zero by the canonical upload endpoint today, so the
// fallback is effectively "no KEV info" rather than authoritative.
//
// Unknown count (Codex R2 fix): the server-side scan-status emits an
// `unknown` bucket for vulnerabilities the enrichment pipeline could not
// map to a CVSS severity (NVD lag, missing CVSS vector, etc.). Earlier
// versions of this function dropped that bucket, so a scan with N
// "unknown" CVEs and zero across critical/high/medium/low rendered as
// "なし ✅" — silently hiding real findings from the operator. We now
// surface the count alongside the rated buckets. It is intentionally NOT
// fed into severity.ShouldFail (see severity.Counts doc).
func formatScanVulnSummary(result *api.UploadResult, summary *api.VulnerabilitySummary) string {
	c, h, m, l, u, kev, total := 0, 0, 0, 0, 0, 0, 0
	if summary != nil {
		c, h, m, l, u, kev, total = summary.Critical, summary.High, summary.Medium, summary.Low, summary.Unknown, summary.KEV, summary.Total
	} else if result != nil {
		// UploadResult has no Unknown field today; leave u=0 in the fallback.
		c, h, m, l, kev, total = result.Critical, result.High, result.Medium, result.Low, result.KEVCount, result.VulnerabilityCount
	}

	if total == 0 && kev == 0 && u == 0 {
		return "なし ✅"
	}

	parts := []string{}
	if kev > 0 {
		parts = append(parts, fmt.Sprintf("%d KEV 🔥", kev))
	}
	if c > 0 {
		parts = append(parts, fmt.Sprintf("%d Critical", c))
	}
	if h > 0 {
		parts = append(parts, fmt.Sprintf("%d High", h))
	}
	if m > 0 {
		parts = append(parts, fmt.Sprintf("%d Medium", m))
	}
	if l > 0 {
		parts = append(parts, fmt.Sprintf("%d Low", l))
	}
	if u > 0 {
		parts = append(parts, fmt.Sprintf("%d Unknown", u))
	}
	if len(parts) == 0 {
		return "なし ✅"
	}
	return strings.Join(parts, ", ")
}
