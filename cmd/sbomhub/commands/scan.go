package commands

import (
	"context"
	"encoding/json"
	"errors"
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

// scanJSONResult is the canonical schema for `sbomhub scan --json`.
// Keep this in sync with sbomhub-internal/draft-sbomhub-action/entrypoint.sh
// jq paths and with the action.yml outputs contract — consumers (the
// GitHub Action wrapper, CI templates, downstream automation) treat this
// as the contract.
//
// Schema rationale per field:
//
//   - SBOMID / ProjectID: server-assigned UUIDs from the canonical upload
//     endpoint. Empty when the run never reached upload (dry-run, early
//     config error before upload).
//   - ProjectName / ProjectCreated: surface name + whether get-or-create
//     created a fresh project so CI logs can report it without an extra
//     GET. ProjectName may be empty when --project was passed as a UUID
//     (we don't round-trip a GET to fetch the name; see UploadSBOM).
//   - ComponentCount: count of components in the local SBOM (CycloneDX
//     `components[]` length, or SPDX `packages[]`). Computed before
//     upload so it survives polling errors.
//   - Format: "cyclonedx" / "spdx" — echoes --format.
//   - URL: web UI link for the project; best-effort from API base URL.
//   - ScanStatus: one of:
//     "completed" — server-side scan reached terminal state without error
//     "failed"    — server-side scan errored (Vulnerabilities may be partial)
//     "running"   — wait-timeout fired while server still scanning (we
//     observed at least one snapshot before timing out)
//     "unknown"   — no signal at all (--wait-timeout with no successful
//     poll, or permanent 4xx fast-fail during polling)
//     "skipped"   — --wait-for-scan=false OR --dry-run skipped the loop
//   - VulnerabilitySummary: per-severity counts. KEV is the orthogonal
//     "any CISA Known Exploited CVE" bucket (also counted in its CVSS
//     bucket). Total is the sum of c/h/m/l/u (NOT including KEV to avoid
//     double-counting against the CVSS buckets).
//   - FailOn: echoes the --fail-on threshold the run was configured with
//     (null when unset), whether the threshold tripped, and the exit code
//     the process will return. ExitCode mirrors the documented set:
//     0 success / 1 threshold exceeded / 2 scan timeout or server failure
//     / 3 API or config error.
type scanJSONResult struct {
	SBOMID               string              `json:"sbom_id"`
	ProjectID            string              `json:"project_id"`
	ProjectName          string              `json:"project_name"`
	ProjectCreated       bool                `json:"project_created"`
	ComponentCount       int                 `json:"component_count"`
	Format               string              `json:"format"`
	URL                  string              `json:"url"`
	ScanStatus           string              `json:"scan_status"`
	VulnerabilitySummary scanJSONVulnSummary `json:"vulnerability_summary"`
	FailOn               scanJSONFailOn      `json:"fail_on"`
}

// scanJSONVulnSummary mirrors api.VulnerabilitySummary but pins JSON
// field naming and ordering for stable wire output. Total is computed
// locally as c+h+m+l+u (CVSS-rated buckets only) rather than trusting
// the server's `total` field — matches the formatScanVulnSummary
// rationale: a server that emits per-bucket counts but leaves `total`
// at zero (older API, streamed/partial response) would otherwise
// produce a misleading total=0 in --json output while the human box
// shows real findings.
type scanJSONVulnSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	KEV      int `json:"kev"`
	Unknown  int `json:"unknown"`
	Total    int `json:"total"`
}

// scanJSONFailOn carries the --fail-on configuration + outcome.
// Threshold is *string so the JSON encodes `null` when --fail-on was
// not supplied — consumers can use `jq -e '.fail_on.threshold'` to
// branch on "was a threshold configured" without overloading the
// empty-string sentinel.
type scanJSONFailOn struct {
	Threshold *string `json:"threshold"`
	Triggered bool    `json:"triggered"`
	ExitCode  int     `json:"exit_code"`
}

// scanFinalState captures every output of the scan/upload/poll pipeline
// that buildScanJSONResult needs. Centralising the inputs keeps the
// helper unit-testable (we can construct a scanFinalState directly in
// tests without standing up a fake server or invoking the real scanner)
// and keeps the JSON builder pure — no globals, no I/O.
type scanFinalState struct {
	componentCount  int
	format          string
	uploadResult    *api.UploadResult
	summary         *api.VulnerabilitySummary
	waitForScan     bool
	dryRun          bool
	scanTimedOut    bool
	scanFailedMsg   string
	scanAPIErrMsg   string
	failOnStr       string // original CLI value, empty when not set
	failOnTriggered bool
	exitCode        int
}

// computeScanStatus maps the final pipeline state to one of the
// canonical scan_status values. Order matters: API error wins over
// timeout (a permanent 4xx tells us the polling endpoint is broken,
// status is unknowable), and timeout-with-snapshot reports "running"
// (the last server observation) rather than "unknown" so consumers can
// distinguish "we saw progress but didn't wait long enough" from "we
// never saw anything".
func computeScanStatus(in scanFinalState) string {
	if in.dryRun {
		return "skipped"
	}
	if !in.waitForScan {
		return "skipped"
	}
	if in.scanAPIErrMsg != "" {
		return "unknown"
	}
	if in.scanFailedMsg != "" {
		return "failed"
	}
	if in.scanTimedOut {
		if in.summary != nil {
			return "running"
		}
		return "unknown"
	}
	if in.summary != nil {
		return "completed"
	}
	return "unknown"
}

// buildScanJSONResult assembles the canonical --json payload from the
// final pipeline state. Pure function: no globals, no I/O — the
// emission to stdout happens in runScan.
func buildScanJSONResult(in scanFinalState) scanJSONResult {
	r := scanJSONResult{
		ComponentCount: in.componentCount,
		Format:         in.format,
		ScanStatus:     computeScanStatus(in),
	}

	if in.uploadResult != nil {
		r.SBOMID = in.uploadResult.SBOMID
		r.ProjectID = in.uploadResult.ProjectID
		r.ProjectName = in.uploadResult.ProjectName
		r.ProjectCreated = in.uploadResult.ProjectCreated
		r.URL = in.uploadResult.URL
		// If summary is nil, fall back to legacy UploadResult counts
		// (canonical upload endpoint leaves them at zero today, but
		// preserve the path for future server versions that populate
		// counts on the upload response).
		if in.summary == nil && (in.uploadResult.Critical+in.uploadResult.High+in.uploadResult.Medium+in.uploadResult.Low+in.uploadResult.KEVCount > 0) {
			r.VulnerabilitySummary = scanJSONVulnSummary{
				Critical: in.uploadResult.Critical,
				High:     in.uploadResult.High,
				Medium:   in.uploadResult.Medium,
				Low:      in.uploadResult.Low,
				KEV:      in.uploadResult.KEVCount,
				Total:    in.uploadResult.Critical + in.uploadResult.High + in.uploadResult.Medium + in.uploadResult.Low,
			}
		}
	}

	if in.summary != nil {
		r.VulnerabilitySummary = scanJSONVulnSummary{
			Critical: in.summary.Critical,
			High:     in.summary.High,
			Medium:   in.summary.Medium,
			Low:      in.summary.Low,
			KEV:      in.summary.KEV,
			Unknown:  in.summary.Unknown,
			// Compute total locally from CVSS buckets — see schema doc
			// rationale. KEV is orthogonal (already counted in c/h/m/l),
			// so it is intentionally NOT added.
			Total: in.summary.Critical + in.summary.High + in.summary.Medium + in.summary.Low + in.summary.Unknown,
		}
	}

	r.FailOn = scanJSONFailOn{
		Threshold: nil,
		Triggered: in.failOnTriggered,
		ExitCode:  in.exitCode,
	}
	if in.failOnStr != "" {
		s := in.failOnStr
		r.FailOn.Threshold = &s
	}

	return r
}

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

	scanCmd.Flags().StringVarP(&scanProject, "project", "p", "", "プロジェクト名 または UUID (このフラグを明示指定したときのみ UUID 形式値を既存プロジェクトの ID として扱う。 未指定時はディレクトリ名を name として get-or-create)")
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
	out := GetOutputConfig()
	outputJSON := out.IsJSON()

	// scanPrintf routes the legacy bare fmt.Printf progress lines to
	// stderr when --json is on (so stdout stays clean for the JSON
	// payload) and to stdout otherwise. Equivalent to out.Print but
	// preserves the existing format-string call sites without forcing
	// every line through the Quiet check (these are progress markers,
	// not user-facing data; --quiet still suppresses them via
	// out.Print's check downstream when consumers migrate).
	scanPrintf := func(format string, a ...interface{}) {
		if out.Quiet {
			return
		}
		w := os.Stdout
		if outputJSON {
			w = os.Stderr
		}
		fmt.Fprintf(w, format, a...)
	}
	scanPrintln := func() {
		if out.Quiet {
			return
		}
		w := os.Stdout
		if outputJSON {
			w = os.Stderr
		}
		fmt.Fprintln(w)
	}

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

	scanPrintf("📦 スキャン開始: %s\n", absPath)
	scanPrintln()

	// スキャナーの選択
	s, err := scanner.New(scanTool)
	if err != nil {
		return fmt.Errorf("スキャナーの初期化に失敗しました: %w", err)
	}

	scanPrintf("🔍 ツール: %s\n", s.Name())

	// スキャン実行
	startTime := time.Now()
	sbomData, err := s.Scan(absPath, scanFormat)
	if err != nil {
		return fmt.Errorf("スキャンに失敗しました: %w", err)
	}
	elapsed := time.Since(startTime)

	scanPrintf("⏱️  スキャン時間: %s\n", elapsed.Round(time.Millisecond))

	// コンポーネント数を表示
	componentCount := countComponents(sbomData)
	scanPrintf("📋 コンポーネント数: %d\n", componentCount)
	scanPrintln()

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
		if outputJSON {
			// Emit a minimal JSON payload so automation parsing
			// stdout still gets a stable shape. scan_status="skipped"
			// signals "no server-side scan was attempted".
			res := buildScanJSONResult(scanFinalState{
				componentCount: componentCount,
				format:         scanFormat,
				dryRun:         true,
				waitForScan:    scanWaitForScan,
				failOnStr:      scanFailOn,
				exitCode:       exitSuccess,
			})
			_ = out.PrintJSON(res)
		}
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

	// プロジェクト名の決定。
	//
	// Codex R12 fix (P2): we track whether --project was *explicitly*
	// supplied so UploadSBOM can decide if a UUID-shaped value should be
	// treated as a project ID. Without this distinction a directory like
	// /tmp/01234567-0123-0123-0123-0123456789ab (e.g. an ephemeral CI
	// checkout) would have its basename routed through the R6 UUID
	// short-circuit and silently attach the SBOM to whatever random
	// project happened to share that ID. We define "explicit" as a
	// non-empty --project flag value: that's exactly the branch where
	// the caller demonstrably chose the value, and matches the existing
	// `scanProject == ""` fallback condition below. (Using
	// cmd.Flags().Changed would be equivalent here, but keeping the
	// check inline avoids reaching into cobra plumbing from the test
	// surface.)
	projectExplicit := scanProject != ""
	projectName := scanProject
	if projectName == "" {
		// ディレクトリ名をプロジェクト名として使用
		projectName = filepath.Base(absPath)
		if projectName == "." || projectName == "/" {
			cwd, _ := os.Getwd()
			projectName = filepath.Base(cwd)
		}
	}

	scanPrintf("📤 アップロード中: プロジェクト '%s'\n", projectName)

	// アップロード。 projectExplicit=false (= dir-basename fallback) のときは
	// UploadSBOM は projectName が UUID 形式であっても ID として扱わず、
	// CreateProject(get-or-create) 経由で安全に name として登録する。
	result, err := client.UploadSBOM(projectName, projectExplicit, sbomData, scanFormat)
	if err != nil {
		return &scanExitError{code: exitAPIError, msg: fmt.Sprintf("アップロードに失敗しました: %v", err)}
	}

	scanPrintln()
	printSuccess("アップロード完了！")
	scanPrintln()

	// Codex R4 finding 1 fix: poll whenever --wait-for-scan is true,
	// regardless of --fail-on. The flag's help text promises to wait for
	// the server-side scan, and the canonical upload endpoint does NOT
	// populate severity counts in its response (vulnerability scans run
	// asynchronously after upload). Previously this branch was gated on
	// `failOnLevel != None`, so a default `sbomhub scan .` (no --fail-on,
	// default --wait-for-scan=true) returned immediately with counts=0
	// and printed "なし ✅" — silently misrepresenting a scan that had
	// real findings once the server finished enriching it.
	//
	// --wait-for-scan=false (with no --fail-on) still skips polling: that
	// is the explicit opt-out, and the upload response's zero counts are
	// the user's stated intent. --wait-for-scan=false with --fail-on is
	// already rejected at startup by the R3 guard above.
	var summary *api.VulnerabilitySummary
	var scanTimedOut bool
	var scanFailedMsg string
	var scanAPIErrMsg string
	var scanLastFetchedAt time.Time
	if scanWaitForScan {
		// Bind the polling loop's deadline to a context so the in-flight
		// HTTP request can be cancelled the moment --wait-timeout expires
		// (Codex R4 finding 2). The httpClient default 60s timeout was
		// the only thing in effect before this — meaning --wait-timeout=10s
		// could still hang for up to 60s on a slow server.
		ctx, cancel := context.WithTimeout(context.Background(), scanWaitTimeout)
		summary, scanTimedOut, scanFailedMsg, scanAPIErrMsg, scanLastFetchedAt = waitForScanCompletion(ctx, client, result.ProjectID, result.SBOMID)
		cancel()
	}

	// Compute the final state of the run. From this point we have a
	// single linear path: figure out the exit error (if any), build the
	// JSON payload (or print the result box) once, then return.
	//
	// We intentionally compute exitErr BEFORE emitting output so the
	// JSON payload can include the documented `fail_on.exit_code` value
	// — consumers (the GitHub Action wrapper, downstream automation)
	// rely on stdout-JSON being a complete snapshot rather than needing
	// to inspect the process exit code separately.
	var (
		exitErr         error
		failOnTriggered bool
		exitCode        = exitSuccess
	)

	switch {
	case scanAPIErrMsg != "":
		// Codex R7 fix: scan-status polling hit a permanent client-side
		// error (typically 401/403 from bad auth, or 404 from a server
		// that does not implement scan-status). Fast-fail with exit-3
		// (API error) regardless of --fail-on — a broken polling
		// endpoint means we cannot trust ANY downstream counts.
		exitCode = exitAPIError
		exitErr = &scanExitError{
			code: exitAPIError,
			msg:  fmt.Sprintf("scan-status polling aborted: %s", scanAPIErrMsg),
		}

	case failOnLevel == severity.LevelNone:
		// No threshold configured. --wait-for-scan timeout / failure
		// is surfaced as a stderr warning but does not block CI.
		exitCode = exitSuccess

	case !scanWaitForScan:
		// Defensive guard: the startup check already rejects --fail-on
		// with --wait-for-scan=false; this branch is unreachable except
		// under future refactor regression.
		exitCode = exitAPIError
		exitErr = &scanExitError{
			code: exitAPIError,
			msg:  "--fail-on requires --wait-for-scan=true (internal invariant violated)",
		}

	case scanTimedOut:
		// Timeout under --fail-on: do NOT trip the threshold (false
		// negative tolerated, false positive avoided). Surface exit-2
		// so CI can branch on it explicitly.
		exitCode = exitScanTimeout
		exitErr = &scanExitError{
			code: exitScanTimeout,
			msg:  fmt.Sprintf("--wait-timeout %s 以内にサーバ側脆弱性スキャンが完了しませんでした。 --fail-on は評価されていません", scanWaitTimeout),
		}

	case scanFailedMsg != "":
		exitCode = exitScanTimeout
		exitErr = &scanExitError{
			code: exitScanTimeout,
			msg:  fmt.Sprintf("サーバ側脆弱性スキャンが失敗しました: %s。 --fail-on は評価されていません", scanFailedMsg),
		}

	case summary == nil:
		exitCode = exitAPIError
		exitErr = &scanExitError{code: exitAPIError, msg: "スキャン結果の取得に失敗しました"}

	default:
		// Codex R1 fix: KEV is sourced from the scan-status response.
		counts := severity.Counts{
			Critical: summary.Critical,
			High:     summary.High,
			Medium:   summary.Medium,
			Low:      summary.Low,
			Unknown:  summary.Unknown,
			KEV:      summary.KEV,
		}
		if severity.ShouldFail(counts, failOnLevel) {
			failOnTriggered = true
			exitCode = exitThresholdExceeded
			exitErr = &scanExitError{
				code: exitThresholdExceeded,
				msg:  fmt.Sprintf("--fail-on %s: 指定された重大度以上の脆弱性が検出されました (critical=%d high=%d medium=%d low=%d unknown=%d kev=%d)", scanFailOn, counts.Critical, counts.High, counts.Medium, counts.Low, counts.Unknown, counts.KEV),
			}
		}
	}

	// Build the final JSON snapshot. Computed even when --json is off
	// so a future refactor can log it for debugging / telemetry without
	// changing the call site.
	finalState := scanFinalState{
		componentCount:  componentCount,
		format:          scanFormat,
		uploadResult:    result,
		summary:         summary,
		waitForScan:     scanWaitForScan,
		dryRun:          false,
		scanTimedOut:    scanTimedOut,
		scanFailedMsg:   scanFailedMsg,
		scanAPIErrMsg:   scanAPIErrMsg,
		failOnStr:       scanFailOn,
		failOnTriggered: failOnTriggered,
		exitCode:        exitCode,
	}

	// Emit either the JSON payload (machine consumers — GitHub Action,
	// CI templates, downstream tooling) or the human result box. Never
	// both: stdout must stay parseable for jq.
	if outputJSON {
		jsonResult := buildScanJSONResult(finalState)
		_ = out.PrintJSON(jsonResult)
	} else {
		printResultBox(componentCount, result, summary)
	}

	// Operator warnings always go to stderr (independent of --json mode)
	// so CI logs surface context even when stdout is being captured for
	// JSON parsing.
	if exitErr == nil && failOnLevel == severity.LevelNone {
		if scanTimedOut {
			// Codex R5 fix: when polling timed out we now return the
			// most recently observed status snapshot (if any). Surface
			// the snapshot timestamp so operators know whether they're
			// looking at partial counts or nothing at all.
			if !scanLastFetchedAt.IsZero() {
				fmt.Fprintf(os.Stderr, "⚠️  サーバ側脆弱性スキャンが --wait-timeout %s 以内に完了しませんでした。 最後の取得時点 (%s) の暫定 counts を表示しています。\n", scanWaitTimeout, scanLastFetchedAt.Format(time.RFC3339))
			} else {
				fmt.Fprintf(os.Stderr, "⚠️  サーバ側脆弱性スキャンが --wait-timeout %s 以内に完了しませんでした。 暫定 counts は取得できませんでした。\n", scanWaitTimeout)
			}
		} else if scanFailedMsg != "" {
			fmt.Fprintf(os.Stderr, "⚠️  サーバ側脆弱性スキャンが失敗しました: %s\n", scanFailedMsg)
		}
	}

	return exitErr
}

// waitForScanCompletion polls GET /api/v1/projects/:id/sboms/:sbom_id/scan-status
// until it reports a terminal state ("completed" or "failed"), or until
// the supplied ctx is cancelled (typically via context.WithTimeout bound
// to --wait-timeout in runScan). Polling cadence is --poll-interval.
// Returns:
//
//   - summary:        latest counts on success (status=completed); on
//     timeout, the most-recently observed counts (Codex R5 fix); nil only
//     when no poll ever returned a valid response before ctx fired.
//   - timedOut:       true if ctx fired before a terminal state was seen
//   - failedErrorMsg: non-empty if server reported the scan failed
//     (server-side scan ran but the enrichment pipeline errored). Distinct
//     from apiErrMsg — this maps to exit-2 (scan-timeout family), since
//     the server reached a terminal "this scan is dead" state and the CLI
//     could not enforce --fail-on against it.
//   - apiErrMsg:      non-empty if scan-status polling aborted because the
//     endpoint returned a permanent client-side error (HTTP 4xx). Maps to
//     exit-3 (API error). See Codex R7 fix below for the full rationale.
//   - lastFetchedAt:  wall-clock timestamp of the most recent successful
//     poll; zero time.Time when no poll ever succeeded. Caller surfaces
//     this to the operator alongside the timeout warning so the partial
//     counts are clearly labelled as a snapshot rather than a final tally.
//
// On transient API errors the function logs a brief notice and keeps
// polling rather than aborting; the network may flap mid-CI and we
// prefer to ride that out within the user's wait-timeout budget. The
// only exception is when the error is itself caused by ctx cancellation —
// that surfaces as a clean timeout instead of a noisy "retry until clock
// catches up" loop (Codex R4 finding 2).
//
// Codex R5 fix: previously this function returned summary=nil on the
// timeout path, which caused runScan -> printResultBox -> formatScanVulnSummary
// to fall back to the canonical upload response's zero counts. The result
// box rendered "なし ✅" right next to the "scan timed out, intermediate
// counts shown" warning — actively misleading. We now keep the latest
// successful snapshot and return it so the operator sees the real partial
// numbers and the warning is consistent with the box content.
//
// Codex R7 fix: HTTP 4xx responses from scan-status now fast-fail instead
// of being silently retried until --wait-timeout. The two pathological
// failure modes this catches:
//
//   - 401/403: the operator's API key is wrong, or the key lost access to
//     the project. Retrying for 5 minutes will not fix this; the only
//     useful signal is "your auth is broken, fix it and re-run".
//   - 404:     this server build does not implement the scan-status
//     endpoint (older API). Retrying will never produce a different
//     answer; surfacing the 404 immediately lets the operator either
//     upgrade the server or drop --wait-for-scan / --fail-on for now.
//
// 5xx and network-flap errors are still classified as transient and
// retried — that's the original "ride out a brief blip mid-CI" intent.
// Unknown error types (e.g. JSON parse failures) are also kept on the
// transient path because they may signal a temporary upstream glitch
// rather than a permanent contract mismatch.
//
// Codex R13 fix (P2): the R7 split treated EVERY 4xx as permanent,
// including 429 Too Many Requests. An upstream gateway or API rate
// limiter throttling the polling loop therefore fast-failed CIs that
// would have succeeded on the next poll. We now delegate the
// transient/permanent classification to APIError.IsRetryable (429 +
// 5xx → retryable, other 4xx → permanent) and honour the server's
// Retry-After hint when present (capped only by ctx deadline, so a
// rogue large Retry-After never outlives --wait-timeout).
func waitForScanCompletion(ctx context.Context, client *api.Client, projectID, sbomID string) (summary *api.VulnerabilitySummary, timedOut bool, failedErrorMsg, apiErrMsg string, lastFetchedAt time.Time) {
	tick := scanPollInterval
	if tick <= 0 {
		tick = 5 * time.Second
	}

	// Progress prints route to stderr in --json mode so stdout stays
	// parseable for the JSON payload emitted by runScan.
	progressW := func() *os.File {
		if GetOutputConfig().IsJSON() {
			return os.Stderr
		}
		return os.Stdout
	}

	fmt.Fprintf(progressW(), "⏳ サーバ側脆弱性スキャン待機中 (timeout=%s, interval=%s)...\n", scanWaitTimeout, tick)

	startTime := time.Now()
	var latest *api.VulnerabilitySummary
	var latestAt time.Time
	for {
		if ctx.Err() != nil {
			return latest, true, "", "", latestAt
		}

		// nextSleep defaults to the configured poll cadence. A retryable
		// APIError carrying a Retry-After hint may bump it up for this
		// iteration only (so a one-off 429 with "Retry-After: 30" doesn't
		// permanently slow the loop down). ctx-bound select below caps
		// any inflated sleep at the remaining --wait-timeout budget.
		nextSleep := tick

		status, err := client.GetScanStatus(ctx, projectID, sbomID)
		if err != nil {
			// If the error is because ctx was cancelled (deadline hit
			// mid-request) treat it as a clean timeout — not a transient
			// API error to retry past the deadline.
			if ctx.Err() != nil {
				return latest, true, "", "", latestAt
			}

			// Classify the API error. 429 / 5xx are retryable transient
			// failures; other 4xx are permanent (bad auth, missing
			// endpoint, malformed path) and fast-fail to exit-3 so the
			// operator sees the real failure mode rather than a misleading
			// "scan timed out".
			var apiErr *api.APIError
			if errors.As(err, &apiErr) {
				if !apiErr.IsRetryable() {
					fmt.Fprintf(progressW(), "   ✗ scan-status 取得エラー (HTTP %d): 永続的なエラーのため即座に中断します\n", apiErr.StatusCode)
					return latest, false, "", fmt.Sprintf("HTTP %d %s: %s", apiErr.StatusCode, apiErr.URL, strings.TrimSpace(apiErr.Message)), latestAt
				}
				// Retryable (429 / 5xx). Honour Retry-After when the
				// server supplied it AND it is longer than our default
				// cadence; we never go faster than the operator asked
				// (would defeat the rate-limit hint) but we still let
				// ctx cancellation wake the sleep below.
				if apiErr.RetryAfter > nextSleep {
					nextSleep = apiErr.RetryAfter
				}
				if apiErr.StatusCode == 429 {
					fmt.Fprintf(progressW(), "   ⚠️  scan-status rate limited (HTTP 429), retrying after %s...\n", nextSleep.Round(time.Second))
				} else {
					fmt.Fprintf(progressW(), "   ⚠️  scan-status server error (HTTP %d), retrying after %s...\n", apiErr.StatusCode, nextSleep.Round(time.Second))
				}
			} else {
				// Non-APIError transient (network flap, JSON parse
				// glitch, …): log and keep polling within ctx budget.
				fmt.Fprintf(progressW(), "   ⚠️  scan-status 取得エラー (継続して再試行): %v\n", err)
			}
		} else {
			elapsed := time.Since(startTime)
			fmt.Fprintf(progressW(), "   状態: %-9s 経過: %4s / %s  (critical=%d high=%d medium=%d low=%d unknown=%d kev=%d total=%d)\n",
				status.Status, elapsed.Round(time.Second), scanWaitTimeout,
				status.Vulnerabilities.Critical, status.Vulnerabilities.High,
				status.Vulnerabilities.Medium, status.Vulnerabilities.Low,
				status.Vulnerabilities.Unknown,
				status.Vulnerabilities.KEV, status.Vulnerabilities.Total)

			// Snapshot by value, not by &status.Vulnerabilities — `status`
			// is rebound each loop iteration; keeping a pointer into the
			// previous iteration's struct would silently mutate or alias.
			snap := status.Vulnerabilities
			latest = &snap
			latestAt = time.Now()

			switch status.Status {
			case "completed":
				return latest, false, "", "", latestAt
			case "failed":
				return latest, false, fallbackString(status.Error, "unspecified server-side scan failure"), "", latestAt
			}
		}

		// Sleep until next poll tick or ctx cancellation, whichever
		// comes first. select prevents a fixed-tick Sleep from outliving
		// the timeout. nextSleep equals `tick` on the happy path; a
		// retryable APIError carrying Retry-After may have bumped it up
		// for this single iteration (Codex R13 P2).
		timer := time.NewTimer(nextSleep)
		select {
		case <-ctx.Done():
			timer.Stop()
			return latest, true, "", "", latestAt
		case <-timer.C:
		}
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
//
// Codex R6 fix (Finding 2): "no findings" is determined from the sum of
// per-bucket counts rather than the server-supplied `total`. Earlier code
// short-circuited on `total == 0` (with kev/unknown defensively added),
// which mis-rendered "なし ✅" any time the server populated per-severity
// buckets but left `total` at zero (partial / streamed responses, or an
// older API build that doesn't compute total client-side). Trusting the
// sum we compute locally also matches the semantics of the buckets we
// actually display below.
//
// Codex R15 fix (P2): when polling returns summary=nil (permanent API
// error before any successful poll, ctx timeout before any snapshot, or
// --wait-for-scan=false skipping the loop entirely) AND the upload
// response carries no usable counts, render an explicit "スキャン未完了"
// marker instead of falling through to the zero-bucket "なし ✅" path.
// The previous behaviour mis-claimed a clean result next to whatever
// warning the caller printed below the box — confusing humans reading
// CI logs and letting automation conclude the scan was vulnerability-
// free. The legacy `result.*` fallback is preserved when those fields
// are non-zero (future server versions that populate counts on upload),
// so we only emit the "未完了" marker when there is truly no signal.
func formatScanVulnSummary(result *api.UploadResult, summary *api.VulnerabilitySummary) string {
	c, h, m, l, u, kev := 0, 0, 0, 0, 0, 0
	switch {
	case summary != nil:
		c, h, m, l, u, kev = summary.Critical, summary.High, summary.Medium, summary.Low, summary.Unknown, summary.KEV
	case result != nil && result.Critical+result.High+result.Medium+result.Low+result.KEVCount > 0:
		// Future-server fallback: upload endpoint returned non-zero
		// counts. Honour them since we have no scan-status snapshot to
		// use instead. UploadResult has no Unknown field today; leave
		// u=0 in the fallback.
		c, h, m, l, kev = result.Critical, result.High, result.Medium, result.Low, result.KEVCount
	default:
		// summary is nil AND the upload result carries no usable counts.
		// Polling either failed (timeout w/o snapshot, permanent 4xx) or
		// was skipped (--wait-for-scan=false). Either way, claiming
		// "なし ✅" would silently misrepresent an unknown state and
		// directly contradict the warning printed alongside this box.
		return "スキャン未完了 ⚠️ (詳細は警告参照)"
	}

	// Compute total from the buckets we render rather than trusting the
	// server's `total` field. KEV is orthogonal to CVSS severity (a KEV
	// CVE is also counted in its critical/high/etc. bucket) so it is
	// included additively here only as a defensive guard against servers
	// that emit KEV without any CVSS bucket populated.
	if c+h+m+l+u+kev == 0 {
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
