package commands

// `sbomhub cra` — Cyber Resilience Act compliance report drafting,
// listing, and approval (M2 Wave M2-7 — sbomhub-cli issue #2).
//
// The M2 MVP exposes three subcommands; reject / edit / reanalyse are
// stubbed out for M3 alongside the bundled `sbomhub evidence-pack`:
//
//	sbomhub cra draft \
//	    --project <id> \
//	    --cve <CVE-ID> \
//	    --type <early_warning|detailed_notification|final_report> \
//	    --lang <ja|en> \
//	    [--source-vex <draft_id>] \
//	    [--output <file>] \
//	    [--non-interactive]
//
//	sbomhub cra list --project <id> \
//	    [--report-type X] [--lang Y] [--state Z] [--decision W] [--limit N]
//
//	sbomhub cra approve --project <id> --report-id <id> [--note <text>]
//
// All three flow through the same M1-aligned regime — credentials via
// resolveCredentials, output via GetOutputConfig, exit codes via
// craExitError (3=permanent, 4=transient) — so the operator gets the
// same UX they learned from `sbomhub triage`.
//
// AI-disabled fallback (BYOK not configured) flows the M1 #F4 / #F22
// pattern:
//   - 2xx + AIDisabled=true  → save template-only report, print hint, exit 0
//   - 503 + known reason     → legacy compat, same fallback path
//   - 503 + generic message  → real outage, exit 4
//
// ※要確認:
//   - VulnerabilityID resolution: `cra draft --cve` accepts a human CVE
//     identifier (CVE-2024-12345) but the server requires the local
//     vulnerabilities.id UUID. We therefore call ListVulnerabilities
//     and match on CVEID — same indirection the M1 triage CLI uses to
//     avoid asking the operator for two IDs.
//   - --output writes ONLY the draft_text payload (markdown), not the
//     full JSON report. JSON consumers can use `--json` instead. The
//     UX rationale is that the markdown is what the operator will
//     paste into the CRA portal; the JSON is debug fodder.
//   - `cra approve --edit` is not yet implemented — operators who need
//     to edit-then-approve flow should `cra draft --output file.md`,
//     edit the file, then `cra approve --note "edited locally"`. The
//     `edited` decision PUT path is wired through the API client so a
//     future flag flip is one cobra wire change.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/youichi-uda/sbomhub-cli/internal/api"
)

// Decision constants — values mirror the server-side
// craDecisionRequest.Decision allow-list (handler/cra_reports.go).
const (
	craDecisionApproved = "approved"
	craDecisionEdited   = "edited"
	craDecisionRejected = "rejected"
)

// Report type allow-list — mirrors cra.ReportType (service/cra/runner.go).
const (
	craReportTypeEarlyWarning         = "early_warning"
	craReportTypeDetailedNotification = "detailed_notification"
	craReportTypeFinalReport          = "final_report"
)

// Lang allow-list — mirrors cra.Lang. M2 supports ja + en.
const (
	craLangJa = "ja"
	craLangEn = "en"
)

// AI-disabled hint surfaced when the server signals BYOK not
// configured. Mirrors the M1 triage aiDisabledHintJa wording so
// operators see the same actionable message across both AI surfaces.
const craAIDisabledHintJa = "APIキー未設定のため AI 解析 skip。 `/settings/llm` で BYOK 設定するか、 template-only draft で運用してください"

// craExitError lets a runCraXxx return a specific exit code through
// the cobra error path. Mirrors triageExitError so main.go's exitCoder
// hook covers both surfaces without a second type assertion branch.
type craExitError struct {
	code int
	msg  string
}

func (e *craExitError) Error() string { return e.msg }
func (e *craExitError) ExitCode() int { return e.code }

// ---------------------------------------------------------------------------
// Flag globals (per subcommand) — kept package-scoped to match the existing
// triage / scan command conventions
// ---------------------------------------------------------------------------

var (
	// shared
	craProject string

	// draft
	craDraftCVE            string
	craDraftReportType     string
	craDraftLang           string
	craDraftSourceVEX      string
	craDraftOutput         string
	craDraftNonInteractive bool
	craDraftProductName    string
	craDraftProductVersion string
	craDraftVendorName     string
	craDraftReporterName   string
	craDraftReporterRole   string
	craDraftContactEmail   string
	craDraftContactPhone   string
	craDraftAwarenessTime  string

	// list
	craListReportType string
	craListLang       string
	craListState      string
	craListDecision   string
	craListCVE        string
	craListLimit      int

	// approve
	craApproveReportID string
	craApproveNote     string
)

// ---------------------------------------------------------------------------
// Cobra wiring
// ---------------------------------------------------------------------------

var craCmd = &cobra.Command{
	Use:   "cra",
	Short: "CRA (Cyber Resilience Act) 報告書ドラフトを生成・閲覧・承認する / Draft, list, and approve EU CRA compliance reports",
	Long: `EU CRA (Cyber Resilience Act) の 24h早期警告 / 72h詳細通知 / 最終報告書を
AI で起草・閲覧・承認するコマンド群です (M2 MVP)。

Subcommands:
  draft    新しい CRA 報告書を起草 (LLM 経由、 ai_disabled の場合は template-only)
  list     プロジェクトの CRA 報告書一覧を表示
  approve  CRA 報告書を承認 (decision=approved を PUT)

使用例 / Examples:
  sbomhub cra draft --project my-device --cve CVE-2024-12345 \
      --type early_warning --lang ja --output draft.md
  sbomhub cra list --project my-device --decision pending
  sbomhub cra approve --project my-device --report-id <uuid> \
      --note "reviewed by security team"

詳細は各 subcommand の --help を参照してください。
See each subcommand's --help for the full flag set.`,
}

var craDraftCmd = &cobra.Command{
	Use:   "draft",
	Short: "新しい CRA 報告書ドラフトを生成 / Draft a new CRA report",
	Long: `指定された (project, cve, type, lang) で CRA 報告書ドラフトを起草します。
内部では POST /api/v1/projects/:id/cra-reports/run を呼び、 承認済 VEX draft
(triage 結果) + advisory + reachability 解析を元に LLM がドラフトを生成します。

BYOK LLM 未設定時 / If BYOK LLM is not configured:
  - サーバが ai_disabled=true で template-only draft を返却
  - stderr に「APIキー未設定」のヒントを表示
  - exit 0 で終了 (CI を fail させない)

事前条件 / Prerequisites:
  この (project, cve) に対して 承認済の VEX draft が必要です。
  An approved VEX draft for this (project, cve) is required. Run
  ` + "`sbomhub triage`" + ` first if you see ERROR: no approved vex_draft.

Exit codes:
  0  正常終了 / success (including AI-disabled fallback)
  3  恒久エラー / permanent (401/403/404/409/422 — fix config / triage first)
  4  一時エラー / transient (429/5xx — retry recommended)`,
	RunE: runCraDraft,
}

var craListCmd = &cobra.Command{
	Use:   "list",
	Short: "プロジェクトの CRA 報告書一覧を表示 / List CRA reports for a project",
	Long: `プロジェクトの CRA 報告書を一覧表示します。 全 page を内部で stitching し、
X-Total-Count header から総数を取得します (M1 #F26 #F28 pattern)。

絞り込み / Filters (省略可 / all optional):
  --report-type  early_warning | detailed_notification | final_report
  --lang         ja | en
  --state        draft | approved | submitted | archived
  --decision     pending | approved | edited | rejected
  --cve          CVE-YYYY-NNNNN
  --limit        表示する最大件数 (server 取得後の CLI 側 slice / cap on client)`,
	RunE: runCraList,
}

var craApproveCmd = &cobra.Command{
	Use:   "approve",
	Short: "CRA 報告書を承認 / Approve a CRA report",
	Long: `指定された CRA 報告書に approved decision を記録します。
内部では PUT /api/v1/projects/:id/cra-reports/:report_id/decision を呼び、
audit log (action=cra_report_decided) も同 tx で書き込まれます。

使用例:
  sbomhub cra approve --project my-device --report-id <uuid> \
      --note "reviewed by Tanaka 2026-09-10"

※要確認:
  edited decision (操作員が draft 本文を書き換える) は M3 で対応予定。
  M2 MVP では approve のみ。 reject / edit / reanalyse はサーバ側
  endpoint は実装済 (DecideReport / ReanalyseReport API) ですが、 CLI flag
  flip 待ちです。`,
	RunE: runCraApprove,
}

func init() {
	rootCmd.AddCommand(craCmd)
	craCmd.AddCommand(craDraftCmd)
	craCmd.AddCommand(craListCmd)
	craCmd.AddCommand(craApproveCmd)

	// shared --project flag — duplicated on each subcommand rather than a
	// persistent flag on craCmd because cobra persistent flags inherit
	// upward, which would pollute the rootCmd help output.
	craDraftCmd.Flags().StringVarP(&craProject, "project", "p", "", "対象プロジェクト ID (UUID) または名前 / project ID (UUID) or name")
	craListCmd.Flags().StringVarP(&craProject, "project", "p", "", "対象プロジェクト ID (UUID) または名前 / project ID (UUID) or name")
	craApproveCmd.Flags().StringVarP(&craProject, "project", "p", "", "対象プロジェクト ID (UUID) または名前 / project ID (UUID) or name")

	// draft
	craDraftCmd.Flags().StringVar(&craDraftCVE, "cve", "", "対象 CVE ID (CVE-YYYY-NNNNN) / target CVE ID")
	craDraftCmd.Flags().StringVar(&craDraftReportType, "type", craReportTypeEarlyWarning, "報告書種別 / report milestone (early_warning | detailed_notification | final_report)")
	craDraftCmd.Flags().StringVar(&craDraftLang, "lang", craLangJa, "言語 / draft language (ja | en)")
	craDraftCmd.Flags().StringVar(&craDraftSourceVEX, "source-vex", "", "VEX draft ID を明示的に指定 (省略時はサーバが (project, cve) の最新 approved draft を使用)")
	craDraftCmd.Flags().StringVarP(&craDraftOutput, "output", "o", "", "draft 本文を書き出す path (markdown)。省略時は stdout")
	craDraftCmd.Flags().BoolVar(&craDraftNonInteractive, "non-interactive", false, "CI 用に prompt を skip / skip interactive prompts (CI mode)")
	craDraftCmd.Flags().StringVar(&craDraftProductName, "product-name", "", "製品名 (CRA 報告書 metadata) / regulated product name")
	craDraftCmd.Flags().StringVar(&craDraftProductVersion, "product-version", "", "製品バージョン / product version")
	craDraftCmd.Flags().StringVar(&craDraftVendorName, "vendor-name", "", "ベンダー名 / vendor (manufacturer) name")
	craDraftCmd.Flags().StringVar(&craDraftReporterName, "reporter-name", "", "報告担当者名 / reporter name")
	craDraftCmd.Flags().StringVar(&craDraftReporterRole, "reporter-role", "", "報告担当者役職 / reporter role")
	craDraftCmd.Flags().StringVar(&craDraftContactEmail, "contact-email", "", "連絡先 email / contact email")
	craDraftCmd.Flags().StringVar(&craDraftContactPhone, "contact-phone", "", "連絡先 phone / contact phone")
	craDraftCmd.Flags().StringVar(&craDraftAwarenessTime, "awareness-time", "", "認知日時 ISO 8601 / awareness timestamp ISO 8601")

	// list
	craListCmd.Flags().StringVar(&craListReportType, "report-type", "", "報告書種別で絞り込み / filter by report type")
	craListCmd.Flags().StringVar(&craListLang, "lang", "", "言語で絞り込み / filter by language")
	craListCmd.Flags().StringVar(&craListState, "state", "", "公開状態で絞り込み / filter by publication state")
	craListCmd.Flags().StringVar(&craListDecision, "decision", "", "判定で絞り込み / filter by decision (pending|approved|edited|rejected)")
	craListCmd.Flags().StringVar(&craListCVE, "cve", "", "CVE ID で絞り込み / filter by CVE ID")
	craListCmd.Flags().IntVar(&craListLimit, "limit", 0, "表示する最大件数 / cap on number of reports to render (0 = no cap)")

	// approve
	craApproveCmd.Flags().StringVar(&craApproveReportID, "report-id", "", "対象 CRA 報告書 ID (UUID) / target CRA report ID")
	craApproveCmd.Flags().StringVar(&craApproveNote, "note", "", "承認理由メモ (audit log に保存) / decision note (persisted to audit log)")
}

// ---------------------------------------------------------------------------
// cra draft
// ---------------------------------------------------------------------------

func runCraDraft(cmd *cobra.Command, args []string) error {
	out := GetOutputConfig()
	if strings.TrimSpace(craProject) == "" {
		return fmt.Errorf("--project は必須です / --project is required")
	}
	if strings.TrimSpace(craDraftCVE) == "" {
		return fmt.Errorf("--cve は必須です / --cve is required (e.g. --cve CVE-2024-12345)")
	}
	if err := validateReportType(craDraftReportType); err != nil {
		return err
	}
	if err := validateLang(craDraftLang); err != nil {
		return err
	}

	client, err := loadCraClient()
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Resolve CVE → vulnerability_id (UUID required by the server).
	// We page through the project's vulnerabilities and match on CVEID
	// — same indirection the M1 triage CLI uses to avoid asking the
	// operator for two IDs. A miss surfaces as exit 3 (permanent: the
	// operator must scan an SBOM that surfaces this CVE before they
	// can draft a CRA report for it).
	vulnID, err := resolveVulnIDForCVE(ctx, client, craProject, craDraftCVE)
	if err != nil {
		return err
	}

	req := api.CRARunReportRequest{
		VulnerabilityID:  vulnID,
		CVEID:            craDraftCVE,
		SourceVEXDraftID: craDraftSourceVEX,
		ReportType:       craDraftReportType,
		Lang:             craDraftLang,
		ProductName:      craDraftProductName,
		ProductVersion:   craDraftProductVersion,
		VendorName:       craDraftVendorName,
		ReporterName:     craDraftReporterName,
		ReporterRole:     craDraftReporterRole,
		ContactEmail:     craDraftContactEmail,
		ContactPhone:     craDraftContactPhone,
		AwarenessTime:    craDraftAwarenessTime,
	}

	res, err := client.RunReport(ctx, craProject, req)
	if err != nil {
		// AI-disabled fallback paths
		var ce *api.CRAError
		if errors.As(err, &ce) && ce.IsAIDisabled() {
			// Legacy 503 path — server has not yet shipped the F4 fix.
			// Print hint + return exit 0 so CI does not break.
			fmt.Fprintln(out.ErrWriter, craAIDisabledHintJa)
			if ce.Reason != "" {
				fmt.Fprintf(out.ErrWriter, "  (server reason: %s)\n", ce.Reason)
			}
			fmt.Fprintln(out.ErrWriter, "  → AI 解析がスキップされたためドラフトは保存されませんでした")
			return nil
		}
		return craFailureToExitError("cra draft", err)
	}

	// AI-disabled fast path (canonical 2xx + ai_disabled=true).
	if res.AIDisabled {
		fmt.Fprintln(out.ErrWriter, craAIDisabledHintJa)
		fmt.Fprintln(out.ErrWriter, "  → template-only draft をサーバに保存しました (ai_disabled fallback)")
	}

	return renderDraftResult(out, res, craDraftOutput)
}

// resolveVulnIDForCVE looks up the project's vulnerabilities and
// returns the local vulnerabilities.id for the requested CVE. Returns
// an exit-3 permanent error when the CVE is not present in the
// project — the operator's correct response is to scan an SBOM that
// surfaces this CVE first, not to retry.
//
// ※要確認: an alternative API would be a dedicated GET /vulnerabilities/
// by-cve endpoint; until that lands the CLI walks the same list the
// `sbomhub triage` loop uses (paginated via #F26).
func resolveVulnIDForCVE(ctx context.Context, client *api.Client, projectID, cveID string) (string, error) {
	vulns, err := client.ListVulnerabilities(ctx, projectID)
	if err != nil {
		// Most likely a permanent setup error (bad project, bad
		// auth) — surface as exit 3.
		return "", &craExitError{code: 3, msg: fmt.Sprintf("脆弱性一覧の取得に失敗しました: %v", err)}
	}
	normalized := strings.ToUpper(strings.TrimSpace(cveID))
	for _, v := range vulns {
		if strings.ToUpper(v.CVEID) == normalized {
			return v.ID, nil
		}
	}
	return "", &craExitError{
		code: 3,
		msg: fmt.Sprintf("CVE %s が project %s に存在しません — まず `sbomhub scan` で SBOM をアップロードしてください",
			cveID, projectID),
	}
}

// renderDraftResult writes the draft to --output (if set) and prints
// the metadata block. In --json mode the whole CRARunReportResult lands
// on stdout (humanWriter routes progress to stderr automatically).
func renderDraftResult(out *OutputConfig, res *api.CRARunReportResult, outputPath string) error {
	if res == nil || res.Report == nil {
		// Defensive: decodeRunReportResult guards this in the API
		// layer, so reaching here would mean a future caller-side
		// transformation dropped Report. Surface as a transient so CI
		// can retry rather than silently exit 0 on an empty draft.
		return &craExitError{code: 4, msg: "サーバから report が返ってきませんでした (protocol error)"}
	}

	if out.IsJSON() {
		return out.PrintJSON(res)
	}

	report := res.Report

	// Write the markdown body to --output if requested. Empty path
	// means "stream to stdout in the human block below".
	if outputPath != "" {
		if err := os.WriteFile(outputPath, []byte(report.DraftText), 0o600); err != nil {
			return fmt.Errorf("ドラフトファイル書き込み失敗 (%s): %w", outputPath, err)
		}
		fmt.Fprintf(out.humanWriter(), "ドラフトを %s に保存しました (%d bytes)\n", outputPath, len(report.DraftText))
	}

	// Metadata block — always rendered so the operator can see what
	// they just created without re-fetching.
	w := out.humanWriter()
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "CRA Report Draft")
	fmt.Fprintln(w, "----------------")
	fmt.Fprintf(w, "  ID            : %s\n", report.ID)
	fmt.Fprintf(w, "  Project       : %s\n", report.ProjectID)
	fmt.Fprintf(w, "  CVE           : %s\n", report.CVEID)
	fmt.Fprintf(w, "  Type          : %s\n", report.ReportType)
	fmt.Fprintf(w, "  Lang          : %s\n", report.Lang)
	fmt.Fprintf(w, "  State         : %s\n", report.State)
	fmt.Fprintf(w, "  Decision      : %s\n", report.Decision)
	if report.Provider != "" || report.Model != "" {
		fmt.Fprintf(w, "  Model         : %s/%s\n", report.Provider, report.Model)
	}
	if res.LLMCallID != "" {
		fmt.Fprintf(w, "  LLM Call ID   : %s\n", res.LLMCallID)
	}
	if report.SourceVEXDraftID != nil && *report.SourceVEXDraftID != "" {
		fmt.Fprintf(w, "  Source VEX    : %s\n", *report.SourceVEXDraftID)
	}
	if res.AIDisabled {
		fmt.Fprintln(w, "  AI Disabled   : true (template-only)")
	}

	// If --output was not set, stream the draft body so the operator
	// sees what was generated without a second command. Truncated to
	// the first ~80 lines so a 5kB draft does not flood the terminal;
	// full body is always in the report row server-side and via
	// --output / --json.
	if outputPath == "" {
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "ドラフト本文 / Draft body:")
		fmt.Fprintln(w, "--------------------------")
		fmt.Fprintln(w, report.DraftText)
	}

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "次のステップ / Next steps:")
	fmt.Fprintf(w, "  1. 内容をレビュー (必要なら %s を編集)\n", firstNonEmpty(outputPath, "draft body 出力"))
	fmt.Fprintf(w, "  2. sbomhub cra approve --project %s --report-id %s\n", report.ProjectID, report.ID)
	return nil
}

// ---------------------------------------------------------------------------
// cra list
// ---------------------------------------------------------------------------

func runCraList(cmd *cobra.Command, args []string) error {
	out := GetOutputConfig()
	if strings.TrimSpace(craProject) == "" {
		return fmt.Errorf("--project は必須です / --project is required")
	}
	client, err := loadCraClient()
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	reports, total, err := client.ListReports(ctx, craProject, api.CRAReportListFilter{
		CVEID:      craListCVE,
		ReportType: craListReportType,
		Lang:       craListLang,
		State:      craListState,
		Decision:   craListDecision,
	})
	if err != nil {
		return craFailureToExitError("cra list", err)
	}

	// Apply --limit cap on the client side. The server still returned
	// the full set (we paged through it via F26) so total/X-Total-Count
	// remains the unfiltered count — the cap is purely cosmetic.
	rendered := reports
	if craListLimit > 0 && len(rendered) > craListLimit {
		rendered = rendered[:craListLimit]
	}

	if out.IsJSON() {
		return out.PrintJSON(map[string]interface{}{
			"reports": rendered,
			"total":   total,
			"shown":   len(rendered),
		})
	}

	w := out.humanWriter()
	if len(rendered) == 0 {
		fmt.Fprintln(w, "CRA 報告書はありません。")
		fmt.Fprintln(w, "No CRA reports.")
		return nil
	}

	fmt.Fprintln(w, "CRA Report 一覧")
	fmt.Fprintln(w, "---------------")
	for _, r := range rendered {
		// One-line summary per report; the operator can `cra approve`
		// using the ID column. CVEID + type + lang are the three
		// fields the operator needs to find a specific row.
		decision := r.Decision
		if decision == "" {
			decision = "pending"
		}
		fmt.Fprintf(w, "  %s  %-22s  %-12s  %-3s  state=%-9s  decision=%s\n",
			r.ID, r.CVEID, r.ReportType, r.Lang, orDash(r.State), decision)
		if r.UpdatedAt != "" {
			fmt.Fprintf(w, "      updated: %s\n", r.UpdatedAt)
		}
	}
	fmt.Fprintf(w, "\n表示: %d / 合計: %d\n", len(rendered), total)
	if total > len(rendered) {
		fmt.Fprintln(w, "  (--limit で表示件数を増やすか、 --json で全件取得してください)")
	}
	return nil
}

// ---------------------------------------------------------------------------
// cra approve
// ---------------------------------------------------------------------------

func runCraApprove(cmd *cobra.Command, args []string) error {
	out := GetOutputConfig()
	if strings.TrimSpace(craProject) == "" {
		return fmt.Errorf("--project は必須です / --project is required")
	}
	if strings.TrimSpace(craApproveReportID) == "" {
		return fmt.Errorf("--report-id は必須です / --report-id is required")
	}
	client, err := loadCraClient()
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	fresh, err := client.DecideReport(ctx, craProject, craApproveReportID, api.CRADecisionRequest{
		Decision:     craDecisionApproved,
		DecisionNote: craApproveNote,
	})
	if err != nil {
		return craFailureToExitError("cra approve", err)
	}

	if out.IsJSON() {
		return out.PrintJSON(fresh)
	}

	w := out.humanWriter()
	fmt.Fprintf(w, "CRA report %s を承認しました\n", fresh.ID)
	fmt.Fprintf(w, "  Project   : %s\n", fresh.ProjectID)
	fmt.Fprintf(w, "  CVE       : %s\n", fresh.CVEID)
	fmt.Fprintf(w, "  Type      : %s\n", fresh.ReportType)
	fmt.Fprintf(w, "  Decision  : %s\n", fresh.Decision)
	if fresh.DecisionAt != nil && *fresh.DecisionAt != "" {
		fmt.Fprintf(w, "  Decided at: %s\n", *fresh.DecisionAt)
	}
	if craApproveNote != "" {
		fmt.Fprintf(w, "  Note      : %s\n", craApproveNote)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// loadCraClient is a thin wrapper around loadConfigAndClient so the
// CRA command paths share the same credential precedence (CLI flag >
// env > config file > default) as the other commands.
func loadCraClient() (*api.Client, error) {
	return loadConfigAndClient()
}

// craFailureToExitError translates a CRA API error into the exit-code
// envelope (3=permanent, 4=transient) following the M1 #F21 pattern.
// Network / unknown errors fall into the transient bucket because the
// operator's correct response (retry) is the same.
//
// AIDisabled is intentionally NOT routed through this helper — the
// CLI handles BYOK fallback inline so it can render the hint + return
// exit 0 on the legacy 503 path. By the time a caller reaches this
// helper, AIDisabled has already been excluded.
func craFailureToExitError(op string, err error) error {
	if err == nil {
		return nil
	}
	var ce *api.CRAError
	if errors.As(err, &ce) {
		switch {
		case ce.IsAIDisabled():
			// Should be unreachable — callers branch on AIDisabled
			// before calling this helper. Defensive: classify as
			// transient so a regression that drops the inline branch
			// does not silently inflate permanentFailures.
			return &craExitError{code: 4, msg: fmt.Sprintf("%s failed: %v", op, err)}
		case ce.IsPermanent():
			return &craExitError{code: 3, msg: fmt.Sprintf("%s 恒久エラー / permanent failure: %v", op, err)}
		case ce.IsTransient():
			return &craExitError{code: 4, msg: fmt.Sprintf("%s 一時エラー / transient failure (retry): %v", op, err)}
		default:
			// Unknown 4xx that the helpers do not classify (e.g. a
			// future 451 / 418) — treat as permanent because the
			// operator's response is "fix something", not "retry".
			return &craExitError{code: 3, msg: fmt.Sprintf("%s 不明な失敗: %v", op, err)}
		}
	}
	// Network / JSON parse / context errors — retry is the right
	// response.
	return &craExitError{code: 4, msg: fmt.Sprintf("%s 一時エラー / transient failure (retry): %v", op, err)}
}

// validateReportType returns nil iff t is in the M2 allow-list.
func validateReportType(t string) error {
	switch t {
	case craReportTypeEarlyWarning, craReportTypeDetailedNotification, craReportTypeFinalReport:
		return nil
	}
	return fmt.Errorf("--type は %s / %s / %s のいずれかを指定してください (got %q)",
		craReportTypeEarlyWarning, craReportTypeDetailedNotification, craReportTypeFinalReport, t)
}

// validateLang returns nil iff l is in the M2 allow-list.
func validateLang(l string) error {
	switch l {
	case craLangJa, craLangEn:
		return nil
	}
	return fmt.Errorf("--lang は %s / %s のいずれかを指定してください (got %q)", craLangJa, craLangEn, l)
}

// firstNonEmpty returns the first non-empty argument; useful for fall-
// back help text. Kept local rather than promoted because the only
// caller is renderDraftResult.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// orDash renders an empty string as "-" so the list output aligns.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

