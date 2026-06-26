package commands

// `sbomhub meti` — METI 手引 ver 2.0 self-assessment listing, refresh,
// per-criterion override, and override clear (M3 Wave M3-7 +
// M3 Codex review #F36 — sbomhub-cli issue #3).
//
// The M3 MVP exposes four subcommands:
//
//	sbomhub meti list --project <id> \
//	    [--phase env_setup|sbom_creation|sbom_operation] \
//	    [--status achieved|not_achieved|needs_review|not_applicable] \
//	    [--has-override] [--limit N]
//
//	sbomhub meti refresh --project <id>
//
//	sbomhub meti override --project <id> --criterion <criterion_id> \
//	    --status <status> [--note <text>] [--improvement-action <text>]
//
//	sbomhub meti clear-override --project <id> --criterion <criterion_id> \
//	    --note <text>
//
// All four flow through the same M1/M2-aligned regime — credentials
// via resolveCredentials, output via GetOutputConfig, exit codes via
// metiExitError (3=permanent, 4=transient) — so the operator gets the
// same UX they learned from `sbomhub triage` / `sbomhub cra`.
//
// AI-disabled fallback is NOT applicable to METI: the evaluator is
// fully local (criteria/*.go is a 27-item rule fan-out, no LLM
// upstream). The issue body's "AI-disabled banner is hint from
// server" wording refers to the read-only banner the Web UI surfaces
// when LLM features are off elsewhere in the product — the METI CLI
// does not surface it because the operator's CLI flow has no AI
// component to disable.
//
// ※要確認:
//   - --has-override is a tri-state boolean: bare flag = "filter to
//     overridden only" (true). Unset = no filter. There is no current
//     way to ask "non-overridden only" through the CLI; the API
//     supports it (HasOverride=*false) but the operator-facing UX has
//     not requested that filter yet.
//   - --improvement-action passes through to MetiOverrideRequest.
//     ImprovementAction (pointer); the CLI sends nil when the flag is
//     not provided to preserve the server's "do not change" semantics.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/youichi-uda/sbomhub-cli/internal/api"
)

// Phase allow-list — mirrors handler.isValidPhase / migration 039
// CHECK constraint on criterion_phase.
const (
	metiPhaseEnvSetup       = "env_setup"
	metiPhaseSBOMCreation   = "sbom_creation"
	metiPhaseSBOMOperation  = "sbom_operation"
)

// Status allow-list — mirrors criteria.Status* constants /
// handler.isValidStatus.
const (
	metiStatusAchieved      = "achieved"
	metiStatusNotAchieved   = "not_achieved"
	metiStatusNeedsReview   = "needs_review"
	metiStatusNotApplicable = "not_applicable"
)

// metiExitError lets a runMetiXxx return a specific exit code through
// the cobra error path. Mirrors craExitError / triageExitError so
// main.go's exitCoder hook covers all three surfaces without a
// branching type assertion.
type metiExitError struct {
	code int
	msg  string
}

func (e *metiExitError) Error() string { return e.msg }
func (e *metiExitError) ExitCode() int { return e.code }

// ---------------------------------------------------------------------------
// Flag globals (per subcommand) — kept package-scoped to match the
// existing triage / cra command conventions
// ---------------------------------------------------------------------------

var (
	// shared
	metiProject string

	// list
	metiListPhase       string
	metiListStatus      string
	metiListHasOverride bool
	metiListLimit       int

	// override
	metiOverrideCriterion        string
	metiOverrideStatus           string
	metiOverrideNote             string
	metiOverrideImprovementAct   string
	metiOverrideImprovementSet   bool // true when --improvement-action was passed on the CLI

	// clear-override (M3 Codex review #F36)
	metiClearOverrideCriterion string
	metiClearOverrideNote      string
)

// ---------------------------------------------------------------------------
// Cobra wiring
// ---------------------------------------------------------------------------

var metiCmd = &cobra.Command{
	Use:   "meti",
	Short: "METI 手引 ver 2.0 自己評価を一覧・再評価・上書きする / Inspect, refresh, and override the METI self-assessment matrix",
	Long: `経済産業省「ソフトウェア管理に向けたSBOM活用の手引 ver 2.0」の
27項目自己評価マトリクスをサーバから取得し、 evaluator による再評価や
担当者上書きを行うコマンド群です (M3 MVP)。

Subcommands:
  list            プロジェクトの自己評価行を一覧 (phase / status / 上書き有無で絞り込み)
  refresh         evaluator を再実行して全 27 項目を Upsert (上書きは保持)
  override        指定 criterion に担当者上書きを適用 (audit log に記録)
  clear-override  指定 criterion の担当者上書きを取り消し (audit log に記録)

使用例 / Examples:
  sbomhub meti list --project my-device
  sbomhub meti list --project my-device --phase sbom_creation --status not_achieved
  sbomhub meti list --project my-device --has-override
  sbomhub meti refresh --project my-device
  sbomhub meti override --project my-device \
      --criterion env_setup.policy_documented --status achieved \
      --note "verified by Tanaka 2026-09-10"
  sbomhub meti clear-override --project my-device \
      --criterion env_setup.policy_documented \
      --note "re-evaluated 2026-09-12: original override was a mis-read"

詳細は各 subcommand の --help を参照してください。
See each subcommand's --help for the full flag set.`,
}

var metiListCmd = &cobra.Command{
	Use:   "list",
	Short: "METI 自己評価行を一覧表示 / List METI assessment rows for a project",
	Long: `プロジェクトの METI 自己評価行を一覧表示します。 全 page を内部で
stitching し、 X-Total-Count header から総数を取得します (M1 #F26 #F28
pattern)。 catalog は 27 項目しかないため通常 1 page で完結しますが、
ページング契約は他の list 系コマンドと同じ実装になっています。

絞り込み / Filters (省略可 / all optional):
  --phase         env_setup | sbom_creation | sbom_operation
  --status        achieved | not_achieved | needs_review | not_applicable
  --has-override  担当者上書きが適用された行のみ表示 / show only operator-overridden rows
  --limit         表示する最大件数 (server 取得後の CLI 側 slice / cap on client)

Exit codes:
  0  正常終了 / success
  3  恒久エラー / permanent (401/403/404 — fix config)
  4  一時エラー / transient (429/5xx — retry recommended)`,
	RunE: runMetiList,
}

var metiRefreshCmd = &cobra.Command{
	Use:   "refresh",
	Short: "evaluator を再実行して全項目を再評価 / Re-run the evaluator over the project",
	Long: `内部では POST /api/v1/projects/:id/meti/assessment/refresh を呼び、
catalog の 27 criterion を evaluator が一括再評価して Upsert します。
担当者上書き (override_*) は保持され、 evaluator-owned 列のみが
更新されます。

書込権限 (write role) が必要です — 403 が返った場合は API key の
権限を確認してください。

Exit codes:
  0  正常終了 / success
  3  恒久エラー / permanent (401/403/404 — fix config)
  4  一時エラー / transient (429/5xx — retry recommended)`,
	RunE: runMetiRefresh,
}

var metiOverrideCmd = &cobra.Command{
	Use:   "override",
	Short: "担当者上書きを適用 / Apply an operator override to one criterion",
	Long: `指定された criterion に担当者上書きを記録します。
内部では PUT /api/v1/projects/:id/meti/assessment/:criterion_id/override を呼び、
audit log (action=meti_assessment_overridden) も同 tx で書き込まれます。

書込権限 (write role) が必要です。 既に上書き済の行に対しては
409 (state-machine guard) で reject されます — 上書きを差し替えたい
場合は先に ` + "`sbomhub meti clear-override`" + ` で既存の上書きを取り消してください。

使用例:
  sbomhub meti override --project my-device \
      --criterion env_setup.policy_documented \
      --status achieved \
      --note "verified by Tanaka 2026-09-10"

Exit codes:
  0  正常終了 / success
  3  恒久エラー / permanent (401/403/404/409 — fix input or clear existing override)
  4  一時エラー / transient (429/5xx — retry recommended)`,
	RunE: runMetiOverride,
}

var metiClearOverrideCmd = &cobra.Command{
	Use:   "clear-override",
	Short: "担当者上書きを取り消す / Clear an operator override on one criterion",
	Long: `指定された criterion に既に適用済の担当者上書きを取り消します
(M3 Codex review #F36 — 誤った上書きを修正するための公式 CLI 経路)。
内部では DELETE /api/v1/projects/:id/meti/assessment/:criterion_id/override
を呼び、 audit log (action=meti_assessment_override_cleared) も同 tx で
書き込まれます。 取り消し理由メモ (--note) は 1-4096 文字必須で、
監査トレースのため audit_logs.details に保存されます (F33/F34)。

取り消し後は evaluator の verdict が再び有効になり、 必要であれば
` + "`sbomhub meti override`" + ` で新しい上書きを適用できます。

書込権限 (write role) と user identity (audit row tying) が必要です。
上書きが存在しない (or 行自体が存在しない) 場合は 404 を返します。

使用例:
  sbomhub meti clear-override --project my-device \
      --criterion env_setup.policy_documented \
      --note "re-evaluated 2026-09-12: original override was a mis-read"

Exit codes:
  0  正常終了 / success
  3  恒久エラー / permanent (400/401/403/404/409 — fix input, nothing to clear,
     or TOCTOU race: reload state with ` + "`meti list`" + ` and re-decide)
  4  一時エラー / transient (429/5xx — retry recommended)`,
	RunE: runMetiClearOverride,
}

func init() {
	rootCmd.AddCommand(metiCmd)
	metiCmd.AddCommand(metiListCmd)
	metiCmd.AddCommand(metiRefreshCmd)
	metiCmd.AddCommand(metiOverrideCmd)
	metiCmd.AddCommand(metiClearOverrideCmd)

	// shared --project flag — duplicated on each subcommand rather than
	// a persistent flag on metiCmd because cobra persistent flags
	// inherit upward, which would pollute the rootCmd help output.
	metiListCmd.Flags().StringVarP(&metiProject, "project", "p", "", "対象プロジェクト ID (UUID) / project ID (UUID)")
	metiRefreshCmd.Flags().StringVarP(&metiProject, "project", "p", "", "対象プロジェクト ID (UUID) / project ID (UUID)")
	metiOverrideCmd.Flags().StringVarP(&metiProject, "project", "p", "", "対象プロジェクト ID (UUID) / project ID (UUID)")
	metiClearOverrideCmd.Flags().StringVarP(&metiProject, "project", "p", "", "対象プロジェクト ID (UUID) / project ID (UUID)")

	// list
	metiListCmd.Flags().StringVar(&metiListPhase, "phase", "", "phase で絞り込み / filter by phase (env_setup|sbom_creation|sbom_operation)")
	metiListCmd.Flags().StringVar(&metiListStatus, "status", "", "evaluator status で絞り込み / filter by evaluator status (achieved|not_achieved|needs_review|not_applicable)")
	metiListCmd.Flags().BoolVar(&metiListHasOverride, "has-override", false, "担当者上書きが適用された行のみ表示 / show only operator-overridden rows")
	metiListCmd.Flags().IntVar(&metiListLimit, "limit", 0, "表示する最大件数 / cap on number of rows to render (0 = no cap)")

	// override
	metiOverrideCmd.Flags().StringVar(&metiOverrideCriterion, "criterion", "", "対象 criterion ID (catalog 由来) / criterion id from the catalog")
	metiOverrideCmd.Flags().StringVar(&metiOverrideStatus, "status", "", "上書き後 status / override status (achieved|not_achieved|needs_review|not_applicable)")
	metiOverrideCmd.Flags().StringVar(&metiOverrideNote, "note", "", "上書き理由メモ (audit log に保存) / override note (persisted to audit log)")
	metiOverrideCmd.Flags().StringVar(&metiOverrideImprovementAct, "improvement-action", "", "改善アクション (省略時は変更しない) / improvement action plan (omit to preserve existing)")

	// clear-override
	metiClearOverrideCmd.Flags().StringVar(&metiClearOverrideCriterion, "criterion", "", "対象 criterion ID (catalog 由来) / criterion id from the catalog")
	metiClearOverrideCmd.Flags().StringVar(&metiClearOverrideNote, "note", "", "取り消し理由メモ (1-4096 文字必須, audit log に保存) / clear note (1-4096 chars, persisted to audit log)")
}

// ---------------------------------------------------------------------------
// meti list
// ---------------------------------------------------------------------------

func runMetiList(cmd *cobra.Command, args []string) error {
	out := GetOutputConfig()
	if strings.TrimSpace(metiProject) == "" {
		return fmt.Errorf("--project は必須です / --project is required")
	}
	if metiListPhase != "" {
		if err := validateMetiPhase(metiListPhase); err != nil {
			return err
		}
	}
	if metiListStatus != "" {
		if err := validateMetiStatus(metiListStatus); err != nil {
			return err
		}
	}
	client, err := loadConfigAndClient()
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	filter := api.MetiAssessmentListFilter{
		Phase:  metiListPhase,
		Status: metiListStatus,
	}
	if cmd.Flags().Changed("has-override") {
		// Pass through the explicit flag value: bare --has-override
		// sets it to true (filter to overridden only); --has-override=false
		// asks for non-overridden only.
		v := metiListHasOverride
		filter.HasOverride = &v
	}

	rows, total, err := client.GetAssessment(ctx, metiProject, filter)
	if err != nil {
		return metiFailureToExitError("meti list", err)
	}

	// Apply --limit cap on the client side. The server still returned
	// the full filtered set (we paged through it via F26) so total
	// remains the unfiltered count — the cap is purely cosmetic.
	rendered := rows
	if metiListLimit > 0 && len(rendered) > metiListLimit {
		rendered = rendered[:metiListLimit]
	}

	if out.IsJSON() {
		return out.PrintJSON(map[string]interface{}{
			"assessments": rendered,
			"total":       total,
			"shown":       len(rendered),
		})
	}

	w := out.humanWriter()
	if len(rendered) == 0 {
		fmt.Fprintln(w, "METI 自己評価行はありません。")
		fmt.Fprintln(w, "No METI assessment rows.")
		fmt.Fprintln(w, "  → `sbomhub meti refresh --project <id>` で evaluator を実行してください")
		return nil
	}

	fmt.Fprintln(w, "METI 自己評価 一覧")
	fmt.Fprintln(w, "-------------------")
	for _, r := range rendered {
		// One-line per criterion; the operator can `meti override`
		// using the criterion_id column. effective status is shown so
		// the operator sees the post-override truth at a glance.
		effective := r.Status
		overrideMark := ""
		if r.OverrideStatus != "" {
			effective = r.OverrideStatus
			overrideMark = " (override)"
		}
		fmt.Fprintf(w, "  %-32s  phase=%-14s  status=%-14s  effective=%s%s\n",
			r.CriterionID, orDash(r.CriterionPhase), orDash(r.Status), effective, overrideMark)
		if r.OverrideNote != "" {
			fmt.Fprintf(w, "      override note: %s\n", r.OverrideNote)
		}
		if r.ImprovementAction != "" {
			fmt.Fprintf(w, "      improvement   : %s\n", r.ImprovementAction)
		}
	}
	fmt.Fprintf(w, "\n表示: %d / 合計: %d\n", len(rendered), total)
	if total > len(rendered) {
		fmt.Fprintln(w, "  (--limit で表示件数を増やすか、 --json で全件取得してください)")
	}
	return nil
}

// ---------------------------------------------------------------------------
// meti refresh
// ---------------------------------------------------------------------------

func runMetiRefresh(cmd *cobra.Command, args []string) error {
	out := GetOutputConfig()
	if strings.TrimSpace(metiProject) == "" {
		return fmt.Errorf("--project は必須です / --project is required")
	}
	client, err := loadConfigAndClient()
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	res, err := client.RefreshAssessment(ctx, metiProject)
	if err != nil {
		return metiFailureToExitError("meti refresh", err)
	}

	if out.IsJSON() {
		return out.PrintJSON(res)
	}

	w := out.humanWriter()
	fmt.Fprintf(w, "METI evaluator を再実行しました\n")
	fmt.Fprintf(w, "  Project           : %s\n", metiProject)
	fmt.Fprintf(w, "  Refreshed         : %d criterion\n", res.Refreshed)
	if res.EvaluatorVersion != "" {
		fmt.Fprintf(w, "  Evaluator version : %s\n", res.EvaluatorVersion)
	}

	// Quick effective-status histogram so the operator gets a one-glance
	// signal without a follow-up `meti list`. Phase-bucketed counts
	// would be more informative but the 27-entry catalog renders fine
	// inline.
	counts := map[string]int{}
	for _, a := range res.Assessments {
		s := a.Status
		if a.OverrideStatus != "" {
			s = a.OverrideStatus
		}
		counts[s]++
	}
	if len(counts) > 0 {
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "effective status 内訳 / Effective status histogram:")
		for _, s := range []string{metiStatusAchieved, metiStatusNotAchieved, metiStatusNeedsReview, metiStatusNotApplicable} {
			if c, ok := counts[s]; ok {
				fmt.Fprintf(w, "  %-18s : %d\n", s, c)
			}
		}
	}

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "次のステップ / Next steps:")
	fmt.Fprintf(w, "  - sbomhub meti list --project %s --status not_achieved  # 残課題を確認\n", metiProject)
	fmt.Fprintf(w, "  - sbomhub meti override --project %s --criterion <id> --status <status> --note <text>\n", metiProject)
	return nil
}

// ---------------------------------------------------------------------------
// meti override
// ---------------------------------------------------------------------------

func runMetiOverride(cmd *cobra.Command, args []string) error {
	out := GetOutputConfig()
	if strings.TrimSpace(metiProject) == "" {
		return fmt.Errorf("--project は必須です / --project is required")
	}
	if strings.TrimSpace(metiOverrideCriterion) == "" {
		return fmt.Errorf("--criterion は必須です / --criterion is required")
	}
	if strings.TrimSpace(metiOverrideStatus) == "" {
		return fmt.Errorf("--status は必須です / --status is required")
	}
	if err := validateMetiStatus(metiOverrideStatus); err != nil {
		return err
	}
	client, err := loadConfigAndClient()
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	req := api.MetiOverrideRequest{
		OverrideStatus: metiOverrideStatus,
		OverrideNote:   metiOverrideNote,
	}
	if cmd.Flags().Changed("improvement-action") {
		// Pointer semantics: a present-but-empty value asks the server
		// to clear improvement_action; omitting the flag preserves
		// whatever the server already has (mirrors CRA
		// EditedDraftText).
		v := metiOverrideImprovementAct
		req.ImprovementAction = &v
	}

	fresh, err := client.OverrideCriterion(ctx, metiProject, metiOverrideCriterion, req)
	if err != nil {
		return metiFailureToExitError("meti override", err)
	}

	if out.IsJSON() {
		return out.PrintJSON(fresh)
	}

	w := out.humanWriter()
	fmt.Fprintf(w, "METI criterion %s に上書きを適用しました\n", fresh.CriterionID)
	fmt.Fprintf(w, "  Project           : %s\n", fresh.ProjectID)
	fmt.Fprintf(w, "  Phase             : %s\n", orDash(fresh.CriterionPhase))
	fmt.Fprintf(w, "  Evaluator status  : %s\n", orDash(fresh.Status))
	fmt.Fprintf(w, "  Override status   : %s\n", orDash(fresh.OverrideStatus))
	if fresh.OverrideAt != nil && *fresh.OverrideAt != "" {
		fmt.Fprintf(w, "  Overridden at     : %s\n", *fresh.OverrideAt)
	}
	if metiOverrideNote != "" {
		fmt.Fprintf(w, "  Note              : %s\n", metiOverrideNote)
	}
	if fresh.ImprovementAction != "" {
		fmt.Fprintf(w, "  Improvement       : %s\n", fresh.ImprovementAction)
	}
	return nil
}

// ---------------------------------------------------------------------------
// meti clear-override (M3 Codex review #F36)
// ---------------------------------------------------------------------------

// metiClearOverrideNoteMaxLen mirrors the server-side cap in
// validateMetiOverrideNote (handler/meti.go: MaxMetiOverrideNoteLen).
// Early validation in the CLI surfaces a friendlier error than a 400
// round-trip and matches the F34 contract.
const metiClearOverrideNoteMaxLen = 4096

func runMetiClearOverride(cmd *cobra.Command, args []string) error {
	out := GetOutputConfig()
	if strings.TrimSpace(metiProject) == "" {
		return fmt.Errorf("--project は必須です / --project is required")
	}
	if strings.TrimSpace(metiClearOverrideCriterion) == "" {
		return fmt.Errorf("--criterion は必須です / --criterion is required")
	}
	cleanedNote := strings.TrimSpace(metiClearOverrideNote)
	if cleanedNote == "" {
		return fmt.Errorf("--note は必須です / --note is required (operator's rationale, persisted to audit log)")
	}
	if len(cleanedNote) > metiClearOverrideNoteMaxLen {
		return fmt.Errorf("--note は %d 文字以内で指定してください (got %d) / --note must be at most %d characters (got %d)",
			metiClearOverrideNoteMaxLen, len(cleanedNote), metiClearOverrideNoteMaxLen, len(cleanedNote))
	}
	client, err := loadConfigAndClient()
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	req := api.MetiClearOverrideRequest{Note: cleanedNote}
	if err := client.ClearOverrideCriterion(ctx, metiProject, metiClearOverrideCriterion, req); err != nil {
		return metiFailureToExitError("meti clear-override", err)
	}

	if out.IsJSON() {
		return out.PrintJSON(map[string]interface{}{
			"cleared":      true,
			"project_id":   metiProject,
			"criterion_id": metiClearOverrideCriterion,
			"note":         cleanedNote,
		})
	}

	w := out.humanWriter()
	fmt.Fprintf(w, "METI criterion %s の上書きを取り消しました\n", metiClearOverrideCriterion)
	fmt.Fprintf(w, "  Project           : %s\n", metiProject)
	fmt.Fprintf(w, "  Cleared note      : %s\n", cleanedNote)
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "次のステップ / Next steps:")
	fmt.Fprintf(w, "  - sbomhub meti list --project %s --has-override   # 取り消し結果を確認\n", metiProject)
	fmt.Fprintf(w, "  - sbomhub meti override --project %s --criterion %s --status <status> --note <text>  # 必要なら新しい上書きを適用\n",
		metiProject, metiClearOverrideCriterion)
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// metiFailureToExitError translates a METI API error into the exit-code
// envelope (3=permanent, 4=transient) following the M1 #F21 pattern.
// Network / unknown errors fall into the transient bucket because the
// operator's correct response (retry) is the same.
//
// Unlike craFailureToExitError there is no AI-disabled branch — the
// METI evaluator is fully local.
func metiFailureToExitError(op string, err error) error {
	if err == nil {
		return nil
	}
	var me *api.MetiError
	if errors.As(err, &me) {
		switch {
		case me.IsPermanent():
			return &metiExitError{code: 3, msg: fmt.Sprintf("%s 恒久エラー / permanent failure: %v", op, err)}
		case me.IsTransient():
			return &metiExitError{code: 4, msg: fmt.Sprintf("%s 一時エラー / transient failure (retry): %v", op, err)}
		default:
			// Unknown 4xx that the helpers do not classify (e.g. a
			// future 451 / 418) — treat as permanent because the
			// operator's response is "fix something", not "retry".
			return &metiExitError{code: 3, msg: fmt.Sprintf("%s 不明な失敗: %v", op, err)}
		}
	}
	// Network / JSON parse / context errors — retry is the right
	// response.
	return &metiExitError{code: 4, msg: fmt.Sprintf("%s 一時エラー / transient failure (retry): %v", op, err)}
}

// validateMetiPhase returns nil iff p is in the M3 phase allow-list.
func validateMetiPhase(p string) error {
	switch p {
	case metiPhaseEnvSetup, metiPhaseSBOMCreation, metiPhaseSBOMOperation:
		return nil
	}
	return fmt.Errorf("--phase は %s / %s / %s のいずれかを指定してください (got %q)",
		metiPhaseEnvSetup, metiPhaseSBOMCreation, metiPhaseSBOMOperation, p)
}

// validateMetiStatus returns nil iff s is in the M3 status allow-list.
func validateMetiStatus(s string) error {
	switch s {
	case metiStatusAchieved, metiStatusNotAchieved, metiStatusNeedsReview, metiStatusNotApplicable:
		return nil
	}
	return fmt.Errorf("--status は %s / %s / %s / %s のいずれかを指定してください (got %q)",
		metiStatusAchieved, metiStatusNotAchieved, metiStatusNeedsReview, metiStatusNotApplicable, s)
}
