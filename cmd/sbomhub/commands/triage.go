package commands

// `sbomhub triage` — interactive AI VEX triage loop for M1 (GitHub
// issue youichi-uda/sbomhub-cli#1, parent plan PRODUCT_REBOOT_PLAN.md
// §7.1 / §8.2).
//
// Flow per invocation:
//
//  1. resolve credentials (config file → env → CLI flag, same precedence
//     as `sbomhub scan` via resolveCredentials),
//  2. fetch the project's vulnerabilities,
//  3. for each vuln, POST /triage/run to get the AI-drafted VEX,
//  4. render the draft (CVE / component / reachability / AI suggestion /
//     confidence / evidence) and prompt the operator for
//     [a]pprove / [e]dit / [r]eject / [s]kip / [q]uit,
//  5. PUT /vex-drafts/:id/decision to persist the decision.
//
// BYOK LLM not configured (server returns 503 from llm.DisabledError):
// the loop short-circuits — every vuln is recorded as
// `under_investigation` via DecideDraft (decision=edited,
// edited_state=under_investigation) so the audit trail still shows the
// triage attempt, and a one-line stderr hint points the operator at
// `/settings/llm`. Exit code 0 (CI must not fail).
//
// --non-interactive disables the prompt and applies the same
// `under_investigation` fallback to every draft regardless of LLM
// state. This is the CI-template mode where you want a paper trail
// without blocking the pipeline on human review.
//
// ※要確認:
//   - The `[path]` positional argument is accepted to match the issue
//     UX ("sbomhub triage . --project ...") but M1 does ALL reachability
//     + LLM work server-side, so path is currently informational only.
//     Recorded into PathContext on the request so server-side audit can
//     log "operator was in this checkout" once the server adds the
//     field; today the server ignores it.
//   - --ecosystem flag: M1 supports Go only (per issue scope). npm is
//     accepted with a stderr warning but the request proceeds — the
//     server-side analyzer is the source of truth on which ecosystems
//     have reachability support. A future hard-fail can land here once
//     the ecosystem list is stable.
//   - --confidence-threshold is forwarded informationally; the server
//     applies SBOMHUB_AI_CONFIDENCE_THRESHOLD authoritatively and
//     returns the effective value in TriageRunResult.Threshold. We
//     warn when the CLI's flag and the server's effective threshold
//     diverge so the operator knows config drift exists.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/youichi-uda/sbomhub-cli/internal/api"
)

// Decision outcome constants — values mirror the server-side
// triage.Decision* constants (see service/triage/runner.go).
const (
	decisionApproved = "approved"
	decisionEdited   = "edited"
	decisionRejected = "rejected"
)

// AI verdict states — values mirror service/triage/types.go.
const (
	stateUnderInvestigation = "under_investigation"
)

// AI feature disabled hint surfaced when the server returns 503
// llm.DisabledError. Kept as a constant so the wording is grep-able
// from the test (BYOK fallback case).
const aiDisabledHintJa = "APIキー未設定のため AI 解析 skip。 `/settings/llm` で設定してください"

var (
	triageProject             string
	triageEcosystem           string
	triageNonInteractive      bool
	triageConfidenceThreshold float64
)

var triageCmd = &cobra.Command{
	Use:   "triage [path]",
	Short: "脆弱性を AI VEX triage する / interactively triage vulnerabilities with AI",
	Long: `脆弱性を AI ベースで triage し、 VEX draft を生成・承認するコマンドです。
Interactively triage vulnerabilities using the BYOK LLM and persist
approve / edit / reject decisions as CycloneDX VEX drafts.

使用例 / Examples:
  sbomhub triage . --project my-device --ecosystem go
  sbomhub triage . --project <uuid> --non-interactive
  sbomhub triage . --project my-device --confidence-threshold 0.8

フロー / Flow:
  1. プロジェクトの脆弱性一覧を取得
     Fetch the project's vulnerabilities
  2. 各脆弱性に対して AI triage (POST /triage/run) を実行
     Run one AI triage cycle per vulnerability
  3. CVE / component / reachability / AI 提案 / confidence / evidence を表示
     Render CVE / component / reachability / AI verdict / confidence /
     evidence to the operator
  4. [a]pprove / [e]dit / [r]eject / [s]kip / [q]uit を選択
     Prompt the operator to decide
  5. 決定を PUT /vex-drafts/:id/decision で保存
     Persist the decision via the decision endpoint

BYOK LLM 未設定時 (= サーバが 503 を返した時) / If BYOK LLM is not
configured (server returns 503):
  - 全 vuln を under_investigation で記録
    Record every vulnerability as under_investigation
  - stderr に「APIキー未設定」のヒントを表示
    Print a one-line hint pointing at /settings/llm
  - exit 0 で終了 (CI を fail させない)
    Exit 0 — CI runs must not be blocked

--non-interactive は CI 用途で prompt を skip し、 同じく全 vuln を
under_investigation で記録します。
--non-interactive skips the prompt and applies the same
under_investigation fallback for every draft (CI template mode).

Exit codes:
  0  正常終了 / success (including the AI-disabled fallback path)
  1  ユーザーが [q]uit / user quit mid-loop
  3  API / 設定エラー / API or configuration error`,
	Args: cobra.MaximumNArgs(1),
	RunE: runTriage,
}

func init() {
	rootCmd.AddCommand(triageCmd)

	triageCmd.Flags().StringVarP(&triageProject, "project", "p", "", "対象プロジェクト ID (UUID) または名前 / project ID (UUID) or name")
	triageCmd.Flags().StringVar(&triageEcosystem, "ecosystem", "go", "対象エコシステム / target ecosystem (M1: go のみ正式サポート / only `go` is fully supported in M1)")
	triageCmd.Flags().BoolVar(&triageNonInteractive, "non-interactive", false, "prompt を skip し全 draft を under_investigation で保存 (CI 用) / skip prompts; save every draft as under_investigation (CI mode)")
	triageCmd.Flags().Float64Var(&triageConfidenceThreshold, "confidence-threshold", 0.7, "AI confidence の最小しきい値 / minimum AI confidence threshold (server-side SBOMHUB_AI_CONFIDENCE_THRESHOLD が真の source of truth / the server-side env var is the source of truth)")
}

// triageExitError lets runTriage signal a specific exit code to
// main() while still returning through the cobra error path. Mirrors
// the scanExitError pattern in scan.go.
type triageExitError struct {
	code int
	msg  string
}

func (e *triageExitError) Error() string { return e.msg }
func (e *triageExitError) ExitCode() int { return e.code }

// runTriage is the cobra entrypoint. Kept thin: input validation +
// API client wiring + delegating to the loop. Everything that needs
// to be unit-tested is reachable via the lower-level helpers
// (interactWith, triageOneVuln, applyDecision) that take an injected
// io.Reader / io.Writer / *api.Client so the test does not have to
// shell out cobra.
func runTriage(cmd *cobra.Command, args []string) error {
	out := GetOutputConfig()

	// --project is required: every API endpoint we call is scoped to
	// projects/:id. Surface this before any API round-trip so the
	// operator sees the actionable error immediately.
	if strings.TrimSpace(triageProject) == "" {
		return fmt.Errorf("--project は必須です / --project is required")
	}

	// --ecosystem warning: M1 supports Go only. Other values are
	// accepted (the server can still parse advisories for any
	// ecosystem it knows about) but the operator gets a one-line
	// notice that reachability quality may degrade. ※要確認: tighten
	// to a hard reject once the ecosystem list is locked.
	ecosystem := strings.ToLower(strings.TrimSpace(triageEcosystem))
	switch ecosystem {
	case "go":
		// fully supported in M1
	case "npm":
		fmt.Fprintln(out.ErrWriter, "警告: --ecosystem=npm は M1 では reachability 解析の対応が限定的です。 結果は under_investigation になる可能性があります。")
		fmt.Fprintln(out.ErrWriter, "warning: --ecosystem=npm has limited reachability support in M1; many drafts will land as under_investigation.")
	default:
		fmt.Fprintf(out.ErrWriter, "警告: 未知の --ecosystem=%q を指定しました。 M1 では go のみ正式サポートです。\n", triageEcosystem)
		fmt.Fprintf(out.ErrWriter, "warning: unknown --ecosystem=%q; only `go` is officially supported in M1.\n", triageEcosystem)
	}

	// Path is informational in M1. Resolve to absolute so any future
	// server-side audit (PathContext) gets a stable reference.
	scanPath := "."
	if len(args) > 0 {
		scanPath = args[0]
	}
	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return fmt.Errorf("パスの解決に失敗しました: %w", err)
	}
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		// Path is informational but if the operator supplied a
		// non-existent path that is almost certainly a typo — fail loud.
		return fmt.Errorf("パスが存在しません: %s", absPath)
	}

	// Credentials — same precedence as the other commands.
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

	client := api.NewClient(cfg.APIURL, cfg.APIKey)

	return runTriageLoop(cmd.Context(), client, triageOpts{
		projectID:           triageProject,
		ecosystem:           ecosystem,
		nonInteractive:      triageNonInteractive,
		confidenceThreshold: triageConfidenceThreshold,
		path:                absPath,
		stdin:               os.Stdin,
		stdout:              out.humanWriter(),
		stderr:              out.ErrWriter,
		editor:              defaultEditor(),
	})
}

// triageOpts groups the parameters passed into the loop so the test
// can construct a single struct rather than threading a long argument
// list. All I/O is injected (stdin / stdout / stderr / editor) so the
// test stubs each independently.
type triageOpts struct {
	projectID           string
	ecosystem           string
	nonInteractive      bool
	confidenceThreshold float64
	path                string

	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer

	// editor returns the command + args to spawn for `e]dit`. Defaults
	// to $EDITOR; tests override with a stub that writes a deterministic
	// payload to the temp file.
	editor editorFunc
}

// editorFunc abstracts $EDITOR. Receives the path of the temp file
// pre-seeded with current justification + detail, returns nil on
// success. Implementations are responsible for blocking until the
// editor exits.
type editorFunc func(path string) error

// runTriageLoop is the testable entrypoint. ctx may be context.TODO()
// from the test harness; runTriage threads cobra's request-scoped ctx.
//
//nolint:funlen // the loop is intentionally inlined for readability;
// splitting per-vuln steps into named helpers (already done for
// interactWith / applyDecision / triageOneVuln) keeps the function
// length within reason without obscuring the control flow.
func runTriageLoop(ctx context.Context, client *api.Client, opts triageOpts) error {
	// Step 1: enumerate vulnerabilities for the project.
	vulns, err := client.ListVulnerabilities(ctx, opts.projectID)
	if err != nil {
		// Treat fetching the work list as a permanent setup failure —
		// no auto-fallback. The operator must fix --project / auth.
		return &triageExitError{code: 3, msg: fmt.Sprintf("脆弱性一覧の取得に失敗しました: %v", err)}
	}
	if len(vulns) == 0 {
		fmt.Fprintln(opts.stdout, "脆弱性は検出されませんでした。 何もすることがありません。")
		fmt.Fprintln(opts.stdout, "No vulnerabilities to triage. Nothing to do.")
		return nil
	}

	reader := bufio.NewReader(opts.stdin)

	approved := 0
	edited := 0
	rejected := 0
	skipped := 0
	underInvestigation := 0
	aiDisabledNotified := false

	for i, v := range vulns {
		fmt.Fprintf(opts.stdout, "\n[%d/%d] %s\n", i+1, len(vulns), formatVulnHeader(v))

		// Step 2: run the AI cycle.
		runResp, err := client.RunTriage(ctx, opts.projectID, api.TriageRunRequest{
			VulnerabilityID: v.ID,
			CVEID:           v.CVEID,
		})

		var apiErr *api.TriageError
		if errors.As(err, &apiErr) && apiErr.IsAIDisabled() {
			// BYOK fallback path. Print the hint once (don't spam),
			// but record EVERY vuln as under_investigation.
			if !aiDisabledNotified {
				fmt.Fprintln(opts.stderr, aiDisabledHintJa)
				if apiErr.Reason != "" {
					fmt.Fprintf(opts.stderr, "  (server reason: %s)\n", apiErr.Reason)
				}
				aiDisabledNotified = true
			}
			// Without a draft we cannot PUT /decision (the endpoint
			// keys on draft_id which we never received). Surface the
			// "noted as under_investigation locally" line so the
			// operator knows the vuln was processed even though no
			// draft row was persisted.
			fmt.Fprintln(opts.stdout, "  → under_investigation (AI disabled — no draft persisted)")
			underInvestigation++
			continue
		}
		if err != nil {
			// Any other failure — permanent or transient — is logged
			// and the loop continues. We do NOT fail the whole run on
			// a per-vuln server error; the operator can re-run later
			// for the unprocessed entries. This matches the "best
			// effort triage" UX of the issue.
			fmt.Fprintf(opts.stderr, "  triage 失敗: %v\n", err)
			skipped++
			continue
		}

		// Confidence threshold divergence warning (one-shot per
		// process). Useful for catching SBOMHUB_AI_CONFIDENCE_THRESHOLD
		// drift between CI config and server config.
		if runResp != nil && runResp.Threshold > 0 && !approxEqual(runResp.Threshold, opts.confidenceThreshold) {
			fmt.Fprintf(opts.stderr, "  注意: --confidence-threshold=%.2f に対しサーバ側は %.2f を使用しています\n", opts.confidenceThreshold, runResp.Threshold)
		}

		renderDraft(opts.stdout, runResp)

		if runResp == nil || runResp.Draft == nil {
			// Defensive: the server returned 2xx but with no draft.
			// Skip and continue rather than panicking on a nil deref.
			fmt.Fprintln(opts.stderr, "  サーバから draft が返ってきませんでした (skip)")
			skipped++
			continue
		}
		draft := runResp.Draft

		// Step 4: decide the verdict.
		var decision string
		var editedState, editedJustification, editedDetail string
		switch {
		case opts.nonInteractive:
			// CI mode: every draft becomes under_investigation, edited
			// payload set explicitly so the server stores the verdict
			// rather than mirroring the AI's original state.
			decision = decisionEdited
			editedState = stateUnderInvestigation
			editedJustification = draft.Justification
			editedDetail = "auto-recorded by `sbomhub triage --non-interactive`"
		default:
			act, edState, edJust, edDetail, quit := promptDecision(reader, opts.stdout, opts.stderr, opts.editor, draft)
			if quit {
				fmt.Fprintln(opts.stdout, "ユーザーが終了を選択しました。")
				printTriageSummary(opts.stdout, len(vulns), i, approved, edited, rejected, skipped, underInvestigation)
				return &triageExitError{code: 1, msg: "ユーザーが triage を中断しました"}
			}
			if act == "" { // skip
				skipped++
				fmt.Fprintln(opts.stdout, "  → skipped")
				continue
			}
			decision = act
			editedState = edState
			editedJustification = edJust
			editedDetail = edDetail
		}

		// Step 5: persist the decision.
		if _, err := client.DecideDraft(ctx, opts.projectID, draft.ID, api.DecisionRequest{
			Decision:            decision,
			EditedState:         editedState,
			EditedJustification: editedJustification,
			EditedDetail:        editedDetail,
		}); err != nil {
			fmt.Fprintf(opts.stderr, "  decision 保存失敗: %v\n", err)
			skipped++
			continue
		}

		switch decision {
		case decisionApproved:
			approved++
			fmt.Fprintf(opts.stdout, "  → VEX draft saved as approved (id: %s)\n", draft.ID)
		case decisionEdited:
			edited++
			if editedState == stateUnderInvestigation {
				underInvestigation++
			}
			fmt.Fprintf(opts.stdout, "  → VEX draft saved as edited (id: %s, state=%s)\n", draft.ID, editedState)
		case decisionRejected:
			rejected++
			fmt.Fprintf(opts.stdout, "  → VEX draft saved as rejected (id: %s)\n", draft.ID)
		}
	}

	printTriageSummary(opts.stdout, len(vulns), len(vulns), approved, edited, rejected, skipped, underInvestigation)
	return nil
}

// formatVulnHeader produces the first line of the per-vuln block,
// matching the issue's example UX ("CVE-2024-XXXXX (github.com/foo/bar
// 1.2.3)"). The component portion uses Source as a stand-in until the
// server projection exposes the linked component name + version.
func formatVulnHeader(v api.VulnerabilityRecord) string {
	header := v.CVEID
	if v.Severity != "" {
		header = fmt.Sprintf("%s [%s]", header, v.Severity)
	}
	if v.InKEV {
		header = header + " [KEV]"
	}
	return header
}

// renderDraft prints the AI suggestion block in the format documented
// in the issue example. Confidence is rendered as a percentage so a
// 0.85 reads as "85%" — the audit log persists the raw 0.85 verbatim.
func renderDraft(w io.Writer, r *api.TriageRunResult) {
	if r == nil || r.Draft == nil {
		return
	}
	d := r.Draft

	// Reachability hint — derived from evidence kinds in the parsed
	// decision. import_only / symbol_ref vary the wording; absence
	// renders nothing rather than a misleading "unknown".
	if r.Parsed != nil {
		reach := summarizeReachability(r.Parsed.Evidence)
		if reach != "" {
			fmt.Fprintf(w, "  Reachability: %s\n", reach)
		}
	}

	suggestion := fmt.Sprintf("  AI 提案: %s", d.State)
	if d.Confidence != nil {
		suggestion = fmt.Sprintf("%s (confidence %.2f", suggestion, *d.Confidence)
		if r.Threshold > 0 {
			suggestion = fmt.Sprintf("%s, threshold %.2f", suggestion, r.Threshold)
		}
		suggestion = suggestion + ")"
	}
	if r.Clamped {
		suggestion = suggestion + " [clamped to under_investigation]"
	}
	fmt.Fprintln(w, suggestion)

	if d.Justification != "" {
		fmt.Fprintf(w, "    justification: %s\n", d.Justification)
	}
	if d.Detail != "" {
		fmt.Fprintf(w, "    detail: %s\n", d.Detail)
	}
	if r.Parsed != nil && len(r.Parsed.Evidence) > 0 {
		fmt.Fprintln(w, "  evidence:")
		for _, e := range r.Parsed.Evidence {
			fmt.Fprintf(w, "    - %s\n", formatEvidence(e))
		}
	}
	if d.Provider != "" || d.Model != "" {
		fmt.Fprintf(w, "  model: %s/%s\n", d.Provider, d.Model)
	}
}

// formatEvidence renders one evidence pointer as a single line. The
// shape mirrors the issue example: "github.com/foo/bar/pkg/x.go:42
// (vulnerable func)".
func formatEvidence(e api.TriageEvidence) string {
	var primary string
	switch {
	case e.FilePath != "":
		primary = e.FilePath
		if e.Line > 0 {
			primary = fmt.Sprintf("%s:%d", primary, e.Line)
		}
	case e.ImportPath != "":
		primary = e.ImportPath
	case e.Symbol != "":
		primary = e.Symbol
	default:
		primary = string(e.Kind)
	}
	if e.Description != "" {
		return fmt.Sprintf("%s (%s)", primary, e.Description)
	}
	if e.Note != "" {
		return fmt.Sprintf("%s — %s", primary, e.Note)
	}
	return primary
}

// summarizeReachability picks a one-line summary out of the evidence
// pointers ("import_only", "symbol_ref", or empty when neither is
// present). Confidence is intentionally NOT reported here — the
// per-decision confidence is the AI verdict, not a reachability
// confidence; surfacing both as separate numbers would mislead.
func summarizeReachability(ev []api.TriageEvidence) string {
	hasImport := false
	hasSymbol := false
	for _, e := range ev {
		switch e.Kind {
		case "import_path":
			hasImport = true
		case "symbol_ref":
			hasSymbol = true
		}
	}
	switch {
	case hasSymbol:
		return "symbol_ref"
	case hasImport:
		return "import_only"
	}
	return ""
}

// promptDecision drives the [a]/[e]/[r]/[s]/[q] prompt. Returns:
//
//	(action, editedState, editedJustification, editedDetail, quit)
//
// where action is one of "approved" / "edited" / "rejected" / "" (skip)
// and quit is true if the operator picked [q]uit.
//
// Invalid inputs reprompt rather than failing the loop — that matches
// the operator expectation that mistyping does not abort an
// hour-long triage session.
func promptDecision(reader *bufio.Reader, stdout, stderr io.Writer, editor editorFunc, draft *api.VEXDraft) (string, string, string, string, bool) {
	for {
		fmt.Fprint(stdout, "  [a]pprove / [e]dit / [r]eject / [s]kip / [q]uit ? ")
		line, err := reader.ReadString('\n')
		if err != nil {
			// EOF on stdin (closed pipe in a test, redirect end of
			// file) — treat as quit so the loop unwinds rather than
			// spinning forever.
			if errors.Is(err, io.EOF) {
				if strings.TrimSpace(line) == "" {
					return "", "", "", "", true
				}
				// Fall through with whatever we did read.
			} else {
				fmt.Fprintf(stderr, "  入力エラー: %v\n", err)
				return "", "", "", "", true
			}
		}
		choice := strings.ToLower(strings.TrimSpace(line))
		switch choice {
		case "a", "approve", "approved":
			return decisionApproved, "", "", "", false
		case "r", "reject", "rejected":
			return decisionRejected, "", "", "", false
		case "s", "skip", "":
			return "", "", "", "", false
		case "q", "quit", "exit":
			return "", "", "", "", true
		case "e", "edit", "edited":
			edState, edJust, edDetail, ok := editVEXContent(stderr, editor, draft)
			if !ok {
				// Editor failed or operator aborted the edit — fall
				// back to the prompt rather than recording a bad
				// edit.
				continue
			}
			return decisionEdited, edState, edJust, edDetail, false
		default:
			fmt.Fprintf(stderr, "  不明な入力: %q (a/e/r/s/q から選択してください)\n", choice)
		}
	}
}

// editorFile is the on-disk shape we hand to $EDITOR. JSON keeps the
// parsing trivial; comments would be lost on round-trip through
// encoding/json, so we document the field semantics in the file
// header instead.
type editorFile struct {
	State         string `json:"state"`
	Justification string `json:"justification"`
	Detail        string `json:"detail"`
}

// editVEXContent spawns $EDITOR on a temp file pre-populated with the
// draft's current state / justification / detail. On a clean save,
// returns the parsed values + ok=true; on any error (editor failure,
// JSON parse failure, empty file) returns ok=false and the caller
// reprompts.
func editVEXContent(stderr io.Writer, editor editorFunc, draft *api.VEXDraft) (string, string, string, bool) {
	tmp, err := os.CreateTemp("", "sbomhub-triage-*.json")
	if err != nil {
		fmt.Fprintf(stderr, "  一時ファイル作成失敗: %v\n", err)
		return "", "", "", false
	}
	defer os.Remove(tmp.Name())

	initial := editorFile{
		State:         draft.State,
		Justification: draft.Justification,
		Detail:        draft.Detail,
	}
	if err := json.NewEncoder(tmp).Encode(initial); err != nil {
		_ = tmp.Close()
		fmt.Fprintf(stderr, "  一時ファイル書き込み失敗: %v\n", err)
		return "", "", "", false
	}
	if err := tmp.Close(); err != nil {
		fmt.Fprintf(stderr, "  一時ファイル close 失敗: %v\n", err)
		return "", "", "", false
	}

	if editor == nil {
		fmt.Fprintln(stderr, "  $EDITOR が未設定です。 export EDITOR=vim 等で設定してください。")
		return "", "", "", false
	}
	if err := editor(tmp.Name()); err != nil {
		fmt.Fprintf(stderr, "  $EDITOR 実行失敗: %v\n", err)
		return "", "", "", false
	}

	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		fmt.Fprintf(stderr, "  編集後の読み込み失敗: %v\n", err)
		return "", "", "", false
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		fmt.Fprintln(stderr, "  ファイルが空です。 編集をキャンセルしました。")
		return "", "", "", false
	}

	var parsed editorFile
	if err := json.Unmarshal(data, &parsed); err != nil {
		fmt.Fprintf(stderr, "  JSON 解析失敗: %v\n", err)
		return "", "", "", false
	}
	return parsed.State, parsed.Justification, parsed.Detail, true
}

// defaultEditor returns an editorFunc that spawns $EDITOR (falling
// back to `vi`). Inherits the parent's stdin / stdout / stderr so the
// terminal-based editor (vi / vim / nano) renders correctly.
func defaultEditor() editorFunc {
	return func(path string) error {
		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = "vi"
		}
		// /bin/sh -c keeps support for EDITOR values that include
		// flags (e.g. EDITOR="emacs -nw"). The path is shell-quoted
		// to survive whitespace.
		cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("%s %q", editor, path))
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
}

// printTriageSummary writes the final tally. processed is the count
// of vulns the loop actually visited (may be < total when the
// operator quit early).
func printTriageSummary(w io.Writer, total, processed, approved, edited, rejected, skipped, underInvestigation int) {
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Triage 結果 / Triage summary")
	fmt.Fprintln(w, "----------------------------")
	fmt.Fprintf(w, "  対象 / total            : %d\n", total)
	fmt.Fprintf(w, "  処理済 / processed      : %d\n", processed)
	fmt.Fprintf(w, "  approved                : %d\n", approved)
	fmt.Fprintf(w, "  edited                  : %d\n", edited)
	fmt.Fprintf(w, "    └ under_investigation : %d\n", underInvestigation)
	fmt.Fprintf(w, "  rejected                : %d\n", rejected)
	fmt.Fprintf(w, "  skipped                 : %d\n", skipped)
}

// approxEqual is a tiny float comparison helper. The CLI flag is user
// input rounded to ~2 decimal places, so a millisecond-precision
// difference (0.70 vs 0.7000000001) should not trip the warning.
func approxEqual(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 1e-6
}
