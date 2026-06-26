package commands

// `sbomhub llm test` / `sbomhub llm bench` — LLM provider connectivity
// check and quality benchmark for enterprise PoC operators (M4 Wave
// M4-7 — sbomhub-cli issue #4).
//
// The M4 MVP exposes two subcommands:
//
//	sbomhub llm test
//	    [--provider <name>] [--json]
//
//	sbomhub llm bench
//	    [--providers <csv>] [--max-cases <N>] [--eval-set <path>]
//	    [--sbomhub-source <path>] [--out <path>] [--markdown]
//	    [--timeout <sec>]
//
// `llm test` — HTTP probe against the sbomhub API server's public
// /api/v1/health endpoint (the only no-auth GET under /api/v1; see
// sbomhub/apps/api/cmd/server/main.go line 591). Surfaces the
// server's self-reported status / mode + (when published) provider /
// model / connected fields. The current server only emits
// {status, mode}, so the CLI gracefully renders "N/A" for the LLM
// metadata until the server is extended (※要確認 in
// internal/api/llm.go).
//
// `llm bench` — wrapper around the M4-3 bench harness
// (sbomhub/apps/api/cmd/llm-bench). Option A from the M4-7 prompt:
// the wrapper shells out to `go run ./cmd/llm-bench` against the
// operator's sbomhub source checkout (located via --sbomhub-source /
// SBOMHUB_SOURCE / default `./sbomhub`). This requires a Go
// toolchain on the operator's machine but avoids API surface
// expansion (Option B) and duplicate LLM provider code (Option C).
// Enterprise customers running the M4 docker-compose stack already
// have the sbomhub source checked out (it ships with
// docker-compose.enterprise.yml) so the dependency is met
// in-context.
//
// Both subcommands flow through the same M1/M2/M3-aligned regime —
// credentials via resolveCredentials, output via GetOutputConfig,
// exit codes via llmExitError (3=permanent, 4=transient) — so the
// operator gets the same UX they learned from `sbomhub triage` /
// `sbomhub cra` / `sbomhub meti`.
//
// F1-F37 fix pattern carry-over (commit message documents specifics):
//   - F21 (exit code 0 / 3 / 4)
//   - F22 (strict 503 AI-disabled detection — only recognised reason
//          markers classify as ai_disabled; gateway 503 stays
//          transient)
//   - F23 (2xx response contract validation — `llm test` requires a
//          `status` field; `llm bench` propagates exit codes from
//          the M4-3 binary)
//   - F26 (pagination not applicable — `llm test` is a single GET;
//          `llm bench` enumerates the eval-set itself inside the
//          spawned binary)
//   - F35-equivalent (`--json` parity with triage / cra / meti
//          subcommands)
//
// ※要確認:
//   - The sbomhub API server does NOT currently publish LLM provider
//     info on /api/v1/health (it returns only {status, mode}). The
//     CLI parses richer fields permissively so a future server
//     extension auto-fills the display; until then "Provider" and
//     "Connected" render as "N/A". Adding /api/v1/health/llm is
//     tracked as a separate issue and intentionally out of scope
//     for M4-7.
//   - `llm bench` requires a Go toolchain because the M4-3 bench
//     harness is invoked via `go run`. Enterprise customers running
//     docker-compose.enterprise.yml have sbomhub source on disk;
//     non-source operators cannot use the bench subcommand. The
//     --help text and the missing-source error message both call
//     this out explicitly.
//   - M4-3 (apps/api/cmd/llm-bench/main.go) exits 0 on success and
//     1 on any failure (eval-set load fail / no providers
//     available / I/O errors). The wrapper folds non-zero exits
//     into our exit-3 (permanent) bucket because every M4-3
//     failure mode is operator-actionable config (set provider
//     env, fix eval-set path) rather than a transient outage.
//     Network errors raised while LAUNCHING the binary
//     (ENOENT on `go`) map to exit-3 too — "install Go" is also a
//     permanent fix.

import (
	"context"
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

// llmExitError lets a runLlmXxx return a specific exit code through
// the cobra error path. Mirrors metiExitError / craExitError /
// triageExitError so main.go's exitCoder hook covers every M4 surface
// without a branching type assertion.
type llmExitError struct {
	code int
	msg  string
}

func (e *llmExitError) Error() string { return e.msg }
func (e *llmExitError) ExitCode() int { return e.code }

// ---------------------------------------------------------------------------
// Default constants
// ---------------------------------------------------------------------------

// llmBenchDefaultEvalSetRel is the path (relative to the sbomhub
// source root) of the canonical 20-case fixture shipped with M4-3.
// Mirrors sbomhub/apps/api/cmd/llm-bench/main.go's default fixture
// reference. The wrapper joins this with --sbomhub-source to form
// the absolute --eval-set passed to `go run`.
//
// M4 Codex review #F38 fix: the fixture lives under apps/api/ on the
// sbomhub side (the M4-3 binary's `apps/api` working dir makes that
// path implicit there). resolveEvalSetPath joins this against the
// sbomhub repo *root*, so the apps/api/ prefix must be embedded here
// — otherwise the preflight os.Stat fails on a fresh checkout.
const llmBenchDefaultEvalSetRel = "apps/api/test/fixtures/llm-bench/cve-20-50.json"

// llmBenchDefaultSbomhubSource is the conventional checkout layout
// for the M4 docker-compose stack (sbom-all/sbomhub-cli sits next
// to sbom-all/sbomhub). If --sbomhub-source is unset and
// SBOMHUB_SOURCE is unset, the wrapper looks for ./sbomhub relative
// to the operator's current directory.
const llmBenchDefaultSbomhubSource = "./sbomhub"

// llmBenchDefaultProviders is the default --providers value: "all"
// expands inside the M4-3 binary to every supported provider, with
// providers missing their BYOK env vars being skipped with a
// stderr warning rather than aborting the whole run.
const llmBenchDefaultProviders = "all"

// llmBenchDefaultMaxCases mirrors the M4-3 fixture size so a fresh
// install runs against the full 20-case eval-set. The operator can
// trim with --max-cases.
const llmBenchDefaultMaxCases = 20

// llmBenchDefaultTimeoutSec mirrors the M4-3 per-call timeout
// default. Surfaced here so the CLI's --help text documents it
// without forcing the user to read the M4-3 source.
const llmBenchDefaultTimeoutSec = 60

// ---------------------------------------------------------------------------
// Flag globals (per subcommand) — kept package-scoped to match the
// existing triage / cra / meti command conventions
// ---------------------------------------------------------------------------

var (
	// test
	llmTestProvider string

	// bench
	llmBenchProviders     string
	llmBenchEvalSet       string
	llmBenchMaxCases      int
	llmBenchSbomhubSource string
	llmBenchOut           string
	llmBenchMarkdown      bool
	llmBenchTimeoutSec    int
)

// ---------------------------------------------------------------------------
// Cobra wiring
// ---------------------------------------------------------------------------

var llmCmd = &cobra.Command{
	Use:   "llm",
	Short: "LLM プロバイダの疎通確認とベンチマーク / LLM provider connectivity check and benchmark",
	Long: `OSS / self-host 版 sbomhub で利用する LLM プロバイダ (OpenAI / Anthropic /
Gemini / Azure OpenAI / Ollama) の疎通確認とベンチマークを行うコマンド群です
(M4 MVP)。

Subcommands:
  test    sbomhub API server の /api/v1/health を叩き、 接続性と
          (公開されていれば) provider / model 情報を表示
          Probe /api/v1/health and report connectivity + (when published)
          provider / model
  bench   sbomhub source 配下の llm-bench harness を実行し、 managed
          AI vs local LLM の品質を 20 件 eval-set で比較
          Run the sbomhub-side llm-bench harness against the bundled
          20-case eval-set to compare managed AI vs local LLM quality

使用例 / Examples:
  sbomhub llm test
  sbomhub llm test --json
  sbomhub llm bench --providers ollama,gemini --sbomhub-source ../sbomhub

詳細は各 subcommand の --help を参照してください。
See each subcommand's --help for the full flag set.`,
}

var llmTestCmd = &cobra.Command{
	Use:   "test",
	Short: "LLM プロバイダの疎通確認 / Check LLM provider connectivity",
	Long: `sbomhub API server の公開 health endpoint (GET /api/v1/health) を
叩き、 connectivity + (server が公開していれば) provider / model
情報を表示します。

サーバ側の現行 health endpoint は {status, mode} のみを返します。
provider / model / connected フィールドは将来サーバ拡張後に
自動的に表示されます (※要確認: 拡張は別 issue、 本 CLI は graceful
fallback として N/A 表示)。

--provider は将来 server 側で複数 provider の同時設定をサポート
した場合の選択用 hint です。 現状はサーバ側 default provider が
1 つのみのため値は無視されます (将来互換のため flag は受理)。

Exit codes:
  0  正常終了 / success
  3  恒久エラー / permanent (401/403/404 — fix config; BYOK 未設定)
  4  一時エラー / transient (429/5xx — retry recommended)`,
	RunE: runLLMTest,
}

var llmBenchCmd = &cobra.Command{
	Use:   "bench",
	Short: "LLM プロバイダの品質ベンチマーク / Benchmark LLM provider quality",
	Long: `sbomhub source 配下の llm-bench harness (sbomhub/apps/api/cmd/
llm-bench) を実行し、 managed AI と local LLM (Ollama) の VEX-triage
品質を 20 件の eval-set で比較します。

前提 / Prerequisites:
  - Go toolchain がインストールされていること (` + "`go run` 経由で M4-3" + ` を呼ぶ)
    A Go toolchain must be installed (the wrapper invokes the bench
    binary via ` + "`go run`" + `)
  - sbomhub OSS の source が手元に checkout されていること
    The sbomhub OSS source must be checked out locally
    (--sbomhub-source / SBOMHUB_SOURCE / ./sbomhub のいずれか)
  - 比較したい provider の BYOK env が設定されていること
    BYOK env vars for the providers under test must be set
    (OPENAI_API_KEY / ANTHROPIC_API_KEY / GOOGLE_API_KEY /
    SBOMHUB_LLM_BENCH_OLLAMA_MODEL など)

出力 / Output:
  - JSONL を stdout (--out で file 出力に切替可能)
  - --markdown 指定時、 集計 markdown table を stderr に出力
  - JSONL is written to stdout (override with --out)
  - With --markdown the aggregation table is emitted to stderr

使用例 / Examples:
  sbomhub llm bench
  sbomhub llm bench --providers ollama,gemini --markdown
  sbomhub llm bench --sbomhub-source ../sbomhub --max-cases 10 --out result.jsonl

Exit codes:
  0  正常終了 / success
  3  恒久エラー / permanent (sbomhub source 不在 / eval-set 不在 /
     provider env 未設定 / Go toolchain 不在 — fix the surfaced cause)
  4  一時エラー / transient (network blip while talking to a provider
     — retry recommended)`,
	RunE: runLLMBench,
}

func init() {
	rootCmd.AddCommand(llmCmd)
	llmCmd.AddCommand(llmTestCmd)
	llmCmd.AddCommand(llmBenchCmd)

	// test
	llmTestCmd.Flags().StringVar(&llmTestProvider, "provider", "",
		"確認対象 provider 名 (現状サーバが default 1 つのみ、 将来互換のため受理) / provider hint (currently advisory)")

	// bench — defaults documented in the constants block above so the
	// --help string stays scannable.
	llmBenchCmd.Flags().StringVar(&llmBenchProviders, "providers", llmBenchDefaultProviders,
		"対象 provider (csv) / providers to bench (csv); 'all' で全 provider")
	llmBenchCmd.Flags().StringVar(&llmBenchEvalSet, "eval-set", "",
		"eval-set JSON path (相対なら --sbomhub-source 起点で解決) / eval-set JSON path (relative paths resolved under --sbomhub-source)")
	llmBenchCmd.Flags().IntVar(&llmBenchMaxCases, "max-cases", llmBenchDefaultMaxCases,
		"1 provider あたり最大 case 数 (F25 fan-out cap) / per-provider case cap")
	llmBenchCmd.Flags().StringVar(&llmBenchSbomhubSource, "sbomhub-source", "",
		"sbomhub OSS source の path (env SBOMHUB_SOURCE / 既定 ./sbomhub) / path to sbomhub OSS source")
	llmBenchCmd.Flags().StringVar(&llmBenchOut, "out", "",
		"JSONL 出力 file path (省略時 stdout) / JSONL output file (default stdout)")
	llmBenchCmd.Flags().BoolVar(&llmBenchMarkdown, "markdown", false,
		"集計 markdown table を stderr に出力 / emit aggregation table on stderr")
	llmBenchCmd.Flags().IntVar(&llmBenchTimeoutSec, "timeout", llmBenchDefaultTimeoutSec,
		"1 case あたり LLM 呼出 timeout 秒 / per-call timeout in seconds")
}

// ---------------------------------------------------------------------------
// llm test
// ---------------------------------------------------------------------------

// runLLMTest probes /api/v1/health on the configured sbomhub API
// server and renders the result.
//
// Output contract:
//   - --json: marshals LLMHealthResponse + a "connectivity": "ok"
//     synthesised field so jq consumers can filter on a single
//     boolean. "N/A" is conveyed by leaving the JSON field empty.
//   - human: one block per field (status, mode, provider, model,
//     connected, reason), with "N/A" rendered when the server did
//     not publish a particular field. The block ends with the
//     URL so the operator knows which endpoint they hit.
func runLLMTest(cmd *cobra.Command, args []string) error {
	out := GetOutputConfig()

	// Resolve credentials directly so we can surface the resolved
	// API URL in the output without needing a Client accessor
	// (client.go is in the M4-7 DO NOT touch list). The client is
	// instantiated against the same cfg so the URL the operator
	// sees on the report is exactly the URL the probe hit.
	cfg, err := resolveCredentials(getConfigDir())
	if err != nil {
		return fmt.Errorf("設定の読み込みに失敗しました: %w", err)
	}
	if cfg.APIURL == "" {
		return fmt.Errorf("API URLが設定されていません。 'sbomhub login' で設定するか、 --api-url フラグ・ 環境変数 SBOMHUB_API_URL を指定してください")
	}
	// API key is optional for the health probe (the endpoint is
	// public). We don't require it because the operator's first
	// connectivity check should not need a key — they're literally
	// asking "can I reach the server" before bothering to set one.
	client := api.NewClient(cfg.APIURL, cfg.APIKey)

	// --provider is accepted but currently advisory — sbomhub OSS has
	// at most one provider configured at a time (per tenant), so the
	// flag has no server-side effect today. Future server work
	// (multi-provider per tenant) can wire it through without a CLI
	// change. We log a one-line stderr notice so the operator knows
	// the flag was consumed.
	if strings.TrimSpace(llmTestProvider) != "" {
		fmt.Fprintf(out.ErrWriter,
			"注: --provider=%q は将来互換 hint として受理されました (現状サーバは default provider 1 つのみ評価)\n",
			llmTestProvider)
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	res, err := client.Health(ctx)
	if err != nil {
		return llmHealthFailureToExitError("llm test", err)
	}

	return renderLLMTest(out, res, cfg.APIURL)
}

// renderLLMTest factors the output path out of runLLMTest so the
// command logic can be reused in tests that drive a fake server +
// captured OutputConfig without re-implementing the rendering.
func renderLLMTest(out *OutputConfig, res *api.LLMHealthResponse, baseURL string) error {
	if out.IsJSON() {
		// Synthesise "connectivity": "ok" so machine consumers can
		// branch on a single boolean. We do NOT collapse server-
		// supplied Connected into this field — they answer different
		// questions ("can the CLI reach the API server" vs "does the
		// API server believe its LLM is reachable").
		payload := map[string]interface{}{
			"connectivity":      "ok",
			"api_url":           baseURL,
			"status":            res.Status,
			"mode":              res.Mode,
			"provider":          res.Provider,
			"model":             res.Model,
			"llm_connected":     nil,
			"llm_reason":        res.Reason,
		}
		if res.Connected != nil {
			payload["llm_connected"] = *res.Connected
		}
		return out.PrintJSON(payload)
	}

	w := out.humanWriter()
	fmt.Fprintln(w, "LLM プロバイダ疎通確認 / LLM provider connectivity")
	fmt.Fprintln(w, "----------------------------------------------------")
	fmt.Fprintf(w, "  API URL          : %s\n", baseURL)
	fmt.Fprintf(w, "  API status       : %s\n", orNA(res.Status))
	fmt.Fprintf(w, "  Server mode      : %s\n", orNA(res.Mode))
	fmt.Fprintf(w, "  LLM provider     : %s\n", orNA(res.Provider))
	fmt.Fprintf(w, "  LLM model        : %s\n", orNA(res.Model))
	fmt.Fprintf(w, "  LLM connected    : %s\n", renderConnected(res.Connected))
	if res.Reason != "" {
		fmt.Fprintf(w, "  LLM reason       : %s\n", res.Reason)
	}
	if res.Provider == "" {
		// Honest disclosure so the operator does not interpret
		// "N/A" as "server is broken" (※要確認 above).
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "注: 現在の sbomhub API server は health endpoint で LLM provider 情報を")
		fmt.Fprintln(w, "    公開していません。 provider 詳細は /settings/llm (Web UI) で確認してください。")
		fmt.Fprintln(w, "    Note: the current sbomhub API server does not publish LLM provider")
		fmt.Fprintln(w, "    info on /api/v1/health — check /settings/llm in the Web UI for")
		fmt.Fprintln(w, "    provider details.")
	}
	return nil
}

// orNA renders an empty string as "N/A" for human display.
func orNA(s string) string {
	if strings.TrimSpace(s) == "" {
		return "N/A"
	}
	return s
}

// renderConnected formats the *bool tri-state for human display.
// nil → "N/A", *true → "yes", *false → "no".
func renderConnected(b *bool) string {
	if b == nil {
		return "N/A"
	}
	if *b {
		return "yes"
	}
	return "no"
}

// llmHealthFailureToExitError translates an LLM health API error
// into the exit-code envelope (3=permanent, 4=transient) following
// the M1 #F21 pattern. Network / unknown errors fall into the
// transient bucket because the operator's correct response (retry)
// is the same.
//
// The AI-disabled 503 case (IsAIDisabled) is folded into permanent
// because the operator's correct response is "configure BYOK in
// /settings/llm", NOT "retry"; we surface a dedicated hint message
// so the operator gets a direct action item rather than a generic
// "permanent failure" line.
func llmHealthFailureToExitError(op string, err error) error {
	if err == nil {
		return nil
	}
	var le *api.LLMError
	if errors.As(err, &le) {
		switch {
		case le.IsAIDisabled():
			return &llmExitError{
				code: 3,
				msg: fmt.Sprintf("%s BYOK 未設定 / BYOK provider not configured: %v\n  → Web UI /settings/llm で provider を設定してください / configure a provider in /settings/llm",
					op, err),
			}
		case le.IsPermanent():
			return &llmExitError{code: 3, msg: fmt.Sprintf("%s 恒久エラー / permanent failure: %v", op, err)}
		case le.IsTransient():
			return &llmExitError{code: 4, msg: fmt.Sprintf("%s 一時エラー / transient failure (retry): %v", op, err)}
		default:
			// Unknown 4xx the helpers do not classify — treat as
			// permanent because the operator's response is "fix
			// something", not "retry".
			return &llmExitError{code: 3, msg: fmt.Sprintf("%s 不明な失敗: %v", op, err)}
		}
	}
	// Network / JSON parse / context errors — retry is the right
	// response.
	return &llmExitError{code: 4, msg: fmt.Sprintf("%s 一時エラー / transient failure (retry): %v", op, err)}
}

// ---------------------------------------------------------------------------
// llm bench
// ---------------------------------------------------------------------------

// runLLMBench is the cobra entrypoint for `sbomhub llm bench`.
// Resolves --sbomhub-source / --eval-set, builds the `go run`
// command line, and execs the M4-3 bench harness inside the sbomhub
// source tree. Stdout / stderr stream through so the operator sees
// JSONL + (optional) markdown table without any CLI buffering.
//
// The wrapper does NOT parse or rewrite the M4-3 output — that
// would duplicate the M4-3 semantics in the CLI and force the
// wrapper to be redeployed whenever the bench schema evolves.
// Pass-through is the explicit design choice for Option A.
func runLLMBench(cmd *cobra.Command, args []string) error {
	out := GetOutputConfig()

	source, err := resolveSbomhubSource(llmBenchSbomhubSource)
	if err != nil {
		return &llmExitError{code: 3, msg: err.Error()}
	}

	evalSetPath, err := resolveEvalSetPath(llmBenchEvalSet, source)
	if err != nil {
		return &llmExitError{code: 3, msg: err.Error()}
	}

	if llmBenchMaxCases <= 0 {
		return &llmExitError{
			code: 3,
			msg:  fmt.Sprintf("--max-cases は 1 以上で指定してください (got %d)", llmBenchMaxCases),
		}
	}
	if llmBenchTimeoutSec <= 0 {
		return &llmExitError{
			code: 3,
			msg:  fmt.Sprintf("--timeout は 1 以上で指定してください (got %d)", llmBenchTimeoutSec),
		}
	}

	// `go` toolchain pre-flight. Surfacing this before we exec gives
	// a friendlier error than the bare "executable file not found"
	// from os/exec. ENOENT here is permanent (operator must install
	// Go) so we map to exit-3.
	if _, lookErr := exec.LookPath("go"); lookErr != nil {
		return &llmExitError{
			code: 3,
			msg: fmt.Sprintf("`go` toolchain が見つかりません: %v\n"+
				"  `sbomhub llm bench` は sbomhub source の M4-3 bench を `go run` 経由で実行します。\n"+
				"  Install Go from https://go.dev/dl/ and ensure `go` is in PATH.",
				lookErr),
		}
	}

	// Build the command. We invoke `go run ./cmd/llm-bench` rather
	// than building first because:
	//   1. avoids leaving a binary in the operator's tree
	//   2. matches the M4-3 README invocation verbatim
	//   3. recompile-on-change picks up local M4-3 patches without
	//      a separate build step
	goArgs := []string{
		"run", "./cmd/llm-bench",
		"--providers", llmBenchProviders,
		"--eval-set", evalSetPath,
		"--max-cases", fmt.Sprintf("%d", llmBenchMaxCases),
		"--timeout", fmt.Sprintf("%d", llmBenchTimeoutSec),
	}
	if llmBenchOut != "" {
		goArgs = append(goArgs, "--out", llmBenchOut)
	}
	if llmBenchMarkdown {
		goArgs = append(goArgs, "--markdown")
	}

	// M4-3 binary lives under apps/api/cmd/llm-bench so the
	// working directory for `go run` is apps/api (where the
	// containing go.mod lives).
	workDir := filepath.Join(source, "apps", "api")
	if _, statErr := os.Stat(filepath.Join(workDir, "go.mod")); os.IsNotExist(statErr) {
		return &llmExitError{
			code: 3,
			msg: fmt.Sprintf(
				"sbomhub source の apps/api/go.mod が見つかりません (looked under %s)\n"+
					"  --sbomhub-source が正しい sbomhub OSS checkout を指していますか?\n"+
					"  --sbomhub-source must point at the sbomhub OSS repo root",
				workDir),
		}
	}

	if out.IsVerbose() {
		fmt.Fprintf(out.ErrWriter, "[DEBUG] cd %s && go %s\n", workDir, strings.Join(goArgs, " "))
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Wire stdout / stderr straight through. JSONL lands on stdout
	// (M4-3 default) so jq pipelines keep working; markdown +
	// per-case slog warnings land on stderr.
	execCmd := exec.CommandContext(ctx, "go", goArgs...)
	execCmd.Dir = workDir
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = out.Writer
	execCmd.Stderr = out.ErrWriter

	// Pass through any provider BYOK env vars the operator already
	// exported. We do NOT redact / filter — the M4-3 binary is what
	// uses them and it has its own no-log discipline.
	execCmd.Env = os.Environ()

	if runErr := execCmd.Run(); runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			// M4-3 exits 0=success / 1=failure (all surfaces). The
			// failure modes (eval-set load fail / no providers
			// configured / I/O error) are all operator-actionable
			// config issues, so we map to exit-3 (permanent). A
			// dedicated transient mapping would require M4-3 to
			// emit a richer exit code surface; until then we err
			// on "do not silently mask the failure as retryable".
			return &llmExitError{
				code: 3,
				msg: fmt.Sprintf("llm bench 失敗 (exit=%d) — stderr の M4-3 メッセージで原因を確認してください",
					exitErr.ExitCode()),
			}
		}
		// Non-ExitError = launch failure (file not found, signal
		// during spawn). Permanent — operator must fix env.
		return &llmExitError{
			code: 3,
			msg:  fmt.Sprintf("llm bench 起動失敗: %v", runErr),
		}
	}

	return nil
}

// resolveSbomhubSource picks the source directory using the
// documented precedence: --sbomhub-source flag > SBOMHUB_SOURCE env
// > default `./sbomhub`. Returns an absolute path so subsequent
// joins are unambiguous.
//
// A missing directory is surfaced as a permanent error with the
// resolution chain spelled out, so the operator sees which sources
// were tried instead of just "directory not found".
func resolveSbomhubSource(flagValue string) (string, error) {
	source := strings.TrimSpace(flagValue)
	if source == "" {
		source = strings.TrimSpace(os.Getenv("SBOMHUB_SOURCE"))
	}
	if source == "" {
		source = llmBenchDefaultSbomhubSource
	}
	abs, err := filepath.Abs(source)
	if err != nil {
		return "", fmt.Errorf("--sbomhub-source の絶対パス解決に失敗: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("sbomhub source ディレクトリが見つかりません (%s): %w\n"+
			"  --sbomhub-source <path> / 環境変数 SBOMHUB_SOURCE / カレントの ./sbomhub のいずれかで sbomhub OSS source を指定してください\n"+
			"  Specify the sbomhub OSS source root via --sbomhub-source, SBOMHUB_SOURCE, or place it at ./sbomhub",
			abs, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("sbomhub source は directory である必要があります: %s", abs)
	}
	return abs, nil
}

// resolveEvalSetPath returns the absolute path to the eval-set JSON.
// When --eval-set is empty the default fixture (relative to the
// sbomhub source root) is used. When --eval-set is a relative path
// it is resolved against the sbomhub source root for parity with
// the M4-3 binary's own relative-path convention.
func resolveEvalSetPath(flagValue, sbomhubSource string) (string, error) {
	path := strings.TrimSpace(flagValue)
	if path == "" {
		path = filepath.Join(sbomhubSource, llmBenchDefaultEvalSetRel)
	} else if !filepath.IsAbs(path) {
		path = filepath.Join(sbomhubSource, path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("--eval-set の絶対パス解決に失敗: %w", err)
	}
	if _, err := os.Stat(abs); err != nil {
		return "", fmt.Errorf("eval-set fixture が見つかりません (%s): %w\n"+
			"  --eval-set <path> で別の fixture を指定するか、 sbomhub source の checkout を確認してください\n"+
			"  Pass --eval-set <path> to point at a custom fixture or verify the sbomhub source checkout",
			abs, err)
	}
	return abs, nil
}

// ---------------------------------------------------------------------------
// helpers reused for testability
// ---------------------------------------------------------------------------

// Compile-time guarantee that runLLMTest / runLLMBench keep the
// cobra RunE signature. If a refactor changes the entry signature
// the command registration above will fail to compile too — this
// var is belt + braces, NOT a call (would execute on import).
var (
	_ func(cmd *cobra.Command, args []string) error = runLLMTest
	_ func(cmd *cobra.Command, args []string) error = runLLMBench
)

// Discard reference keeps the io import live for the test file even
// when production code happens not to use it (e.g. when stdout/
// stderr flow through directly without a discard pipe).
var _ io.Writer = io.Discard
