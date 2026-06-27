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
// the wrapper compiles the M4-3 binary into a per-invocation temp
// dir via `go build` and execs the resulting binary directly,
// against the operator's sbomhub source checkout (located via
// --sbomhub-source / SBOMHUB_SOURCE / default `./sbomhub`). This
// requires a Go toolchain on the operator's machine but avoids
// API surface expansion (Option B) and duplicate LLM provider
// code (Option C). Enterprise customers running the M4
// docker-compose stack already have the sbomhub source checked
// out (it ships with docker-compose.enterprise.yml) so the
// dependency is met in-context.
//
// M4 Codex review #F61 (round 6) fix: the pre-fix path used
// `go run ./cmd/llm-bench`. `go run` always exits 1 when the
// inner program fails — regardless of the inner os.Exit(N) value
// — so the M4-3 F42 typed contract (2/3/4/5) was silently masked
// (operators saw exit 3 from the F57 contract-violation branch
// even when M4-3 emitted a clean exit 4 "no providers"). The
// build+exec split routes exec.ExitError.ExitCode() back to the
// actual M4-3 exit code so F46 pass-through holds in production.
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
//     harness is compiled on demand via `go build` and exec'd
//     directly (M4 Codex review #F61). Enterprise customers
//     running docker-compose.enterprise.yml have sbomhub source
//     on disk; non-source operators cannot use the bench
//     subcommand. The --help text and the missing-source error
//     message both call this out explicitly.
//   - M4-3 (apps/api/cmd/llm-bench/main.go) emits a *typed* exit-code
//     contract after F42:
//       0 success
//       2 usage / flag validation
//       3 fixture / config validation
//       4 no providers available
//       5 execution / output failure
//     M4 Codex review #F46 fix: the wrapper now propagates these
//     codes verbatim (option (a) — transparent pass-through) so CI
//     pipelines can distinguish "no providers configured" (4 → fix
//     BYOK env) from "execution failure" (5 → likely transient /
//     retry candidate). The trade-off vs option (c) hybrid (compress
//     2/3/4 → 3 and 5 → 4) is that exit code 4 then has two meanings
//     depending on which sbomhub-cli subcommand emitted it:
//     `triage`/`cra`/`meti`/`llm test` use 4 = transient HTTP, while
//     `llm bench` uses 4 = "no providers configured" by reflecting
//     the M4-3 contract. We accept that overload because the
//     stderr/wrapper message names the M4-3 code explicitly and CI
//     pipelines already branch on (subcommand, exit-code) pairs.
//     ※要確認: if downstream automation assumes a single global
//     permanent=3/transient=4 split across every subcommand, switch
//     to option (c) and document the loss of "no providers" vs
//     "execution failure" granularity.
//     Signal-killed subprocesses (ExitCode == -1) map to 4 as a
//     transient-leaning default — the operator's correct response
//     is usually retry (CTRL-C / OOM kill / parent timeout).
//     Network errors raised while LAUNCHING the binary
//     (ENOENT on `go`) map to exit-3 because "install Go" is a
//     permanent fix.
//     M4 Codex review #F57 (round 5): codes OUTSIDE the 2/3/4/5
//     band are renormalised to exit 3 by mapBenchSubprocessError
//     + the captured-stderr tee in runLLMBench so the documented
//     `llm bench` contract (0/2/3/4/5) is never silently widened.
//     Before #F61 (round 6) this branch fired routinely because
//     `go run` itself emitted exit 1 on inner failure regardless
//     of the inner os.Exit(N); after F61 the build+exec split
//     means it only fires for true contract violations (the M4-3
//     binary actually emitted a code outside the documented
//     band, or the subprocess died with an unusual exit). The
//     captured tail of the bench binary's stderr is embedded in
//     the error message so operators do not have to re-run.
//     M4 Codex review #F61 (round 6): the bench binary is now
//     compiled via `go build` into a temp dir and exec'd
//     directly, so exec.ExitError.ExitCode() reflects the actual
//     M4-3 F42 code. The pre-F61 `go run` path masked this code
//     (always exit 1 on inner failure) and forced the F57
//     contract-violation branch to fire for ordinary M4-3
//     failures, breaking F46 transparent pass-through in
//     production.

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

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
	llmBenchBinary        string
	llmBenchOut           string
	llmBenchMarkdown      bool
	llmBenchTimeoutSec    int
)

var (
	llmBenchReleaseDownloadBaseURL = "https://github.com/youichi-uda/sbomhub/releases/download"
	llmBenchLatestReleaseAPIURL    = "https://api.github.com/repos/youichi-uda/sbomhub/releases/latest"
	llmBenchHTTPClient             = &http.Client{Timeout: 60 * time.Second}
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
  bench   llm-bench release binary (default) または sbomhub source build
          を実行し、 managed AI vs local LLM の品質を 20 件 eval-set で比較
          Run the llm-bench release binary (default) or source build
          against the bundled 20-case eval-set to compare managed AI
          vs local LLM quality

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
	Long: `sbomhub release artifact として配布される llm-bench binary を実行し、
managed AI と local LLM (Ollama) の VEX-triage 品質を 20 件の eval-set で
比較します。既定は SBOMHUB_BENCH_MODE=binary です。

前提 / Prerequisites:
  - binary mode は GitHub Release から llm-bench archive を download し、
    ~/.cache/sbomhub-cli/llm-bench/<version>-<os>-<arch>/ に cache します
    Binary mode downloads the pre-built llm-bench archive from GitHub
    Releases and caches it under ~/.cache/sbomhub-cli/llm-bench/...
  - offline / air-gapped では --bench-binary <path> で manual binary を指定
    Use --bench-binary <path> to bypass download/cache in offline or
    air-gapped environments
  - source mode が必要な場合は SBOMHUB_BENCH_MODE=source を指定し、
    sbomhub OSS source を --sbomhub-source / SBOMHUB_SOURCE / ./sbomhub で渡します
    Set SBOMHUB_BENCH_MODE=source to keep the old source checkout +
    ` + "`go build`" + ` path
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
  SBOMHUB_BENCH_VERSION=v1.4.1 sbomhub llm bench --max-cases 10
  sbomhub llm bench --bench-binary /opt/sbomhub/llm-bench
  SBOMHUB_BENCH_MODE=source sbomhub llm bench --sbomhub-source ../sbomhub

Exit codes (wrapper preflight + M4-3 F42 typed pass-through):
  0  正常終了 / success
  2  usage / flag validation failure (forwarded from M4-3)
  3  恒久エラー / permanent — wrapper preflight (download/cache/checksum /
     sbomhub source 不在 / eval-set 不在 / Go toolchain 不在 /
     ` + "`go build`" + ` 失敗 / launch failure)、 M4-3 の fixture / config
     validation、 もしくは M4-3 binary が documented contract 外の exit
     code を emit した場合の正規化 (F57)
  4  no providers configured (forwarded from M4-3 — set BYOK env or
     drop the missing provider from --providers) — または wrapper
     subprocess の signal-killed / abnormal termination
  5  execution / output failure (forwarded from M4-3 — likely
     transient provider outage、 retry recommended)

M4 Codex review #F46: codes 2/3/4/5 are forwarded verbatim from the
M4-3 bench binary so CI pipelines can distinguish "no providers
configured" (4) from "provider execution failure" (5).
M4 Codex review #F57: codes OUTSIDE 2/3/4/5 are renormalised to
exit 3 so the documented contract (0/2/3/4/5) is never silently
widened; the captured bench-binary stderr is quoted in the
wrapper's error message.
M4 Codex review #F61: the M4-3 binary is compiled via ` + "`go build`" + `
into a temp dir and exec'd directly, so its exit code is forwarded
verbatim per F46. The pre-F61 ` + "`go run`" + ` path always returned exit 1
on inner failure regardless of the inner os.Exit(N), silently
masking the M4-3 F42 typed contract — CI saw exit 3 (F57 contract
violation) instead of the real M4-3 code.`,
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
	llmBenchCmd.Flags().StringVar(&llmBenchBinary, "bench-binary", "",
		"download/cache を bypass して実行する llm-bench binary path / manual llm-bench binary path (bypasses download/cache)")
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
			"connectivity":  "ok",
			"api_url":       baseURL,
			"status":        res.Status,
			"mode":          res.Mode,
			"provider":      res.Provider,
			"model":         res.Model,
			"llm_connected": nil,
			"llm_reason":    res.Reason,
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
// Selects binary/source mode, resolves --eval-set, and execs the
// M4-3 bench harness. Stdout / stderr stream through so the operator
// sees JSONL + (optional) markdown table without any CLI buffering.
//
// The wrapper does NOT parse or rewrite the M4-3 output — that
// would duplicate the M4-3 semantics in the CLI and force the
// wrapper to be redeployed whenever the bench schema evolves.
// Pass-through is the explicit design choice for Option A.
func runLLMBench(cmd *cobra.Command, args []string) error {
	out := GetOutputConfig()

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

	mode := resolveBenchMode(os.Getenv("SBOMHUB_BENCH_MODE"))
	switch mode {
	case "binary":
		return runLLMBenchBinaryMode(cmd, out)
	case "source":
		return runLLMBenchSourceMode(cmd, out)
	default:
		return &llmExitError{
			code: 3,
			msg:  fmt.Sprintf("SBOMHUB_BENCH_MODE must be binary or source (got %q)", mode),
		}
	}
}

func runLLMBenchSourceMode(cmd *cobra.Command, out *OutputConfig) error {
	source, err := resolveSbomhubSource(llmBenchSbomhubSource)
	if err != nil {
		return &llmExitError{code: 3, msg: err.Error()}
	}

	evalSetPath, err := resolveEvalSetPath(llmBenchEvalSet, source)
	if err != nil {
		return &llmExitError{code: 3, msg: err.Error()}
	}

	// `go` toolchain pre-flight. Surfacing this before we exec gives
	// a friendlier error than the bare "executable file not found"
	// from os/exec. ENOENT here is permanent (operator must install
	// Go) so we map to exit-3.
	if _, lookErr := exec.LookPath("go"); lookErr != nil {
		return &llmExitError{
			code: 3,
			msg: fmt.Sprintf("`go` toolchain が見つかりません: %v\n"+
				"  SBOMHUB_BENCH_MODE=source は sbomhub source の M4-3 bench を `go build` してから実行します。\n"+
				"  Install Go from https://go.dev/dl/ and ensure `go` is in PATH.",
				lookErr),
		}
	}

	// M4 Codex review #F61 fix: compile the M4-3 binary with
	// `go build` into a per-invocation temp dir, then exec the
	// resulting binary directly so exec.ExitError.ExitCode()
	// reflects the actual M4-3 F42 typed exit-code contract
	// (2/3/4/5).
	//
	// Pre-F61 the wrapper used `go run ./cmd/llm-bench`. That
	// path always returned exit 1 from the `go` driver on inner
	// failure regardless of the inner os.Exit(N) value — silently
	// masking M4-3's typed contract and forcing the F57 contract-
	// violation branch (→ wrapper exit 3) to fire even when M4-3
	// emitted a perfectly valid exit 4 ("no providers"). The
	// build+exec split restores F46 transparent pass-through.
	//
	// Trade-offs vs the pre-F61 `go run` approach:
	//   1. Adds an explicit `go build` step that writes into a
	//      temp dir (cleaned up by defer). No artefact is left in
	//      the operator's tree.
	//   2. Cold-cache first runs add a few seconds for compile;
	//      second-and-later invocations are effectively free thanks
	//      to Go's build cache ($GOCACHE).
	//   3. Operators can correlate `wrapper exit N` with the
	//      M4-3-documented exit-code table directly, without the
	//      pre-F61 "wrapper says exit 3 but bench printed exit 4"
	//      confusion.
	benchArgs := buildLLMBenchArgs(evalSetPath)

	// M4-3 binary lives under apps/api/cmd/llm-bench so the
	// working directory for `go build` and the subsequent exec is
	// apps/api (where the containing go.mod lives).
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

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Step 1 (F61): compile the M4-3 bench binary into a temp dir.
	// On build failure we surface exit 3 with the captured `go
	// build` stderr embedded, mirroring the F57 contract for the
	// exec step. The temp dir is unconditionally cleaned up via
	// defer regardless of whether build / exec succeeds.
	tmpDir, mkErr := os.MkdirTemp("", "sbomhub-llm-bench-*")
	if mkErr != nil {
		return &llmExitError{
			code: 3,
			msg:  fmt.Sprintf("llm bench 一時ディレクトリ作成に失敗: %v", mkErr),
		}
	}
	defer os.RemoveAll(tmpDir)
	benchBin := filepath.Join(tmpDir, "llm-bench")
	if runtime.GOOS == "windows" {
		benchBin += ".exe"
	}

	// -buildvcs=false avoids "error obtaining VCS status: exit
	// status 128" when the sbomhub source is a git checkout whose
	// ownership does not match the running uid (most commonly when
	// the operator mounts a host clone into a docker container —
	// host uid != container uid triggers git's safe.directory
	// check, fails the VCS stamp, and aborts the otherwise-clean
	// build). We do not need VCS metadata stamped into a
	// throwaway bench binary, so disabling the stamp is cheap.
	buildStderr := &cappedBuffer{limit: mapBenchStderrCaptureLimit}
	buildCmd := exec.CommandContext(ctx, "go", "build", "-buildvcs=false", "-o", benchBin, "./cmd/llm-bench")
	buildCmd.Dir = workDir
	// Route build-phase chatter (module download progress, compiler
	// diagnostics) to stderr so stdout stays exclusively reserved
	// for the eventual JSONL the operator pipes into jq.
	buildCmd.Stdout = out.ErrWriter
	buildCmd.Stderr = io.MultiWriter(out.ErrWriter, buildStderr)
	// Inherit env so $GOCACHE / $GOMODCACHE / GOPROXY / GOTOOLCHAIN
	// honour whatever the operator already configured.
	buildCmd.Env = os.Environ()

	if out.IsVerbose() {
		fmt.Fprintf(out.ErrWriter, "[DEBUG] cd %s && go build -buildvcs=false -o %s ./cmd/llm-bench\n", workDir, benchBin)
	}

	if buildErr := buildCmd.Run(); buildErr != nil {
		snippet := summariseStderrTail(buildStderr.Bytes())
		msg := fmt.Sprintf(
			"llm bench compile failure (`go build ./cmd/llm-bench`): %v",
			buildErr)
		if snippet != "" {
			msg += "\n  stderr (truncated):\n" + snippet
		}
		return &llmExitError{code: 3, msg: msg}
	}

	// Step 2 (F61): exec the built binary directly so its
	// ExitCode() is the actual M4-3 F42 contract code. JSONL
	// lands on stdout (M4-3 default) so jq pipelines keep
	// working; markdown + per-case slog warnings land on stderr.
	//
	// M4 Codex review #F57: tee stderr into a bounded buffer so
	// the wrapper can quote the bench binary's complaint when it
	// exits with a code OUTSIDE the M4-3 typed contract band.
	// The cap is kept small (mapBenchStderrCaptureLimit) so a
	// runaway slog stream cannot inflate CLI memory; on-screen
	// output is unaffected because we keep streaming through
	// io.MultiWriter.
	if out.IsVerbose() {
		fmt.Fprintf(out.ErrWriter, "[DEBUG] cd %s && %s %s\n", workDir, benchBin, strings.Join(benchArgs, " "))
	}

	return execLLMBenchBinary(ctx, out, benchBin, workDir, benchArgs)
}

func runLLMBenchBinaryMode(cmd *cobra.Command, out *OutputConfig) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	benchBin := strings.TrimSpace(llmBenchBinary)
	var workDir string
	if benchBin != "" {
		abs, err := filepath.Abs(benchBin)
		if err != nil {
			return &llmExitError{code: 3, msg: fmt.Sprintf("--bench-binary の絶対パス解決に失敗: %v", err)}
		}
		info, err := os.Stat(abs)
		if err != nil {
			return &llmExitError{code: 3, msg: fmt.Sprintf("--bench-binary が見つかりません (%s): %v", abs, err)}
		}
		if info.IsDir() {
			return &llmExitError{code: 3, msg: fmt.Sprintf("--bench-binary は file を指定してください: %s", abs)}
		}
		benchBin = abs
		workDir = filepath.Dir(abs)
	} else {
		resolved, err := ensureCachedLLMBenchBinary(ctx, out)
		if err != nil {
			return &llmExitError{code: 3, msg: err.Error()}
		}
		benchBin = resolved.BinaryPath
		workDir = resolved.WorkDir
	}

	evalSetPath, err := resolveBinaryEvalSetPath(llmBenchEvalSet, workDir)
	if err != nil {
		return &llmExitError{code: 3, msg: err.Error()}
	}

	return execLLMBenchBinary(ctx, out, benchBin, workDir, buildLLMBenchArgs(evalSetPath))
}

func resolveBenchMode(raw string) string {
	mode := strings.ToLower(strings.TrimSpace(raw))
	if mode == "" {
		return "binary"
	}
	return mode
}

func buildLLMBenchArgs(evalSetPath string) []string {
	benchArgs := []string{
		"--providers", llmBenchProviders,
		"--eval-set", evalSetPath,
		"--max-cases", fmt.Sprintf("%d", llmBenchMaxCases),
		"--timeout", fmt.Sprintf("%d", llmBenchTimeoutSec),
	}
	if llmBenchOut != "" {
		benchArgs = append(benchArgs, "--out", llmBenchOut)
	}
	if llmBenchMarkdown {
		benchArgs = append(benchArgs, "--markdown")
	}
	return benchArgs
}

func execLLMBenchBinary(ctx context.Context, out *OutputConfig, benchBin, workDir string, benchArgs []string) error {
	if out.IsVerbose() {
		fmt.Fprintf(out.ErrWriter, "[DEBUG] cd %s && %s %s\n", workDir, benchBin, strings.Join(benchArgs, " "))
	}

	execStderr := &cappedBuffer{limit: mapBenchStderrCaptureLimit}
	execCmd := exec.CommandContext(ctx, benchBin, benchArgs...)
	execCmd.Dir = workDir
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = out.Writer
	execCmd.Stderr = io.MultiWriter(out.ErrWriter, execStderr)
	execCmd.Env = os.Environ()

	if runErr := execCmd.Run(); runErr != nil {
		return mapBenchSubprocessError(runErr, execStderr.Bytes())
	}
	return nil
}

type llmBenchCachedBinary struct {
	BinaryPath string
	WorkDir    string
}

type llmBenchReleaseTarget struct {
	Tag      string
	OS       string
	Arch     string
	Ext      string
	FileName string
}

func ensureCachedLLMBenchBinary(ctx context.Context, out *OutputConfig) (llmBenchCachedBinary, error) {
	target, err := resolveLLMBenchReleaseTarget(ctx)
	if err != nil {
		return llmBenchCachedBinary{}, err
	}
	cacheDir, err := llmBenchCacheDir(target)
	if err != nil {
		return llmBenchCachedBinary{}, err
	}
	binaryPath := filepath.Join(cacheDir, llmBenchBinaryName(target.OS))
	checksumPath := filepath.Join(cacheDir, ".archive.sha256")

	checksums, err := fetchLLMBenchChecksums(ctx, target)
	if err != nil {
		if isExecutableFile(binaryPath) {
			fmt.Fprintf(out.ErrWriter, "warning: llm-bench checksums.txt fetch failed; using existing cached binary %s: %v\n", binaryPath, err)
			return llmBenchCachedBinary{BinaryPath: binaryPath, WorkDir: cacheDir}, nil
		}
		return llmBenchCachedBinary{}, err
	}
	wantChecksum, ok := checksums[target.FileName]
	if !ok {
		return llmBenchCachedBinary{}, fmt.Errorf("checksums.txt does not contain %s", target.FileName)
	}

	if isExecutableFile(binaryPath) {
		if cached, readErr := os.ReadFile(checksumPath); readErr == nil && strings.EqualFold(strings.TrimSpace(string(cached)), wantChecksum) {
			return llmBenchCachedBinary{BinaryPath: binaryPath, WorkDir: cacheDir}, nil
		}
		fmt.Fprintf(out.ErrWriter, "warning: llm-bench cache checksum mismatch for %s; re-downloading\n", binaryPath)
		_ = os.RemoveAll(cacheDir)
	}

	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return llmBenchCachedBinary{}, fmt.Errorf("llm-bench cache directory creation failed: %w", err)
	}
	archiveURL := llmBenchArchiveURL(target)
	archiveBytes, gotChecksum, err := downloadLLMBenchArchive(ctx, archiveURL)
	if err != nil {
		return llmBenchCachedBinary{}, err
	}
	if !strings.EqualFold(gotChecksum, wantChecksum) {
		_ = os.RemoveAll(cacheDir)
		return llmBenchCachedBinary{}, fmt.Errorf("llm-bench archive checksum mismatch for %s: got %s, want %s", target.FileName, gotChecksum, wantChecksum)
	}
	if err := extractLLMBenchArchive(archiveBytes, target, cacheDir); err != nil {
		_ = os.RemoveAll(cacheDir)
		return llmBenchCachedBinary{}, err
	}
	if !isExecutableFile(binaryPath) {
		_ = os.RemoveAll(cacheDir)
		return llmBenchCachedBinary{}, fmt.Errorf("llm-bench archive did not contain executable %s", llmBenchBinaryName(target.OS))
	}
	if err := os.WriteFile(checksumPath, []byte(wantChecksum+"\n"), 0o644); err != nil {
		return llmBenchCachedBinary{}, fmt.Errorf("llm-bench checksum marker write failed: %w", err)
	}
	return llmBenchCachedBinary{BinaryPath: binaryPath, WorkDir: cacheDir}, nil
}

func resolveLLMBenchReleaseTarget(ctx context.Context) (llmBenchReleaseTarget, error) {
	tag, err := resolveLLMBenchVersion(ctx)
	if err != nil {
		return llmBenchReleaseTarget{}, err
	}
	osName, arch, err := llmBenchPlatform(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return llmBenchReleaseTarget{}, err
	}
	ext := ".tar.gz"
	if osName == "windows" {
		ext = ".zip"
	}
	fileName := fmt.Sprintf("llm-bench-%s-%s-%s%s", tag, osName, arch, ext)
	return llmBenchReleaseTarget{Tag: tag, OS: osName, Arch: arch, Ext: ext, FileName: fileName}, nil
}

func resolveLLMBenchVersion(ctx context.Context) (string, error) {
	if env := strings.TrimSpace(os.Getenv("SBOMHUB_BENCH_VERSION")); env != "" {
		return normaliseLLMBenchTag(env), nil
	}
	if self := strings.TrimSpace(version); self != "" && self != "dev" {
		return normaliseLLMBenchTag(self), nil
	}
	return fetchLatestLLMBenchTag(ctx)
}

func normaliseLLMBenchTag(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}

func fetchLatestLLMBenchTag(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, llmBenchLatestReleaseAPIURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	res, err := llmBenchHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("GitHub latest release lookup failed: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", fmt.Errorf("GitHub latest release lookup failed: HTTP %d", res.StatusCode)
	}
	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("GitHub latest release JSON parse failed: %w", err)
	}
	tag := normaliseLLMBenchTag(payload.TagName)
	if tag == "" {
		return "", errors.New("GitHub latest release did not include tag_name")
	}
	return tag, nil
}

func llmBenchPlatform(goos, goarch string) (string, string, error) {
	switch goos {
	case "linux", "darwin", "windows":
	default:
		return "", "", fmt.Errorf("unsupported llm-bench OS %q (supported: linux, darwin, windows)", goos)
	}
	switch goarch {
	case "amd64", "arm64":
	default:
		return "", "", fmt.Errorf("unsupported llm-bench arch %q (supported: amd64, arm64)", goarch)
	}
	return goos, goarch, nil
}

func llmBenchCacheDir(target llmBenchReleaseTarget) (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("user cache directory resolution failed: %w", err)
	}
	return filepath.Join(base, "sbomhub-cli", "llm-bench", fmt.Sprintf("%s-%s-%s", target.Tag, target.OS, target.Arch)), nil
}

func llmBenchArchiveURL(target llmBenchReleaseTarget) string {
	base := strings.TrimRight(llmBenchReleaseDownloadBaseURL, "/")
	return base + "/" + url.PathEscape(target.Tag) + "/" + url.PathEscape(target.FileName)
}

func llmBenchChecksumsURL(target llmBenchReleaseTarget) string {
	base := strings.TrimRight(llmBenchReleaseDownloadBaseURL, "/")
	return base + "/" + url.PathEscape(target.Tag) + "/checksums.txt"
}

func fetchLLMBenchChecksums(ctx context.Context, target llmBenchReleaseTarget) (map[string]string, error) {
	body, err := httpGetBytes(ctx, llmBenchChecksumsURL(target))
	if err != nil {
		return nil, fmt.Errorf("llm-bench checksums.txt download failed: %w", err)
	}
	checksums := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		sum := strings.ToLower(fields[0])
		name := strings.TrimPrefix(fields[len(fields)-1], "*")
		if _, err := hex.DecodeString(sum); err != nil || len(sum) != sha256.Size*2 {
			continue
		}
		checksums[filepath.Base(name)] = sum
	}
	if len(checksums) == 0 {
		return nil, errors.New("checksums.txt did not contain SHA-256 entries")
	}
	return checksums, nil
}

func downloadLLMBenchArchive(ctx context.Context, archiveURL string) ([]byte, string, error) {
	body, err := httpGetBytes(ctx, archiveURL)
	if err != nil {
		return nil, "", fmt.Errorf("llm-bench archive download failed: %w", err)
	}
	sum := sha256.Sum256(body)
	return body, hex.EncodeToString(sum[:]), nil
}

func httpGetBytes(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	res, err := llmBenchHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s: HTTP %d", rawURL, res.StatusCode)
	}
	return io.ReadAll(res.Body)
}

func extractLLMBenchArchive(archiveBytes []byte, target llmBenchReleaseTarget, destDir string) error {
	if target.OS == "windows" {
		return extractLLMBenchZip(archiveBytes, destDir)
	}
	return extractLLMBenchTarGz(archiveBytes, destDir)
}

func extractLLMBenchTarGz(archiveBytes []byte, destDir string) error {
	gz, err := gzip.NewReader(bytes.NewReader(archiveBytes))
	if err != nil {
		return fmt.Errorf("open tar.gz: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar.gz: %w", err)
		}
		if header == nil {
			continue
		}
		targetPath, err := safeArchivePath(destDir, header.Name)
		if err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(header.Mode) & 0o777
			if mode == 0 {
				mode = 0o644
			}
			f, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		}
	}
}

func extractLLMBenchZip(archiveBytes []byte, destDir string) error {
	zr, err := zip.NewReader(bytes.NewReader(archiveBytes), int64(len(archiveBytes)))
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	for _, zf := range zr.File {
		targetPath, err := safeArchivePath(destDir, zf.Name)
		if err != nil {
			return err
		}
		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return err
		}
		src, err := zf.Open()
		if err != nil {
			return err
		}
		mode := zf.Mode() & 0o777
		if mode == 0 {
			mode = 0o644
		}
		dst, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			_ = src.Close()
			return err
		}
		if _, err := io.Copy(dst, src); err != nil {
			_ = src.Close()
			_ = dst.Close()
			return err
		}
		if err := src.Close(); err != nil {
			_ = dst.Close()
			return err
		}
		if err := dst.Close(); err != nil {
			return err
		}
	}
	return nil
}

func safeArchivePath(destDir, name string) (string, error) {
	clean := filepath.Clean(name)
	if clean == "." || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return "", fmt.Errorf("unsafe path in llm-bench archive: %s", name)
	}
	targetPath := filepath.Join(destDir, clean)
	destClean := filepath.Clean(destDir) + string(filepath.Separator)
	targetClean := filepath.Clean(targetPath)
	if !strings.HasPrefix(targetClean, destClean) && targetClean != filepath.Clean(destDir) {
		return "", fmt.Errorf("unsafe path in llm-bench archive: %s", name)
	}
	return targetPath, nil
}

func resolveBinaryEvalSetPath(flagValue, workDir string) (string, error) {
	path := strings.TrimSpace(flagValue)
	if path == "" {
		path = filepath.Join(workDir, "fixtures", "llm-bench", "cve-20-50.json")
	} else if !filepath.IsAbs(path) {
		path = filepath.Join(workDir, path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("--eval-set の絶対パス解決に失敗: %w", err)
	}
	if _, err := os.Stat(abs); err != nil {
		return "", fmt.Errorf("eval-set fixture が見つかりません (%s): %w\n"+
			"  binary mode では archive 同梱 fixtures/llm-bench/cve-20-50.json を既定で使います。\n"+
			"  Pass --eval-set <path> to point at a custom fixture or verify the llm-bench archive/manual binary directory",
			abs, err)
	}
	return abs, nil
}

func llmBenchBinaryName(goos string) string {
	if goos == "windows" {
		return "llm-bench.exe"
	}
	return "llm-bench"
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode()&0o111 != 0
}

// mapBenchStderrCaptureLimit caps how much subprocess stderr we
// retain for the F57 contract-violation error message. 8 KiB is
// enough to fit a typical Go toolchain error
// ("go: go.mod requires go >= 1.25.0 (running go 1.22.12; ...)")
// + several frames of compile-error context, while keeping CLI
// memory bounded even under a runaway slog burst. The same cap is
// reused for the F61 `go build` stderr buffer in runLLMBench.
const mapBenchStderrCaptureLimit = 8 * 1024

// mapBenchM4ContractMin / mapBenchM4ContractMax bracket the M4-3
// F42 typed exit-code contract surface (2/3/4/5 inclusive). Codes
// inside this band are forwarded verbatim per F46; codes OUTSIDE
// the band are re-normalised to exit 3 by F57 with the captured
// stderr quoted in the error message so operators do not have to
// re-run to learn what the subprocess complained about.
//
// Post-F61 the bench binary is exec'd directly (no `go run`
// wrapper), so this branch fires only when the M4-3 binary itself
// emits an undocumented exit code — not the routine
// `go run`-masked exit 1 it fired against pre-F61.
const (
	mapBenchM4ContractMin = 2
	mapBenchM4ContractMax = 5
)

// cappedBuffer is an io.Writer that retains at most `limit` bytes,
// silently discarding the tail. Used to give mapBenchSubprocessError
// the recent stderr context without exposing the CLI to memory
// inflation if the subprocess emits an unbounded slog stream
// before failing.
type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

// Write implements io.Writer. Once `limit` bytes are buffered any
// further writes are dropped — the operator-visible stream is the
// MultiWriter sibling (the OutputConfig.ErrWriter), so this buffer
// only exists to be quoted on subprocess failure.
func (c *cappedBuffer) Write(p []byte) (int, error) {
	remaining := c.limit - c.buf.Len()
	if remaining <= 0 {
		return len(p), nil
	}
	if len(p) > remaining {
		c.buf.Write(p[:remaining])
		return len(p), nil
	}
	c.buf.Write(p)
	return len(p), nil
}

// Bytes returns the captured slice. Safe to call after the
// underlying subprocess has exited; the returned slice is not
// mutated by subsequent Write calls (because writes after the cap
// is reached are dropped).
func (c *cappedBuffer) Bytes() []byte {
	return c.buf.Bytes()
}

// mapBenchSubprocessError translates the error returned by
// execCmd.Run() into the llmExitError envelope that main.go's
// exitCoder hook will surface to the OS.
//
// M4 Codex review #F46 fix — option (a) transparent pass-through:
// for *exec.ExitError we forward the M4-3 typed contract code
// (2 usage / 3 config / 4 no providers / 5 execution) verbatim so
// CI can branch on the underlying cause. Negative exit codes
// (signal-killed / aborted before exit) map to 4 (retryable
// default). Non-ExitError values (launch failure — `go` binary
// missing, fork failure) map to 3 because the operator must fix
// the local environment before re-running.
//
// M4 Codex review #F57 fix — contract-band normalisation: exit
// codes OUTSIDE the documented M4-3 surface are re-mapped to
// exit 3 with the captured stderr quoted into the error message.
// Pre-F57 the wrapper forwarded the bare code verbatim, which
// silently widened the documented `llm bench` contract (README
// + --help promise 0/2/3/4/5) and meant CI pipelines branching
// on the contract could not distinguish "bench launch failure"
// from a future M4-3 widening — an undocumented code would just
// leak through with no hint at the cause. The bytes captured by
// runLLMBench's io.MultiWriter tee are quoted (truncated to
// fit) so operators see the underlying complaint directly.
//
// M4 Codex review #F61 (round 6): post-fix this branch fires
// only for true contract violations from the M4-3 binary
// itself. Pre-F61 it fired routinely because the wrapper
// shelled out via `go run`, which always exits 1 on inner
// failure regardless of the inner os.Exit(N). The build+exec
// split in runLLMBench means exec.ExitError.ExitCode() now
// reflects the actual M4-3 F42 code, so the 2/3/4/5 band
// pass-through (F46) holds in production.
//
// Factored out of runLLMBench so unit tests can drive synthetic
// *exec.ExitError values (sh -c "exit N") without a populated
// sbomhub OSS checkout. stderrTail may be nil for tests that do
// not exercise the F57 path.
func mapBenchSubprocessError(runErr error, stderrTail []byte) *llmExitError {
	if runErr == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		subExit := exitErr.ExitCode()
		if subExit < 0 {
			// Signal-killed or aborted before producing a typed
			// exit code (CTRL-C, OOM, parent context cancel). The
			// operator's usual next step is "retry", so we default
			// to 4 (transient-leaning) rather than 3 (permanent).
			// ※要確認: signal=SIGKILL by OOM-killer is arguably
			// permanent (operator must add RAM); we still pick 4
			// because the M1/F21 convention treats "no typed exit
			// code" as transient and operators have learned that
			// mapping.
			return &llmExitError{
				code: 4,
				msg: fmt.Sprintf("llm bench abnormally terminated (signal / no exit code): %v",
					runErr),
			}
		}
		// M4 Codex review #F57: only forward codes inside the
		// documented M4-3 typed contract band. Codes outside are
		// renormalised to exit 3 (permanent — operator must fix
		// env) and quote the captured stderr so the underlying
		// complaint reaches the operator without a second run.
		// Without this clamp, undocumented codes would leak through
		// and CI pipelines branching on the published 0/2/3/4/5
		// contract could not route them correctly.
		//
		// M4 Codex review #F61: post-fix this branch fires only
		// when the M4-3 binary itself emits an undocumented code
		// (compile errors are caught by the `go build` preflight
		// in runLLMBench, which returns exit 3 before reaching
		// this mapper). The error message is generalised so the
		// post-F61 reader is not misled into thinking `go run` is
		// still in use.
		if subExit < mapBenchM4ContractMin || subExit > mapBenchM4ContractMax {
			snippet := summariseStderrTail(stderrTail)
			msg := fmt.Sprintf(
				"llm bench launch/compile failure: subprocess exited %d (outside the documented M4-3 contract %d-%d). "+
					"The bench binary emitted an exit code that is not part of the M4-3 F42 typed contract (2=usage / 3=config / 4=no providers / 5=execution failure); "+
					"see the captured stderr below for the underlying complaint.",
				subExit, mapBenchM4ContractMin, mapBenchM4ContractMax)
			if snippet != "" {
				msg += "\n  stderr (truncated):\n" + snippet
			}
			return &llmExitError{code: 3, msg: msg}
		}
		// Forward M4-3 (sbomhub apps/api/cmd/llm-bench) F42 typed
		// contract verbatim: 2=usage / 3=config / 4=no providers /
		// 5=execution. The wrapper does not re-interpret these
		// codes — see the file-header ※要確認 for the option
		// (a) vs (c) trade-off rationale.
		return &llmExitError{
			code: subExit,
			msg: fmt.Sprintf("llm bench exited with code %d — see sbomhub M4-3 doc "+
				"(apps/api/cmd/llm-bench) for the typed exit-code contract "+
				"(2=usage / 3=config / 4=no providers / 5=execution failure)",
				subExit),
		}
	}
	// Non-ExitError = launch failure (file not found, fork
	// failure). Permanent — operator must fix env.
	return &llmExitError{
		code: 3,
		msg:  fmt.Sprintf("llm bench 起動失敗: %v", runErr),
	}
}

// summariseStderrTail trims a captured stderr slice for inclusion
// in the F57 error message. Returns an empty string when there's
// nothing useful (e.g. tests that did not tee anything in) so the
// message stays clean. Indents every line so the embedded snippet
// is visually distinct from the surrounding wrapper text.
func summariseStderrTail(tail []byte) string {
	trimmed := strings.TrimSpace(string(tail))
	if trimmed == "" {
		return ""
	}
	var b strings.Builder
	for _, line := range strings.Split(trimmed, "\n") {
		b.WriteString("    ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
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
