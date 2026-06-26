package commands

// Unit tests for `sbomhub llm test` / `sbomhub llm bench` —
// exercises each subcommand's UX + exit-code classification + flag
// validation. Tests are keyed off the same M1/M2/M3 fix-pattern
// numbers as the cra_test.go / meti_test.go regressions so a
// reviewer can trace each rule end-to-end:
//
//   - F21 exit code 3 (permanent) / 4 (transient)
//   - F22 strict 503 AI-disabled detection (BYOK marker vs generic
//         gateway 503)
//   - F23 2xx contract validation (no status field → transient)
//
// The bench harness is exercised via the path-resolution helpers
// (resolveSbomhubSource / resolveEvalSetPath) — the actual `go run`
// subprocess is NOT spawned in tests because that would require a
// populated sbomhub OSS checkout in the test fixture (out of scope
// for a CLI-level unit test). Integration coverage lives in the
// sbomhub repo's M4-3 cmd/llm-bench harness.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/youichi-uda/sbomhub-cli/internal/api"
)

// ---------------------------------------------------------------------------
// Fake server harness
// ---------------------------------------------------------------------------

type llmFakeServer struct {
	t          *testing.T
	server     *httptest.Server
	healthResp func(r *http.Request) (status int, payload interface{}, raw string)
	hits       int
}

func newLLMFakeServer(t *testing.T) *llmFakeServer {
	t.Helper()
	tf := &llmFakeServer{t: t}
	tf.server = httptest.NewServer(http.HandlerFunc(tf.handle))
	t.Cleanup(tf.server.Close)
	return tf
}

func (tf *llmFakeServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/health" {
		tf.t.Errorf("unexpected path %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	tf.hits++
	status := http.StatusOK
	var payload interface{}
	var raw string
	if tf.healthResp != nil {
		status, payload, raw = tf.healthResp(r)
	} else {
		payload = map[string]string{"status": "ok", "mode": "byok"}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if raw != "" {
		_, _ = io.WriteString(w, raw)
		return
	}
	if payload != nil {
		_ = json.NewEncoder(w).Encode(payload)
	}
}

// ---------------------------------------------------------------------------
// llm test — runLLMTestWith helper that mirrors runLLMTest's body
// without leaking package-scoped flag globals between tests
// ---------------------------------------------------------------------------

type llmTestArgs struct {
	provider string
}

type llmTestResult struct {
	err error
}

// runLLMTestAndCapture replays the runLLMTest body using an
// injected client + buffered OutputConfig so the test does not have
// to leak globals. Mirrors the M3 meti_test pattern.
func runLLMTestAndCapture(t *testing.T, client *api.Client, apiURL string, args llmTestArgs, jsonOutput bool) (llmTestResult, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	out := &OutputConfig{Writer: &stdout, ErrWriter: &stderr, JSON: jsonOutput}

	if strings.TrimSpace(args.provider) != "" {
		// Mirror runLLMTest's stderr notice for the advisory flag.
		// We don't assert on it but tests can inspect stderr if
		// they want to.
		_, _ = stderr.WriteString("注: --provider hint received\n")
	}

	res, err := client.Health(context.Background())
	if err != nil {
		return llmTestResult{err: llmHealthFailureToExitError("llm test", err)}, &stdout, &stderr
	}
	if err := renderLLMTest(out, res, apiURL); err != nil {
		return llmTestResult{err: err}, &stdout, &stderr
	}
	return llmTestResult{}, &stdout, &stderr
}

// TestLLMTest_HappyPath_MinimalServer — current server shape
// ({status, mode}) should render human-readable output with N/A
// for the unpublished provider/model.
func TestLLMTest_HappyPath_MinimalServer(t *testing.T) {
	tf := newLLMFakeServer(t)
	tf.healthResp = func(r *http.Request) (int, interface{}, string) {
		return http.StatusOK, map[string]string{"status": "ok", "mode": "byok"}, ""
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, stdout, _ := runLLMTestAndCapture(t, client, tf.server.URL, llmTestArgs{}, false)
	if res.err != nil {
		t.Fatalf("llm test err: %v", res.err)
	}
	out := stdout.String()
	if !strings.Contains(out, "API URL") {
		t.Errorf("stdout missing API URL line: %s", out)
	}
	if !strings.Contains(out, "byok") {
		t.Errorf("stdout missing mode: %s", out)
	}
	if !strings.Contains(out, "N/A") {
		t.Errorf("stdout should render N/A for unpublished provider: %s", out)
	}
	if tf.hits != 1 {
		t.Errorf("expected 1 health hit, got %d", tf.hits)
	}
}

// TestLLMTest_HappyPath_JSONOutput — --json mode should emit a
// machine-readable payload with the connectivity flag and the
// nullable LLM fields.
func TestLLMTest_HappyPath_JSONOutput(t *testing.T) {
	tf := newLLMFakeServer(t)
	connected := true
	tf.healthResp = func(r *http.Request) (int, interface{}, string) {
		return http.StatusOK, map[string]interface{}{
			"status":    "ok",
			"mode":      "byok",
			"provider":  "ollama",
			"model":     "qwen2.5-coder:7b",
			"connected": connected,
		}, ""
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, stdout, _ := runLLMTestAndCapture(t, client, tf.server.URL, llmTestArgs{}, true)
	if res.err != nil {
		t.Fatalf("llm test err: %v", res.err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("JSON parse: %v\n%s", err, stdout.String())
	}
	if got, _ := payload["connectivity"].(string); got != "ok" {
		t.Errorf("connectivity = %v, want ok", payload["connectivity"])
	}
	if got, _ := payload["provider"].(string); got != "ollama" {
		t.Errorf("provider = %v, want ollama", payload["provider"])
	}
	if got, _ := payload["llm_connected"].(bool); !got {
		t.Errorf("llm_connected = %v, want true", payload["llm_connected"])
	}
}

// TestLLMTest_PermanentExit3_F21 — 401 must classify permanent.
func TestLLMTest_PermanentExit3_F21(t *testing.T) {
	tf := newLLMFakeServer(t)
	tf.healthResp = func(r *http.Request) (int, interface{}, string) {
		return http.StatusUnauthorized, map[string]string{"error": "invalid api key"}, ""
	}
	client := api.NewClient(tf.server.URL, "k")
	res, _, _ := runLLMTestAndCapture(t, client, tf.server.URL, llmTestArgs{}, false)
	exitErr, ok := res.err.(*llmExitError)
	if !ok {
		t.Fatalf("F21: err = %v (%T), want *llmExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("F21: ExitCode = %d, want 3 (401 permanent)", exitErr.ExitCode())
	}
}

// TestLLMTest_TransientExit4_503Generic_F22 — a generic 503 with no
// AI-disabled marker must surface as transient (gateway outage).
func TestLLMTest_TransientExit4_503Generic_F22(t *testing.T) {
	tf := newLLMFakeServer(t)
	tf.healthResp = func(r *http.Request) (int, interface{}, string) {
		return http.StatusServiceUnavailable, nil, "<html>503 Service Unavailable</html>"
	}
	client := api.NewClient(tf.server.URL, "k")
	res, _, _ := runLLMTestAndCapture(t, client, tf.server.URL, llmTestArgs{}, false)
	exitErr, ok := res.err.(*llmExitError)
	if !ok {
		t.Fatalf("F22: err = %v (%T), want *llmExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 4 {
		t.Errorf("F22: ExitCode = %d, want 4 (generic 503 = transient outage)", exitErr.ExitCode())
	}
}

// TestLLMTest_PermanentExit3_503AIDisabled_F22 — a 503 with a
// recognised BYOK-not-configured marker must surface as permanent
// (operator must configure BYOK, not retry).
func TestLLMTest_PermanentExit3_503AIDisabled_F22(t *testing.T) {
	tf := newLLMFakeServer(t)
	tf.healthResp = func(r *http.Request) (int, interface{}, string) {
		return http.StatusServiceUnavailable,
			map[string]string{"error": "BYOK key not configured", "reason": "BYOK key not configured"},
			""
	}
	client := api.NewClient(tf.server.URL, "k")
	res, _, _ := runLLMTestAndCapture(t, client, tf.server.URL, llmTestArgs{}, false)
	exitErr, ok := res.err.(*llmExitError)
	if !ok {
		t.Fatalf("F22: err = %v (%T), want *llmExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("F22: ExitCode = %d, want 3 (BYOK-not-configured = permanent)", exitErr.ExitCode())
	}
	if !strings.Contains(exitErr.Error(), "BYOK") && !strings.Contains(exitErr.Error(), "settings/llm") {
		t.Errorf("F22: error message should hint at /settings/llm, got %q", exitErr.Error())
	}
}

// TestLLMTest_TransientExit4_ProtocolError_F23 — a 2xx with no
// status field must surface as transient.
func TestLLMTest_TransientExit4_ProtocolError_F23(t *testing.T) {
	tf := newLLMFakeServer(t)
	tf.healthResp = func(r *http.Request) (int, interface{}, string) {
		return http.StatusOK, map[string]interface{}{}, ""
	}
	client := api.NewClient(tf.server.URL, "k")
	res, _, _ := runLLMTestAndCapture(t, client, tf.server.URL, llmTestArgs{}, false)
	exitErr, ok := res.err.(*llmExitError)
	if !ok {
		t.Fatalf("F23: err = %v (%T), want *llmExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 4 {
		t.Errorf("F23: ExitCode = %d, want 4 (protocol violation = transient)", exitErr.ExitCode())
	}
}

// TestLLMTest_NetworkError_Exit4 — a connection failure (port
// closed) maps to exit 4 (transient).
func TestLLMTest_NetworkError_Exit4(t *testing.T) {
	// Use an unroutable URL so the dial fails cleanly.
	client := api.NewClient("http://127.0.0.1:1", "k")
	res, _, _ := runLLMTestAndCapture(t, client, "http://127.0.0.1:1", llmTestArgs{}, false)
	exitErr, ok := res.err.(*llmExitError)
	if !ok {
		t.Fatalf("err = %v (%T), want *llmExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 4 {
		t.Errorf("ExitCode = %d, want 4 (network error = transient)", exitErr.ExitCode())
	}
}

// TestLLMHealthFailureToExitError_Classification_F21 — direct unit
// test for the classifier so a refactor breaking the mapping is
// caught without spinning up an httptest server per case.
func TestLLMHealthFailureToExitError_Classification_F21(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"nil error", nil, 0},
		{"401 permanent", &api.LLMError{StatusCode: 401}, 3},
		{"403 permanent", &api.LLMError{StatusCode: 403}, 3},
		{"404 permanent", &api.LLMError{StatusCode: 404}, 3},
		{"429 transient", &api.LLMError{StatusCode: 429}, 4},
		{"500 transient", &api.LLMError{StatusCode: 500}, 4},
		{"503 generic transient", &api.LLMError{StatusCode: 503, Raw: "gateway down"}, 4},
		{"503 AI-disabled permanent", &api.LLMError{StatusCode: 503, Reason: "BYOK key not configured"}, 3},
		{"protocol error transient", &api.LLMError{StatusCode: 200, ProtocolError: true}, 4},
		// F39 regression: 204 / 206 with ProtocolError=true must
		// still surface as transient exit-4 (not the default exit-3
		// permanent bucket) at the classifier layer.
		{"204 protocol error transient (F39)", &api.LLMError{StatusCode: 204, ProtocolError: true}, 4},
		{"206 protocol error transient (F39)", &api.LLMError{StatusCode: 206, ProtocolError: true}, 4},
		{"network error transient", errors.New("connection refused"), 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := llmHealthFailureToExitError("op", tc.err)
			if tc.wantCode == 0 {
				if err != nil {
					t.Errorf("want nil, got %v", err)
				}
				return
			}
			exitErr, ok := err.(*llmExitError)
			if !ok {
				t.Fatalf("err = %v (%T), want *llmExitError", err, err)
			}
			if exitErr.ExitCode() != tc.wantCode {
				t.Errorf("ExitCode = %d, want %d", exitErr.ExitCode(), tc.wantCode)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// llm bench — path resolution + flag validation tests
//
// The actual `go run` subprocess is NOT spawned because that would
// require a real sbomhub OSS checkout in the test fixture. The
// pre-flight helpers (resolveSbomhubSource / resolveEvalSetPath +
// the flag-validation branch in runLLMBench) carry the bulk of the
// CLI logic and are tested directly here.
// ---------------------------------------------------------------------------

// TestResolveSbomhubSource_MissingDir — a non-existent directory
// must surface as a permanent (actionable) error with the resolved
// absolute path so the operator can spot a typo.
func TestResolveSbomhubSource_MissingDir(t *testing.T) {
	_, err := resolveSbomhubSource(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected error for missing sbomhub source")
	}
	if !strings.Contains(err.Error(), "sbomhub source") {
		t.Errorf("error message should mention sbomhub source: %v", err)
	}
}

// TestResolveSbomhubSource_FlagWins — --sbomhub-source flag value
// takes precedence over SBOMHUB_SOURCE env.
func TestResolveSbomhubSource_FlagWins(t *testing.T) {
	envDir := t.TempDir()
	flagDir := t.TempDir()
	t.Setenv("SBOMHUB_SOURCE", envDir)
	got, err := resolveSbomhubSource(flagDir)
	if err != nil {
		t.Fatalf("resolve err: %v", err)
	}
	wantAbs, _ := filepath.Abs(flagDir)
	if got != wantAbs {
		t.Errorf("got %s, want %s (flag must win over env)", got, wantAbs)
	}
}

// TestResolveSbomhubSource_EnvFallback — when --sbomhub-source is
// empty, SBOMHUB_SOURCE env is consulted.
func TestResolveSbomhubSource_EnvFallback(t *testing.T) {
	envDir := t.TempDir()
	t.Setenv("SBOMHUB_SOURCE", envDir)
	got, err := resolveSbomhubSource("")
	if err != nil {
		t.Fatalf("resolve err: %v", err)
	}
	wantAbs, _ := filepath.Abs(envDir)
	if got != wantAbs {
		t.Errorf("got %s, want %s (env should be consulted when flag empty)", got, wantAbs)
	}
}

// TestResolveSbomhubSource_IsFile — pointing at a regular file (not
// a directory) must surface as a permanent error.
func TestResolveSbomhubSource_IsFile(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "not-a-dir")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	_, err := resolveSbomhubSource(f)
	if err == nil {
		t.Fatal("expected error for file (not dir)")
	}
	if !strings.Contains(err.Error(), "directory") {
		t.Errorf("error message should mention directory requirement: %v", err)
	}
}

// TestResolveEvalSetPath_DefaultFromSource — empty --eval-set picks
// the M4-3 canonical fixture under the sbomhub source root.
//
// M4 Codex review #F38 regression: the default rel path must be
// joined against the sbomhub repo *root* and resolve to
// apps/api/test/fixtures/llm-bench/cve-20-50.json (the M4-3 binary's
// working dir is apps/api, but resolveEvalSetPath sees the repo root
// — so the apps/api/ prefix must be embedded in the default
// constant).
func TestResolveEvalSetPath_DefaultFromSource(t *testing.T) {
	tmp := t.TempDir()
	// Lay down the M4-3 fixture path so the resolver can stat it.
	// Must mirror the actual sbomhub layout (apps/api/test/...) —
	// F38 fix moved the default to include the apps/api/ prefix.
	fixture := filepath.Join(tmp, "apps", "api", "test", "fixtures", "llm-bench", "cve-20-50.json")
	if err := os.MkdirAll(filepath.Dir(fixture), 0o755); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	if err := os.WriteFile(fixture, []byte(`{"version":1,"cases":[]}`), 0o644); err != nil {
		t.Fatalf("seed fixture: %v", err)
	}

	got, err := resolveEvalSetPath("", tmp)
	if err != nil {
		t.Fatalf("resolve err: %v", err)
	}
	wantAbs, _ := filepath.Abs(fixture)
	if got != wantAbs {
		t.Errorf("got %s, want %s", got, wantAbs)
	}
}

// TestLLMBenchDefaultEvalSetRel_MatchesSbomhubLayout — guards the
// constant directly so a future refactor that drops the apps/api/
// prefix re-introduces F38 with a loud unit-level failure rather
// than only being caught by the path-resolution test below.
func TestLLMBenchDefaultEvalSetRel_MatchesSbomhubLayout(t *testing.T) {
	const want = "apps/api/test/fixtures/llm-bench/cve-20-50.json"
	if llmBenchDefaultEvalSetRel != want {
		t.Errorf("llmBenchDefaultEvalSetRel = %q, want %q (M4 Codex #F38 — must be joined against repo root, not apps/api workdir)",
			llmBenchDefaultEvalSetRel, want)
	}
}

// TestResolveEvalSetPath_AbsoluteOverride — --eval-set with an
// absolute path is honoured as-is.
func TestResolveEvalSetPath_AbsoluteOverride(t *testing.T) {
	tmp := t.TempDir()
	override := filepath.Join(tmp, "alt.json")
	if err := os.WriteFile(override, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err := resolveEvalSetPath(override, t.TempDir())
	if err != nil {
		t.Fatalf("resolve err: %v", err)
	}
	if got != override {
		t.Errorf("got %s, want %s (absolute path must be honoured)", got, override)
	}
}

// TestResolveEvalSetPath_RelativeJoinsSource — a relative
// --eval-set is joined under the sbomhub source root.
func TestResolveEvalSetPath_RelativeJoinsSource(t *testing.T) {
	source := t.TempDir()
	rel := "custom/eval.json"
	full := filepath.Join(source, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	if err := os.WriteFile(full, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err := resolveEvalSetPath(rel, source)
	if err != nil {
		t.Fatalf("resolve err: %v", err)
	}
	if got != full {
		t.Errorf("got %s, want %s (relative path must join source root)", got, full)
	}
}

// TestResolveEvalSetPath_Missing — a missing fixture surfaces a
// permanent error so the operator does not silently bench a
// no-cases run.
func TestResolveEvalSetPath_Missing(t *testing.T) {
	_, err := resolveEvalSetPath("does-not-exist.json", t.TempDir())
	if err == nil {
		t.Fatal("expected error for missing eval-set")
	}
	if !strings.Contains(err.Error(), "eval-set") {
		t.Errorf("error should mention eval-set: %v", err)
	}
}

// ---------------------------------------------------------------------------
// F46 — subprocess exit-code propagation
//
// M4 Codex review round 2 finding: the bench wrapper used to fold
// any non-zero subprocess exit into a fixed code=3, which destroyed
// the M4-3 F42 typed contract (2 usage / 3 config / 4 no providers /
// 5 execution failure). The fix wires `mapBenchSubprocessError` to
// pass these codes through verbatim so CI can distinguish "no
// providers configured" (4 → fix BYOK env) from "execution failure"
// (5 → likely transient / retry).
//
// We exercise the helper directly with synthetic *exec.ExitError
// values produced by `sh -c "exit N"` — that gives us a real
// runtime *exec.ExitError without needing a populated sbomhub OSS
// checkout in the test fixture. Skipped on Windows where /bin/sh
// is not guaranteed (other M4 tests follow the same convention).
// ---------------------------------------------------------------------------

// runShExit launches `sh -c "exit N"` and returns the resulting
// error from cmd.Run(). The returned error is always a real
// *exec.ExitError with ExitCode() == N (per POSIX shell semantics),
// which is exactly what the M4-3 bench subprocess would produce.
//
// We intentionally spawn a real subprocess (rather than fabricate
// a synthetic *exec.ExitError) so the test exercises the same
// errors.As path the production code hits — fakes have repeatedly
// drifted from real os/exec semantics in past Codex reviews.
func runShExit(t *testing.T, code int) error {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("F46 propagation test requires POSIX sh")
	}
	cmd := exec.Command("sh", "-c", "exit "+strconv.Itoa(code))
	err := cmd.Run()
	if err == nil {
		t.Fatalf("sh -c 'exit %d' returned nil error", code)
	}
	return err
}

// TestRunLLMBench_ExitCodePropagation_F46 — `mapBenchSubprocessError`
// must forward subprocess exit codes 2/3/4/5 verbatim into the
// llmExitError envelope so CI pipelines can branch on the M4-3 F42
// typed contract.
func TestRunLLMBench_ExitCodePropagation_F46(t *testing.T) {
	cases := []struct {
		name     string
		subExit  int
		wantCode int
		wantMsg  string
	}{
		{"M4-3 usage (2)", 2, 2, "exited with code 2"},
		{"M4-3 config (3)", 3, 3, "exited with code 3"},
		{"M4-3 no providers (4)", 4, 4, "exited with code 4"},
		{"M4-3 execution failure (5)", 5, 5, "exited with code 5"},
		// M4-3 might widen the contract in the future; a 6 should
		// still flow through transparently rather than be silently
		// remapped to 3. Guards against a future regression where
		// someone re-introduces the "fold to 3" anti-pattern.
		{"future M4-3 code (6)", 6, 6, "exited with code 6"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runErr := runShExit(t, tc.subExit)
			got := mapBenchSubprocessError(runErr)
			if got == nil {
				t.Fatal("F46: mapBenchSubprocessError returned nil for non-nil run error")
			}
			if got.ExitCode() != tc.wantCode {
				t.Errorf("F46: ExitCode = %d, want %d (M4-3 typed contract must pass through verbatim, not collapse to 3)",
					got.ExitCode(), tc.wantCode)
			}
			if !strings.Contains(got.Error(), tc.wantMsg) {
				t.Errorf("F46: error message %q missing %q (operator needs the underlying code surfaced)",
					got.Error(), tc.wantMsg)
			}
			// The wrapper must also point operators at the M4-3
			// doc so they can interpret the forwarded code.
			if !strings.Contains(got.Error(), "M4-3") {
				t.Errorf("F46: error message should reference the M4-3 doc, got %q", got.Error())
			}
		})
	}
}

// TestMapBenchSubprocessError_LaunchFailure_F46 — a non-ExitError
// (e.g. `go` binary missing → exec.ErrNotFound wrapped in
// PathError) must still surface as a permanent exit-3 because the
// operator's fix is environmental ("install Go") not retryable.
func TestMapBenchSubprocessError_LaunchFailure_F46(t *testing.T) {
	// Synthesise a launch failure by running a path that cannot
	// possibly exist — exec.Cmd.Run reports this as a non-
	// *exec.ExitError (typically *fs.PathError) so the helper's
	// fallback branch fires.
	cmd := exec.Command(filepath.Join(t.TempDir(), "definitely-not-a-binary"))
	runErr := cmd.Run()
	if runErr == nil {
		t.Fatal("expected launch failure for non-existent binary")
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		t.Skipf("platform reports launch failure as *exec.ExitError, helper test N/A here: %v", runErr)
	}
	got := mapBenchSubprocessError(runErr)
	if got == nil {
		t.Fatal("F46: mapBenchSubprocessError returned nil for launch failure")
	}
	if got.ExitCode() != 3 {
		t.Errorf("F46: launch-failure ExitCode = %d, want 3 (permanent — fix env)", got.ExitCode())
	}
	if !strings.Contains(got.Error(), "起動失敗") {
		t.Errorf("F46: launch-failure message should mention 起動失敗, got %q", got.Error())
	}
}

// TestMapBenchSubprocessError_NilPassthrough_F46 — a nil runErr
// must return a nil envelope (no spurious exit-1 noise when the
// subprocess succeeded).
func TestMapBenchSubprocessError_NilPassthrough_F46(t *testing.T) {
	if got := mapBenchSubprocessError(nil); got != nil {
		t.Errorf("F46: mapBenchSubprocessError(nil) = %v, want nil", got)
	}
}

// TestMapBenchSubprocessError_SignalKilled_F46 — a subprocess
// killed by signal (ExitCode() == -1) maps to exit-4 (transient-
// leaning) per the documented ※要確認 in llm.go. We simulate this
// by spawning sh, letting it sleep, then killing the process; the
// ProcessState.ExitCode() returns -1 because no clean exit
// happened.
func TestMapBenchSubprocessError_SignalKilled_F46(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("F46 signal-kill test requires POSIX kill semantics")
	}
	cmd := exec.Command("sh", "-c", "sleep 30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill sleep: %v", err)
	}
	runErr := cmd.Wait()
	if runErr == nil {
		t.Fatal("expected non-nil error after kill")
	}
	got := mapBenchSubprocessError(runErr)
	if got == nil {
		t.Fatal("F46: mapBenchSubprocessError returned nil for signal-killed subprocess")
	}
	// Some platforms encode signal kills with a normal positive
	// exit code via sh's reporting layer (128 + signo). On those
	// platforms ExitCode() >= 0 and we forward verbatim per the
	// M4-3 contract path — that is acceptable behaviour (the
	// operator sees the underlying number). Only assert the
	// negative-code branch when we actually hit it.
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) && exitErr.ExitCode() < 0 {
		if got.ExitCode() != 4 {
			t.Errorf("F46: signal-killed (ExitCode=-1) maps to %d, want 4 (transient-leaning default)",
				got.ExitCode())
		}
		if !strings.Contains(got.Error(), "signal") {
			t.Errorf("F46: signal-killed message should mention signal, got %q", got.Error())
		}
	}
}

// ---------------------------------------------------------------------------
// cobra wiring smoke tests — verify the commands are registered
// with the expected names and flags, so a refactor that drops a
// subcommand or renames a flag is caught.
// ---------------------------------------------------------------------------

// TestLLMCmd_Registered — the `llm` parent command must be wired
// onto rootCmd with the test + bench subcommands.
func TestLLMCmd_Registered(t *testing.T) {
	llm, _, err := rootCmd.Find([]string{"llm"})
	if err != nil {
		t.Fatalf("rootCmd.Find(llm): %v", err)
	}
	if llm.Use != "llm" {
		t.Errorf("llm.Use = %q, want llm", llm.Use)
	}
	gotSubs := map[string]bool{}
	for _, sub := range llm.Commands() {
		gotSubs[sub.Name()] = true
	}
	for _, want := range []string{"test", "bench"} {
		if !gotSubs[want] {
			t.Errorf("`llm %s` subcommand missing (got %v)", want, gotSubs)
		}
	}
}

// TestLLMTestCmd_Flags — flags expected by the M4-7 contract are
// declared on `llm test`.
func TestLLMTestCmd_Flags(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"llm", "test"})
	if err != nil {
		t.Fatalf("find llm test: %v", err)
	}
	for _, want := range []string{"provider"} {
		if cmd.Flags().Lookup(want) == nil {
			t.Errorf("--%s flag missing on `llm test`", want)
		}
	}
}

// TestLLMBenchCmd_Flags — flags expected by the M4-7 contract are
// declared on `llm bench`.
func TestLLMBenchCmd_Flags(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"llm", "bench"})
	if err != nil {
		t.Fatalf("find llm bench: %v", err)
	}
	for _, want := range []string{
		"providers", "eval-set", "max-cases",
		"sbomhub-source", "out", "markdown", "timeout",
	} {
		if cmd.Flags().Lookup(want) == nil {
			t.Errorf("--%s flag missing on `llm bench`", want)
		}
	}
}
