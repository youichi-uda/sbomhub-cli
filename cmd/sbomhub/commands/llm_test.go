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
// typed contract. Codes OUTSIDE that band (notably exit 1 from a
// `go run` toolchain mismatch) are renormalised by F57 — that
// behaviour is covered in TestMapBenchSubprocessError_ContractExitNormalization_F57
// below.
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runErr := runShExit(t, tc.subExit)
			got := mapBenchSubprocessError(runErr, nil)
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
	got := mapBenchSubprocessError(runErr, nil)
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
	if got := mapBenchSubprocessError(nil, nil); got != nil {
		t.Errorf("F46: mapBenchSubprocessError(nil) = %v, want nil", got)
	}
}

// ---------------------------------------------------------------------------
// F57 — contract-band normalisation
//
// M4 Codex review round 5 finding: the F46 pass-through forwarded
// ANY subprocess exit code verbatim, including codes outside the
// documented M4-3 0/2/3/4/5 contract. In particular exit 1 from
// `go run` itself (toolchain mismatch / compile error — the bench
// binary never started, so no F42 code is meaningful) leaked
// through as an undocumented code that CI pipelines branching on
// the published contract could not route. The fix re-normalises
// any non-contract code to exit 3 (permanent — operator must fix
// env) and quotes the captured `go run` stderr in the error
// message so operators do not have to re-run to diagnose.
// ---------------------------------------------------------------------------

// TestMapBenchSubprocessError_ContractExitNormalization_F57 — exit
// codes outside the documented M4-3 band (1 / 6 / 42 / 127, etc.)
// must be renormalised to exit 3, preserving the documented
// `llm bench` exit-code contract (0/2/3/4/5). Codes INSIDE the
// band continue to forward verbatim (F46 pass-through, covered by
// TestRunLLMBench_ExitCodePropagation_F46).
func TestMapBenchSubprocessError_ContractExitNormalization_F57(t *testing.T) {
	cases := []struct {
		name    string
		subExit int
	}{
		// Most realistic case: `go run` toolchain mismatch
		// ("go: go.mod requires go >= 1.25.0 ...") emits exit 1.
		{"go-run toolchain/compile failure (1)", 1},
		// Hypothetical future M4-3 widening; before F57 this would
		// also leak through verbatim. After F57 it normalises to 3
		// so the documented contract holds until the wrapper is
		// updated to acknowledge the new code.
		{"undocumented future code (6)", 6},
		// Shell-style "command not found" exit, which a misnamed
		// `go` shim could produce.
		{"shell command-not-found (127)", 127},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runErr := runShExit(t, tc.subExit)
			got := mapBenchSubprocessError(runErr, nil)
			if got == nil {
				t.Fatal("F57: mapBenchSubprocessError returned nil for non-nil run error")
			}
			if got.ExitCode() != 3 {
				t.Errorf("F57: subprocess exit %d should be renormalised to 3 (documented contract is 0/2/3/4/5), got %d",
					tc.subExit, got.ExitCode())
			}
			if !strings.Contains(got.Error(), "launch/compile failure") {
				t.Errorf("F57: error message should mention launch/compile failure, got %q", got.Error())
			}
			// The error must surface the underlying subprocess
			// exit number so an operator can correlate with the
			// `go run` output the captured-stderr tee already
			// streamed to the terminal.
			if !strings.Contains(got.Error(), strconv.Itoa(tc.subExit)) {
				t.Errorf("F57: error message should include subprocess exit number %d, got %q",
					tc.subExit, got.Error())
			}
		})
	}
}

// TestMapBenchSubprocessError_StderrTailQuoted_F57 — the captured
// `go run` stderr tail must be embedded in the normalised exit-3
// error message so operators see the underlying complaint without
// a second run. Pre-F57 the wrapper emitted only "exit=1" with no
// context.
func TestMapBenchSubprocessError_StderrTailQuoted_F57(t *testing.T) {
	runErr := runShExit(t, 1)
	tail := []byte("go: go.mod requires go >= 1.25.0 (running go 1.22.12; GOTOOLCHAIN=local)\n")
	got := mapBenchSubprocessError(runErr, tail)
	if got == nil {
		t.Fatal("F57: mapBenchSubprocessError returned nil")
	}
	if got.ExitCode() != 3 {
		t.Errorf("F57: ExitCode = %d, want 3", got.ExitCode())
	}
	if !strings.Contains(got.Error(), "go.mod requires go >= 1.25.0") {
		t.Errorf("F57: error message should quote captured stderr, got %q", got.Error())
	}
	if !strings.Contains(got.Error(), "stderr (truncated)") {
		t.Errorf("F57: error message should label the embedded stderr block, got %q", got.Error())
	}
}

// TestMapBenchSubprocessError_StderrTailNilOK_F57 — when the
// stderr tail is nil (early-failure path, or tests that don't
// exercise the tee), the F57 message must still be coherent — no
// dangling "stderr:" label, no panic.
func TestMapBenchSubprocessError_StderrTailNilOK_F57(t *testing.T) {
	runErr := runShExit(t, 1)
	got := mapBenchSubprocessError(runErr, nil)
	if got == nil {
		t.Fatal("F57: nil stderr tail produced nil error envelope")
	}
	if got.ExitCode() != 3 {
		t.Errorf("F57: ExitCode = %d, want 3", got.ExitCode())
	}
	if strings.Contains(got.Error(), "stderr (truncated):") {
		t.Errorf("F57: empty stderr tail should not emit a 'stderr (truncated):' header, got %q",
			got.Error())
	}
}

// TestCappedBuffer_Cap_F57 — the bounded buffer used to tee
// `go run` stderr must drop bytes past its limit while still
// reporting the full write count (so io.MultiWriter is satisfied
// and the parallel stream to the operator's terminal is not
// disturbed).
func TestCappedBuffer_Cap_F57(t *testing.T) {
	buf := &cappedBuffer{limit: 16}
	payload := bytes.Repeat([]byte("x"), 64)
	n, err := buf.Write(payload)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(payload) {
		t.Errorf("F57: Write returned n=%d, want %d (MultiWriter contract)", n, len(payload))
	}
	if got := buf.Bytes(); len(got) != 16 {
		t.Errorf("F57: buffered len=%d, want 16 (capped)", len(got))
	}
	// A second write past the cap is a no-op for the buffer but
	// still returns the full length.
	n, err = buf.Write([]byte("more"))
	if err != nil {
		t.Fatalf("write 2: %v", err)
	}
	if n != 4 {
		t.Errorf("F57: post-cap Write returned n=%d, want 4", n)
	}
	if got := buf.Bytes(); len(got) != 16 {
		t.Errorf("F57: post-cap buffered len=%d, want 16 (unchanged)", len(got))
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
	got := mapBenchSubprocessError(runErr, nil)
	if got == nil {
		t.Fatal("F46: mapBenchSubprocessError returned nil for signal-killed subprocess")
	}
	// Some platforms encode signal kills with a normal positive
	// exit code via sh's reporting layer (128 + signo, e.g. 137 for
	// SIGKILL). On those platforms ExitCode() >= 0 — but post-F57
	// the wrapper now renormalises codes outside the M4-3 band to
	// exit 3 rather than forwarding 137 verbatim (which would have
	// silently widened the documented contract). Only the negative-
	// code branch is asserted because that's the one F46's
	// transient-leaning default targets.
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
// F61 — `go build` + direct exec preserves the M4-3 typed exit-code
// contract
//
// M4 Codex review round 6 finding: the bench wrapper used to shell
// out via `go run ./cmd/llm-bench`, which always exits 1 from the
// `go` driver on inner failure regardless of the inner os.Exit(N).
// That silently masked the M4-3 F42 typed contract (2/3/4/5) —
// operators saw the F57 contract-violation branch fire with exit 3
// even when M4-3 emitted a clean exit 4 ("no providers"). The fix
// compiles the M4-3 binary with `go build` and execs the resulting
// binary directly, so exec.ExitError.ExitCode() reflects the actual
// M4-3 contract code.
//
// The integration test below proves the mechanism end-to-end: it
// writes a tiny Go program, builds it with `go build -o`, execs
// the resulting binary, and asserts that the wrapper's
// mapBenchSubprocessError forwards each M4-3 contract code (2/3/4/5)
// verbatim. The pre-F61 `sh -c "exit N"` tests above continue to
// guard mapBenchSubprocessError's behaviour at the helper level —
// the new test additionally guards the end-to-end build+exec path.
// ---------------------------------------------------------------------------

// TestRunLLMBench_RealGoProgramExitCodePreservation_F61 — guards
// the F61 fix end-to-end: a real Go program compiled with
// `go build -o` and exec'd directly must propagate its os.Exit(N)
// to exec.ExitError.ExitCode(), which mapBenchSubprocessError then
// forwards verbatim for codes 2/3/4/5. Pre-F61 the wrapper used
// `go run`, which always returned exit 1 on inner failure — this
// test would have detected the masking by failing on all four
// sub-cases (mapped to wrapper exit 3 instead of the real code).
func TestRunLLMBench_RealGoProgramExitCodePreservation_F61(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("F61 build+exec test relies on POSIX paths and a temp-dir layout that mirrors the wrapper's apps/api workdir")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("F61 test requires `go` in PATH: %v", err)
	}

	// Mirror the M4-3 F42 typed contract exhaustively so a
	// future refactor that re-introduces `go run` (or any other
	// driver that masks the inner exit code) trips every code
	// path at once.
	cases := []struct {
		name     string
		srcCode  int
		wantCode int
	}{
		{"M4-3 usage (2)", 2, 2},
		{"M4-3 config (3)", 3, 3},
		{"M4-3 no providers (4)", 4, 4},
		{"M4-3 execution failure (5)", 5, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			// Tiny self-contained Go module so `go build` works
			// without any network / module-cache deps. The minimum
			// `go` directive (1.22) matches sbomhub-cli's own
			// go.mod baseline so build cache reuse is realistic.
			if err := os.WriteFile(filepath.Join(tmp, "go.mod"),
				[]byte("module bench-fake\n\ngo 1.22\n"), 0o644); err != nil {
				t.Fatalf("seed go.mod: %v", err)
			}
			src := "package main\n\nimport \"os\"\n\nfunc main() { os.Exit(" + strconv.Itoa(tc.srcCode) + ") }\n"
			if err := os.WriteFile(filepath.Join(tmp, "main.go"), []byte(src), 0o644); err != nil {
				t.Fatalf("seed main.go: %v", err)
			}

			// Step 1: build the program. Mirrors runLLMBench's
			// `go build -o <tmpDir>/llm-bench ./cmd/llm-bench`.
			binPath := filepath.Join(tmp, "bench-fake")
			buildCmd := exec.Command("go", "build", "-o", binPath, ".")
			buildCmd.Dir = tmp
			if buildOut, buildErr := buildCmd.CombinedOutput(); buildErr != nil {
				t.Fatalf("F61: go build failed: %v\n%s", buildErr, buildOut)
			}

			// Step 2: exec the built binary directly. This is the
			// load-bearing line of the F61 fix — using `go run`
			// here (the pre-F61 path) would always surface
			// exec.ExitError.ExitCode() == 1 and force the F57
			// contract-violation branch to fire.
			runErr := exec.Command(binPath).Run()
			if runErr == nil {
				t.Fatalf("F61: expected non-nil error for os.Exit(%d), got nil", tc.srcCode)
			}

			// Sanity check at the exec layer: the real exit code
			// must reach exec.ExitError. This is what F61 buys us;
			// if a future refactor breaks it the wrapper test
			// below will fail too, but this assertion narrows the
			// diagnostic to the exec layer first.
			var exitErr *exec.ExitError
			if !errors.As(runErr, &exitErr) {
				t.Fatalf("F61: runErr is %T (%v), want *exec.ExitError", runErr, runErr)
			}
			if exitErr.ExitCode() != tc.srcCode {
				t.Fatalf("F61: direct exec ExitCode = %d, want %d (real binary must preserve os.Exit)",
					exitErr.ExitCode(), tc.srcCode)
			}

			// End-to-end: mapBenchSubprocessError forwards the
			// real code verbatim per F46 because the build+exec
			// split surfaces an authentic M4-3-contract code.
			got := mapBenchSubprocessError(runErr, nil)
			if got == nil {
				t.Fatal("F61: mapBenchSubprocessError returned nil for non-nil run error")
			}
			if got.ExitCode() != tc.wantCode {
				t.Errorf("F61: wrapper ExitCode = %d, want %d (build+exec must preserve M4-3 F42 contract; `go run` masking would surface 3 instead)",
					got.ExitCode(), tc.wantCode)
			}
			if !strings.Contains(got.Error(), "exited with code "+strconv.Itoa(tc.wantCode)) {
				t.Errorf("F61: error message should name the underlying code %d, got %q",
					tc.wantCode, got.Error())
			}
		})
	}
}

// TestRunLLMBench_GoRunMasksExitCode_F61_NegativeProof — documents
// the WHY of F61 with a regression sentinel: the pre-fix path used
// `go run`, which masks every inner exit code as 1. This test
// invokes `go run` against the same tiny program the F61 test
// builds + execs, and asserts that `go run` indeed surfaces exit
// 1 (not the inner os.Exit(4)). A future refactor that
// re-introduces `go run` in runLLMBench would re-introduce the
// masking — this test prevents the operator from getting fooled
// by green CI when M4-3's exit codes are once again silently
// rewritten to 1.
func TestRunLLMBench_GoRunMasksExitCode_F61_NegativeProof(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("F61 negative proof relies on POSIX path layout")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("F61 negative proof requires `go` in PATH: %v", err)
	}

	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"),
		[]byte("module bench-fake-gorun\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatalf("seed go.mod: %v", err)
	}
	// os.Exit(4) — the most representative M4-3 "no providers"
	// code, which pre-F61 was silently masked to exit 1 by
	// `go run`.
	src := "package main\n\nimport \"os\"\n\nfunc main() { os.Exit(4) }\n"
	if err := os.WriteFile(filepath.Join(tmp, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("seed main.go: %v", err)
	}

	cmd := exec.Command("go", "run", ".")
	cmd.Dir = tmp
	// Discard the `go run` "exit status 4" stderr line so the
	// test logs stay clean. We assert on the exit code only.
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	runErr := cmd.Run()
	if runErr == nil {
		t.Fatal("F61 neg-proof: `go run` against os.Exit(4) returned nil error — sanity broken")
	}
	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) {
		t.Fatalf("F61 neg-proof: runErr is %T (%v), want *exec.ExitError", runErr, runErr)
	}
	// THIS is the bug F61 fixes: `go run` always exits 1 on
	// inner failure regardless of the inner os.Exit(N). If this
	// assertion ever starts failing because `go run` learned to
	// propagate the inner code, the F61 build+exec workaround
	// could be revisited — but until then the workaround is the
	// only way to preserve M4-3's F42 typed contract.
	if exitErr.ExitCode() != 1 {
		t.Errorf("F61 neg-proof: `go run` exit code = %d, want 1 (this test guards the F61 build+exec workaround; "+
			"if `go run` now propagates inner exit codes, the workaround in runLLMBench can be reverted)",
			exitErr.ExitCode())
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
