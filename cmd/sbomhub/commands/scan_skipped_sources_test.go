package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/youichi-uda/sbomhub-cli/internal/api"
	"github.com/youichi-uda/sbomhub-cli/internal/scanner"
)

// Tests for the additive scan-status fields `skipped_sources` and
// `reasons` (sbomhub docs/UPGRADE.md §26, JVN outage / SBOMHUB_JVN=off).
//
// Contract under test:
//   - a skipped source is reported (stderr warning, result box line,
//     --json `skipped_sources`) but is NOT a failure: exit codes and
//     --fail-on semantics are unchanged;
//   - `source_unavailable` in `reasons` of a failed scan is explained in
//     the failed-scan message;
//   - an old server that sends neither field produces exactly the
//     previous output.

func setFastPolling(t *testing.T) {
	t.Helper()
	saveTimeout, savePoll := scanWaitTimeout, scanPollInterval
	scanWaitTimeout = 5 * time.Second
	scanPollInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		scanWaitTimeout = saveTimeout
		scanPollInterval = savePoll
	})
}

func TestPollScanStatus_CarriesSkippedSourcesAndReasons(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantFailed  string
		wantSkipped []string
		wantReasons []string
	}{
		{
			name:        "completed, jvn skipped",
			body:        `{"status":"completed","vulnerabilities":{"high":1,"total":1},"skipped_sources":["jvn"]}`,
			wantSkipped: []string{"jvn"},
		},
		{
			name:        "failed, jvn skipped, nvd failed",
			body:        `{"status":"failed","error":"nvd: scan failed (fetch_failed)","vulnerabilities":{},"reasons":["fetch_failed"],"skipped_sources":["jvn"]}`,
			wantFailed:  "nvd: scan failed (fetch_failed)",
			wantSkipped: []string{"jvn"},
			wantReasons: []string{"fetch_failed"},
		},
		{
			name:        "failed, source_unavailable",
			body:        `{"status":"failed","error":"jvn: scan failed (fetch_failed, source_unavailable)","vulnerabilities":{},"reasons":["fetch_failed","source_unavailable"]}`,
			wantFailed:  "jvn: scan failed (fetch_failed, source_unavailable)",
			wantReasons: []string{"fetch_failed", "source_unavailable"},
		},
		{
			name: "old server",
			body: `{"status":"completed","vulnerabilities":{"high":1,"total":1}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setFastPolling(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), scanWaitTimeout)
			defer cancel()
			got := pollScanStatus(ctx, api.NewClient(server.URL, "k"), "p", "s")
			if got.timedOut || got.apiErrMsg != "" || got.summary == nil {
				t.Fatalf("unexpected outcome %+v", got)
			}
			if got.failedMsg != tc.wantFailed {
				t.Errorf("failedMsg = %q, want %q", got.failedMsg, tc.wantFailed)
			}
			if !reflect.DeepEqual(got.skippedSources, tc.wantSkipped) {
				t.Errorf("skippedSources = %#v, want %#v", got.skippedSources, tc.wantSkipped)
			}
			if !reflect.DeepEqual(got.reasons, tc.wantReasons) {
				t.Errorf("reasons = %#v, want %#v", got.reasons, tc.wantReasons)
			}
		})
	}
}

// A `skipped_sources` seen on a non-terminal poll must not leak into the
// outcome: the server only defines it for completed/failed.
func TestPollScanStatus_SkippedSourcesOnlyFromTerminalPoll(t *testing.T) {
	setFastPolling(t)
	var n int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			_, _ = w.Write([]byte(`{"status":"running","vulnerabilities":{},"skipped_sources":["jvn"]}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"completed","vulnerabilities":{}}`))
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), scanWaitTimeout)
	defer cancel()
	got := pollScanStatus(ctx, api.NewClient(server.URL, "k"), "p", "s")
	if got.skippedSources != nil {
		t.Errorf("skippedSources = %#v, want nil (terminal poll had none)", got.skippedSources)
	}
}

func jsonKeys(t *testing.T, v interface{}) []string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestBuildScanJSONResult_SkippedSources(t *testing.T) {
	crit := "critical"
	in := scanFinalState{
		format:         "cyclonedx",
		uploadResult:   &api.UploadResult{SBOMID: "s", ProjectID: "p"},
		summary:        &api.VulnerabilitySummary{High: 1},
		waitForScan:    true,
		failOnStr:      crit,
		exitCode:       exitSuccess,
		skippedSources: []string{"jvn"},
	}
	got := buildScanJSONResult(in)
	if got.ScanStatus != "completed" {
		t.Errorf("scan_status = %q, want completed (a skipped source is not a failure)", got.ScanStatus)
	}
	if !reflect.DeepEqual(got.SkippedSources, []string{"jvn"}) {
		t.Errorf("SkippedSources = %#v, want [jvn]", got.SkippedSources)
	}
	if got.FailOn.ExitCode != exitSuccess || got.FailOn.Triggered {
		t.Errorf("fail_on = %+v, want unchanged (exit 0, not triggered)", got.FailOn)
	}
	raw, _ := json.Marshal(got)
	if !strings.Contains(string(raw), `"skipped_sources":["jvn"]`) {
		t.Errorf("JSON %s lacks skipped_sources", raw)
	}
}

func TestBuildScanJSONResult_Reasons(t *testing.T) {
	in := scanFinalState{
		summary:       &api.VulnerabilitySummary{},
		waitForScan:   true,
		scanFailedMsg: "jvn: scan failed (fetch_failed, source_unavailable)",
		scanReasons:   []string{"fetch_failed", "source_unavailable"},
		exitCode:      exitScanTimeout,
	}
	got := buildScanJSONResult(in)
	raw, _ := json.Marshal(got)
	if !strings.Contains(string(raw), `"reasons":["fetch_failed","source_unavailable"]`) {
		t.Errorf("JSON %s lacks reasons", raw)
	}
}

// Old server: the JSON key set must be exactly the pre-change one.
func TestBuildScanJSONResult_OldServerKeySetUnchanged(t *testing.T) {
	in := scanFinalState{
		uploadResult: &api.UploadResult{SBOMID: "s", ProjectID: "p"},
		summary:      &api.VulnerabilitySummary{High: 1},
		waitForScan:  true,
	}
	want := []string{"component_count", "fail_on", "format", "project_created", "project_id", "project_name", "sbom_id", "scan_status", "url", "vulnerability_summary"}
	if got := jsonKeys(t, buildScanJSONResult(in)); !reflect.DeepEqual(got, want) {
		t.Errorf("keys = %v, want %v", got, want)
	}
	// Failed scan from an old server (no reasons) too.
	in.scanFailedMsg = "nvd: rate limited"
	if got := jsonKeys(t, buildScanJSONResult(in)); !reflect.DeepEqual(got, want) {
		t.Errorf("failed keys = %v, want %v", got, want)
	}
}

func TestFormatSkippedSourcesWarning(t *testing.T) {
	if got := formatSkippedSourcesWarning(nil, false); got != "" {
		t.Errorf("nil -> %q, want empty", got)
	}
	if got := formatSkippedSourcesWarning([]string{}, true); got != "" {
		t.Errorf("empty -> %q, want empty", got)
	}
	got := formatSkippedSourcesWarning([]string{"jvn"}, false)
	for _, want := range []string{"jvn", "SBOMHUB_JVN=off", "不完全"} {
		if !strings.Contains(got, want) {
			t.Errorf("warning %q lacks %q", got, want)
		}
	}
	if strings.Contains(got, "--fail-on") {
		t.Errorf("warning without --fail-on mentions it: %q", got)
	}
	if got := formatSkippedSourcesWarning([]string{"jvn"}, true); !strings.Contains(got, "--fail-on") {
		t.Errorf("warning with --fail-on should mention it: %q", got)
	}
	// Codex R2 Medium: SBOMHUB_JVN=off keeps older JVN findings linked, so
	// --fail-on is NOT evaluated "without" the source; the warning must not
	// claim so, and must say old findings may still be counted.
	if got := formatSkippedSourcesWarning([]string{"jvn"}, true); strings.Contains(got, "除いた結果で評価") || !strings.Contains(got, "再確認されない") {
		t.Errorf("warning misdescribes --fail-on input: %q", got)
	}
	// Server-supplied names are printed to a terminal: control bytes
	// (ANSI escapes) must not pass through.
	if got := formatSkippedSourcesWarning([]string{"jvn\x1b[2J\n"}, false); strings.ContainsAny(got[:len(got)-1], "\x1b\r") || strings.Count(got, "\n") != 1 {
		t.Errorf("control characters not stripped: %q", got)
	}
}

func TestFormatScanFailedDetail(t *testing.T) {
	// Old server / no reasons: exactly the server's error string.
	if got := formatScanFailedDetail("nvd: rate limited", nil); got != "nvd: rate limited" {
		t.Errorf("no reasons -> %q, want unchanged", got)
	}
	// Reasons already in the error string, none of them source_unavailable:
	// unchanged.
	if got := formatScanFailedDetail("nvd: scan failed (fetch_failed)", []string{"fetch_failed"}); got != "nvd: scan failed (fetch_failed)" {
		t.Errorf("reasons already present -> %q, want unchanged", got)
	}
	// Reasons not named by the error string are appended.
	if got := formatScanFailedDetail("boom", []string{"deadline_exceeded"}); !strings.Contains(got, "deadline_exceeded") {
		t.Errorf("missing reason not appended: %q", got)
	}
	// source_unavailable is explained.
	got := formatScanFailedDetail("jvn: scan failed (fetch_failed, source_unavailable)", []string{"fetch_failed", "source_unavailable"})
	for _, want := range []string{"source_unavailable", "SBOMHUB_JVN=off"} {
		if !strings.Contains(got, want) {
			t.Errorf("detail %q lacks %q", got, want)
		}
	}
}

// --- end-to-end through runScan -------------------------------------------

type e2eRun struct {
	err    error
	stdout string
	stderr string
}

// fakeScanner stands in for syft/trivy/cdxgen so the run-level tests
// execute in CI, where no scanner is installed (Codex R2 Low).
type fakeScanner struct{}

func (fakeScanner) Name() string    { return "fake" }
func (fakeScanner) Available() bool { return true }
func (fakeScanner) Scan(string, string) ([]byte, error) {
	return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"left-pad","version":"1.3.0"}]}`), nil
}

// runScanAgainst drives runScan against a fake server whose scan-status
// endpoint returns body, with a fake SBOM scanner.
func runScanAgainst(t *testing.T, body, failOn string, jsonOut bool) e2eRun {
	t.Helper()
	saveNewScanner := newScanner
	newScanner = func(string) (scanner.Scanner, error) { return fakeScanner{}, nil }
	t.Cleanup(func() { newScanner = saveNewScanner })
	const projectID = "55555555-5555-5555-5555-555555555555"
	const sbomID = "66666666-6666-6666-6666-666666666666"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/api/v1/projects/"+projectID+"/sbom":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"` + sbomID + `","project_id":"` + projectID + `","format":"cyclonedx"}`))
		case r.URL.Path == "/api/v1/projects/"+projectID+"/sboms/"+sbomID+"/scan-status":
			_, _ = w.Write([]byte(body))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	saveProject, saveFailOn, saveWait, saveDry, saveTool := scanProject, scanFailOn, scanWaitForScan, scanDryRun, scanTool
	saveURL, saveKey := apiURL, apiKey
	saveJSON, saveWriter := globalOutput.JSON, globalOutput.Writer
	saveStdout, saveStderr := os.Stdout, os.Stderr
	t.Cleanup(func() {
		scanProject, scanFailOn, scanWaitForScan, scanDryRun, scanTool = saveProject, saveFailOn, saveWait, saveDry, saveTool
		apiURL, apiKey = saveURL, saveKey
		globalOutput.JSON, globalOutput.Writer = saveJSON, saveWriter
		os.Stdout, os.Stderr = saveStdout, saveStderr
	})
	setFastPolling(t)
	scanProject, scanFailOn, scanWaitForScan, scanDryRun, scanTool = projectID, failOn, true, false, ""
	apiURL, apiKey = server.URL, "test-key"
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", "")
	t.Setenv("SBOMHUB_API_URL", "")
	t.Setenv("SBOMHUB_API_KEY", "")

	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	os.Stdout, os.Stderr = outW, errW
	globalOutput.JSON, globalOutput.Writer = jsonOut, outW
	var outBuf, errBuf bytes.Buffer
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(&outBuf, outR); done <- struct{}{} }()
	go func() { _, _ = io.Copy(&errBuf, errR); done <- struct{}{} }()

	err := runScan(scanCmd, []string{t.TempDir()})

	_ = outW.Close()
	_ = errW.Close()
	<-done
	<-done
	os.Stdout, os.Stderr = saveStdout, saveStderr
	return e2eRun{err: err, stdout: outBuf.String(), stderr: errBuf.String()}
}

const (
	bodySkippedJVN = `{"status":"completed","vulnerabilities":{"high":1,"total":1},"skipped_sources":["jvn"]}`
	bodyOldServer  = `{"status":"completed","vulnerabilities":{"high":1,"total":1}}`
)

func TestRunScan_SkippedSourcesWarnsButDoesNotFail(t *testing.T) {
	// --fail-on critical with only a High finding: passes, exactly as
	// without skipped_sources.
	r := runScanAgainst(t, bodySkippedJVN, "critical", false)
	if r.err != nil {
		t.Fatalf("runScan err = %v, want nil (skipped source is not a failure)", r.err)
	}
	if !strings.Contains(r.stderr, "jvn") || !strings.Contains(r.stderr, "SBOMHUB_JVN=off") {
		t.Errorf("stderr lacks skipped-source warning:\n%s", r.stderr)
	}
	if !strings.Contains(r.stdout, "未照会") {
		t.Errorf("result box lacks skipped-source line:\n%s", r.stdout)
	}

	// --fail-on high trips exactly as before: exit 1.
	r = runScanAgainst(t, bodySkippedJVN, "high", false)
	var exitErr *scanExitError
	if !errors.As(r.err, &exitErr) || exitErr.ExitCode() != exitThresholdExceeded {
		t.Fatalf("runScan err = %v, want exit %d", r.err, exitThresholdExceeded)
	}
	if !strings.Contains(r.stderr, "SBOMHUB_JVN=off") {
		t.Errorf("warning must also be printed when --fail-on trips:\n%s", r.stderr)
	}
}

func TestRunScan_SkippedSourcesJSON(t *testing.T) {
	r := runScanAgainst(t, bodySkippedJVN, "critical", true)
	if r.err != nil {
		t.Fatalf("runScan err = %v", r.err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(r.stdout), &got); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, r.stdout)
	}
	if got["scan_status"] != "completed" {
		t.Errorf("scan_status = %v", got["scan_status"])
	}
	if ss, _ := got["skipped_sources"].([]interface{}); len(ss) != 1 || ss[0] != "jvn" {
		t.Errorf("skipped_sources = %v, want [jvn]", got["skipped_sources"])
	}
	if !strings.Contains(r.stderr, "SBOMHUB_JVN=off") {
		t.Errorf("stderr lacks warning in --json mode:\n%s", r.stderr)
	}
}

func TestRunScan_OldServerOutputUnchanged(t *testing.T) {
	r := runScanAgainst(t, bodyOldServer, "critical", false)
	if r.err != nil {
		t.Fatalf("runScan err = %v", r.err)
	}
	if strings.Contains(r.stderr, "SBOMHUB_JVN") || strings.Contains(r.stdout, "未照会") || strings.Contains(r.stdout, "SBOMHUB_JVN") {
		t.Errorf("old server must produce no skipped-source output:\nstdout:\n%s\nstderr:\n%s", r.stdout, r.stderr)
	}
	r = runScanAgainst(t, bodyOldServer, "critical", true)
	if strings.Contains(r.stdout, "skipped_sources") || strings.Contains(r.stdout, "reasons") {
		t.Errorf("old server JSON gained keys:\n%s", r.stdout)
	}
}

func TestRunScan_SourceUnavailableFailedMessage(t *testing.T) {
	body := `{"status":"failed","error":"jvn: scan failed (fetch_failed, source_unavailable)","vulnerabilities":{},"reasons":["fetch_failed","source_unavailable"]}`
	r := runScanAgainst(t, body, "critical", false)
	var exitErr *scanExitError
	if !errors.As(r.err, &exitErr) || exitErr.ExitCode() != exitScanTimeout {
		t.Fatalf("runScan err = %v, want exit %d (unchanged)", r.err, exitScanTimeout)
	}
	if !strings.Contains(exitErr.Error(), "SBOMHUB_JVN=off") {
		t.Errorf("failed message lacks source_unavailable hint: %q", exitErr.Error())
	}
}

// Codex R1 Medium: a failed scan that also skipped a source does not
// evaluate --fail-on; the skipped-source warning must not claim it did.
func TestRunScan_FailedAndSkippedDoesNotClaimFailOnEvaluated(t *testing.T) {
	body := `{"status":"failed","error":"nvd: scan failed (fetch_failed)","vulnerabilities":{},"reasons":["fetch_failed"],"skipped_sources":["jvn"]}`
	r := runScanAgainst(t, body, "critical", false)
	var exitErr *scanExitError
	if !errors.As(r.err, &exitErr) || exitErr.ExitCode() != exitScanTimeout {
		t.Fatalf("runScan err = %v, want exit %d", r.err, exitScanTimeout)
	}
	if !strings.Contains(r.stderr, "SBOMHUB_JVN=off") {
		t.Errorf("skipped-source warning missing on failed scan:\n%s", r.stderr)
	}
	if strings.Contains(r.stderr, "--fail-on はこれらのソースを除いた結果で評価") {
		t.Errorf("warning claims --fail-on was evaluated on a failed scan:\n%s", r.stderr)
	}
}

// Codex R1 Low: old server JSON has exactly the pre-change key set.
func TestRunScan_OldServerJSONKeySetExact(t *testing.T) {
	r := runScanAgainst(t, bodyOldServer, "critical", true)
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(r.stdout), &got); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, r.stdout)
	}
	want := []string{"component_count", "fail_on", "format", "project_created", "project_id", "project_name", "sbom_id", "scan_status", "url", "vulnerability_summary"}
	if keys := jsonKeys(t, got); !reflect.DeepEqual(keys, want) {
		t.Errorf("keys = %v, want %v", keys, want)
	}
}

// Codex R2 Low: the result box for an old server (no skipped_sources) is
// byte-for-byte the pre-change box.
func TestPrintResultBox_NoSkippedSourcesExactPreviousOutput(t *testing.T) {
	saveStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	printResultBox(3, &api.UploadResult{URL: "http://x/projects/p"}, &api.VulnerabilitySummary{High: 1}, nil)
	_ = w.Close()
	os.Stdout = saveStdout
	got, _ := io.ReadAll(r)
	want := "" +
		"┌─────────────────────────────────────────────────────────┐\n" +
		"│ スキャン完了                                            │\n" +
		"├─────────────────────────────────────────────────────────┤\n" +
		"│ コンポーネント: 3                                        │\n" +
		"│ 脆弱性: 1 High                                           │\n" +
		"│                                                         │\n" +
		"│ URL: http://x/projects/p                                 │\n" +
		"└─────────────────────────────────────────────────────────┘\n"
	if string(got) != want {
		t.Errorf("result box changed:\n got:\n%s\nwant:\n%s", got, want)
	}
}
