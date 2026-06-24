package commands

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/youichi-uda/sbomhub-cli/internal/api"
	"github.com/youichi-uda/sbomhub-cli/internal/config"
)

// TestWaitForScanCompletion_Completes verifies the polling loop reaches a
// terminal "completed" state and returns the final per-severity counts.
// We seed the fake server to transition running → completed on the second
// poll so we also exercise the multi-iteration path.
func TestWaitForScanCompletion_Completes(t *testing.T) {
	const projectID = "11111111-1111-1111-1111-111111111111"
	const sbomID = "22222222-2222-2222-2222-222222222222"

	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		resp := api.ScanStatusResponse{
			Status:    "running",
			SbomID:    sbomID,
			ProjectID: projectID,
			Vulnerabilities: api.VulnerabilitySummary{
				Critical: 0, High: 1, Medium: 0, Low: 0, Total: 1,
			},
		}
		if n >= 2 {
			resp.Status = "completed"
			resp.Vulnerabilities = api.VulnerabilitySummary{
				Critical: 2, High: 3, Medium: 0, Low: 0, KEV: 1, Total: 5,
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := api.NewClient(server.URL, "test-key")

	// Force a fast polling cadence so the test does not idle.
	scanWaitTimeout = 5 * time.Second
	scanPollInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		scanWaitTimeout = 5 * time.Minute
		scanPollInterval = 5 * time.Second
	})

	ctx, cancel := context.WithTimeout(context.Background(), scanWaitTimeout)
	defer cancel()
	summary, timedOut, failedMsg, lastFetchedAt := waitForScanCompletion(ctx, client, projectID, sbomID)
	if timedOut {
		t.Fatalf("waitForScanCompletion timed out unexpectedly (hits=%d)", atomic.LoadInt32(&hits))
	}
	if failedMsg != "" {
		t.Fatalf("waitForScanCompletion reported failed=%q", failedMsg)
	}
	if summary == nil {
		t.Fatal("summary is nil on completion")
	}
	if lastFetchedAt.IsZero() {
		t.Error("lastFetchedAt is zero on completion; expected the timestamp of the terminal poll")
	}
	if summary.Critical != 2 || summary.High != 3 || summary.Total != 5 {
		t.Errorf("summary = %+v, want critical=2 high=3 total=5", *summary)
	}
	// Codex R1 fix regression guard: KEV bucket must round-trip from the
	// server response through the polling loop so --fail-on kev has a
	// non-zero count to evaluate downstream in runScan.
	if summary.KEV != 1 {
		t.Errorf("summary.KEV = %d, want 1 (waitForScanCompletion must propagate KEV from scan-status)", summary.KEV)
	}
}

// TestWaitForScanCompletion_TimesOut verifies the timeout path: when the
// server never transitions to a terminal state, the loop returns
// timedOut=true with no summary, which scan.go maps to exit code 2.
func TestWaitForScanCompletion_TimesOut(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := api.ScanStatusResponse{
			Status: "running",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := api.NewClient(server.URL, "test-key")

	scanWaitTimeout = 80 * time.Millisecond
	scanPollInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		scanWaitTimeout = 5 * time.Minute
		scanPollInterval = 5 * time.Second
	})

	ctx, cancel := context.WithTimeout(context.Background(), scanWaitTimeout)
	defer cancel()
	summary, timedOut, failedMsg, _ := waitForScanCompletion(ctx, client, "p", "s")
	if !timedOut {
		t.Errorf("expected timeout, got summary=%+v failedMsg=%q", summary, failedMsg)
	}
}

// TestWaitForScanCompletion_Failed verifies the server-side failure path
// surfaces the error message back to the caller and is not silently
// treated as success. scan.go maps this to exit code 2 as well.
func TestWaitForScanCompletion_Failed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := api.ScanStatusResponse{
			Status: "failed",
			Error:  "nvd: rate limited",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := api.NewClient(server.URL, "test-key")

	scanWaitTimeout = 5 * time.Second
	scanPollInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		scanWaitTimeout = 5 * time.Minute
		scanPollInterval = 5 * time.Second
	})

	ctx, cancel := context.WithTimeout(context.Background(), scanWaitTimeout)
	defer cancel()
	_, timedOut, failedMsg, _ := waitForScanCompletion(ctx, client, "p", "s")
	if timedOut {
		t.Error("expected failed path, not timeout")
	}
	if failedMsg != "nvd: rate limited" {
		t.Errorf("failedMsg = %q, want %q", failedMsg, "nvd: rate limited")
	}
}

// TestWaitForScanCompletion_TimeoutPreservesPartialCounts verifies the
// Codex R5 fix: when polling times out after one or more successful
// status fetches, the function must return the most recent VulnerabilitySummary
// snapshot (NOT nil) together with the timestamp of that fetch. Before
// the fix, timeout discarded the snapshot, runScan fell back to the
// upload response's zero counts, and the result box rendered "なし ✅"
// next to the timeout warning — silently hiding real partial findings.
func TestWaitForScanCompletion_TimeoutPreservesPartialCounts(t *testing.T) {
	const projectID = "33333333-3333-3333-3333-333333333333"
	const sbomID = "44444444-4444-4444-4444-444444444444"

	// Server hits 1..2 return a running snapshot with real counts; hits
	// 3+ block until the test's ctx cancels them. This forces the loop to
	// observe a non-empty snapshot before timeout fires.
	hung := make(chan struct{})
	t.Cleanup(func() { close(hung) })

	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n <= 2 {
			resp := api.ScanStatusResponse{
				Status:    "running",
				SbomID:    sbomID,
				ProjectID: projectID,
				Vulnerabilities: api.VulnerabilitySummary{
					Critical: 1, High: 2, Medium: 0, Low: 0, KEV: 1, Total: 3,
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		// Hang until ctx cancels or the test ends.
		select {
		case <-r.Context().Done():
		case <-hung:
		}
	}))
	defer server.Close()

	client := api.NewClient(server.URL, "test-key")

	// Tight ctx deadline so the test finishes fast, but long enough for
	// the first two polls (10ms interval) to land.
	scanWaitTimeout = 300 * time.Millisecond
	scanPollInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		scanWaitTimeout = 5 * time.Minute
		scanPollInterval = 5 * time.Second
	})

	ctx, cancel := context.WithTimeout(context.Background(), scanWaitTimeout)
	defer cancel()

	before := time.Now()
	summary, timedOut, failedMsg, lastFetchedAt := waitForScanCompletion(ctx, client, projectID, sbomID)
	after := time.Now()

	if !timedOut {
		t.Fatalf("expected timeout, got summary=%+v failedMsg=%q", summary, failedMsg)
	}
	if failedMsg != "" {
		t.Errorf("failedMsg = %q, want empty (timeout path)", failedMsg)
	}
	if summary == nil {
		t.Fatal("summary is nil on timeout — partial counts were discarded (Codex R5 regression)")
	}
	if summary.Critical != 1 || summary.High != 2 || summary.KEV != 1 || summary.Total != 3 {
		t.Errorf("summary = %+v, want critical=1 high=2 kev=1 total=3 (latest running snapshot)", *summary)
	}
	if lastFetchedAt.IsZero() {
		t.Error("lastFetchedAt is zero; expected the timestamp of the last successful poll")
	}
	if lastFetchedAt.Before(before) || lastFetchedAt.After(after) {
		t.Errorf("lastFetchedAt=%s out of bounds [%s, %s]", lastFetchedAt, before, after)
	}
	if got := atomic.LoadInt32(&hits); got < 2 {
		t.Errorf("server hits=%d, want >=2 (loop should poll at least the two non-hung responses)", got)
	}
}

// TestWaitForScanCompletion_TimeoutNoSuccessfulPoll covers the edge case
// where ctx fires before any GetScanStatus call returns successfully —
// summary must be nil and lastFetchedAt must be the zero time so callers
// can distinguish "no snapshot at all" from "stale snapshot from t=X".
func TestWaitForScanCompletion_TimeoutNoSuccessfulPoll(t *testing.T) {
	// Server hangs forever — never writes a response.
	hung := make(chan struct{})
	t.Cleanup(func() { close(hung) })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-hung:
		}
	}))
	defer server.Close()

	client := api.NewClient(server.URL, "test-key")

	scanWaitTimeout = 80 * time.Millisecond
	scanPollInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		scanWaitTimeout = 5 * time.Minute
		scanPollInterval = 5 * time.Second
	})

	ctx, cancel := context.WithTimeout(context.Background(), scanWaitTimeout)
	defer cancel()
	summary, timedOut, _, lastFetchedAt := waitForScanCompletion(ctx, client, "p", "s")
	if !timedOut {
		t.Fatal("expected timeout")
	}
	if summary != nil {
		t.Errorf("summary = %+v, want nil when no poll ever returned", *summary)
	}
	if !lastFetchedAt.IsZero() {
		t.Errorf("lastFetchedAt = %s, want zero time when no poll ever returned", lastFetchedAt)
	}
}

// TestWaitForScanCompletion_ContextCancelAbortsHungRequest verifies the
// Codex R4 finding 2 fix: when the context fires while an HTTP request
// is hung (server never writes a response), the polling loop returns
// timedOut=true within a few ms of the context deadline — NOT after the
// httpClient default 60s. Before the fix the GetScanStatus request was
// not bound to ctx, so --wait-timeout=10s could still hang for up to
// 60s on a slow server.
func TestWaitForScanCompletion_ContextCancelAbortsHungRequest(t *testing.T) {
	// Server intentionally hangs forever — never writes a response.
	hung := make(chan struct{})
	t.Cleanup(func() { close(hung) })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-hung:
		}
	}))
	defer server.Close()

	client := api.NewClient(server.URL, "test-key")

	// Set the package-level wait timeout high enough that, if the HTTP
	// request were bound to httpClient.Timeout (the broken behavior) the
	// test would observe a much longer elapsed time. The actual deadline
	// we care about is the ctx below.
	scanWaitTimeout = 10 * time.Second
	scanPollInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		scanWaitTimeout = 5 * time.Minute
		scanPollInterval = 5 * time.Second
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, timedOut, _, _ := waitForScanCompletion(ctx, client, "p", "s")
	elapsed := time.Since(start)

	if !timedOut {
		t.Errorf("expected timeout when ctx cancels mid-request")
	}
	// Allow generous slack but reject the "waited the full 60s httpClient
	// default" failure mode (and anything close to it).
	if elapsed > 2*time.Second {
		t.Errorf("waitForScanCompletion took %s with a 100ms ctx — HTTP request is not bound to ctx (Codex R4 finding 2 regression)", elapsed)
	}
}

// TestResolveCredentials_FailSoftMissingConfig verifies the Codex R2 fix:
// when ~/.sbomhub/config.yaml does not exist (e.g. a CI runner that
// never ran `sbomhub login`), `--api-url` / `--api-key` flags and
// SBOMHUB_API_URL / SBOMHUB_API_KEY env vars are honoured anyway.
//
// Before the fix, scan.go called config.Load which returned an error for
// the missing file, killing the run with exitAPIError before the flag /
// env layer could even be inspected.
func TestResolveCredentials_FailSoftMissingConfig(t *testing.T) {
	tmpDir := t.TempDir() // intentionally no config.yaml

	// Reset env + globals so this test doesn't leak into / from siblings.
	t.Setenv("SBOMHUB_API_URL", "")
	t.Setenv("SBOMHUB_API_KEY", "")
	saveURL, saveKey := apiURL, apiKey
	t.Cleanup(func() { apiURL, apiKey = saveURL, saveKey })

	// Sub-test 1: CLI flag layer only.
	apiURL = "https://flag.example.com"
	apiKey = "sbh_flag"
	cfg, err := resolveCredentials(tmpDir)
	if err != nil {
		t.Fatalf("resolveCredentials() error = %v, want nil with flags + no config", err)
	}
	if cfg.APIURL != "https://flag.example.com" || cfg.APIKey != "sbh_flag" {
		t.Errorf("flags not applied: APIURL=%q APIKey=%q", cfg.APIURL, cfg.APIKey)
	}

	// Sub-test 2: env layer only. (Clear the flag globals.)
	apiURL, apiKey = "", ""
	t.Setenv("SBOMHUB_API_URL", "https://env.example.com")
	t.Setenv("SBOMHUB_API_KEY", "sbh_env")
	cfg, err = resolveCredentials(tmpDir)
	if err != nil {
		t.Fatalf("resolveCredentials() error = %v, want nil with env + no config", err)
	}
	if cfg.APIURL != "https://env.example.com" || cfg.APIKey != "sbh_env" {
		t.Errorf("env not applied: APIURL=%q APIKey=%q", cfg.APIURL, cfg.APIKey)
	}
}

// TestResolveCredentials_Precedence asserts the documented order
// CLI flag > env > config file > default. A regression here means a CI
// runner trying to override a stale ~/.sbomhub/config.yaml with --api-url
// would silently keep talking to the wrong API.
func TestResolveCredentials_Precedence(t *testing.T) {
	tmpDir := t.TempDir()
	if err := config.Save(&config.Config{
		APIURL: "https://file.example.com",
		APIKey: "sbh_file",
	}, tmpDir); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	saveURL, saveKey := apiURL, apiKey
	t.Cleanup(func() { apiURL, apiKey = saveURL, saveKey })

	// File + env: env wins over file.
	apiURL, apiKey = "", ""
	t.Setenv("SBOMHUB_API_URL", "https://env.example.com")
	t.Setenv("SBOMHUB_API_KEY", "sbh_env")
	cfg, err := resolveCredentials(tmpDir)
	if err != nil {
		t.Fatalf("resolveCredentials() error = %v", err)
	}
	if cfg.APIURL != "https://env.example.com" || cfg.APIKey != "sbh_env" {
		t.Errorf("env should beat file: APIURL=%q APIKey=%q", cfg.APIURL, cfg.APIKey)
	}

	// File + env + flag: flag wins over both.
	apiURL = "https://flag.example.com"
	apiKey = "sbh_flag"
	cfg, err = resolveCredentials(tmpDir)
	if err != nil {
		t.Fatalf("resolveCredentials() error = %v", err)
	}
	if cfg.APIURL != "https://flag.example.com" || cfg.APIKey != "sbh_flag" {
		t.Errorf("flag should beat env and file: APIURL=%q APIKey=%q", cfg.APIURL, cfg.APIKey)
	}

	// File only (no env, no flag): file value is used unchanged.
	apiURL, apiKey = "", ""
	t.Setenv("SBOMHUB_API_URL", "")
	t.Setenv("SBOMHUB_API_KEY", "")
	cfg, err = resolveCredentials(tmpDir)
	if err != nil {
		t.Fatalf("resolveCredentials() error = %v", err)
	}
	if cfg.APIURL != "https://file.example.com" || cfg.APIKey != "sbh_file" {
		t.Errorf("file value lost when no env/flag: APIURL=%q APIKey=%q", cfg.APIURL, cfg.APIKey)
	}
}

// TestFormatScanVulnSummary_UnknownNotDropped verifies the Codex R2
// second fix: a scan whose only findings live in the `unknown` bucket
// must NOT render as "なし ✅". Before the fix the formatter only
// inspected critical/high/medium/low/kev, so an N-Unknown scan looked
// clean — silently hiding the data-quality finding from the operator.
func TestFormatScanVulnSummary_UnknownNotDropped(t *testing.T) {
	cases := []struct {
		name    string
		summary *api.VulnerabilitySummary
		wantHas string
		wantNot string
	}{
		{
			name:    "unknown only",
			summary: &api.VulnerabilitySummary{Unknown: 5, Total: 5},
			wantHas: "5 Unknown",
			wantNot: "なし",
		},
		{
			name:    "unknown + critical both shown",
			summary: &api.VulnerabilitySummary{Critical: 2, Unknown: 3, Total: 5},
			wantHas: "3 Unknown",
		},
		{
			name:    "all zero still says なし",
			summary: &api.VulnerabilitySummary{},
			wantHas: "なし",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatScanVulnSummary(nil, tc.summary)
			if tc.wantHas != "" && !strings.Contains(got, tc.wantHas) {
				t.Errorf("formatScanVulnSummary() = %q, want substring %q", got, tc.wantHas)
			}
			if tc.wantNot != "" && strings.Contains(got, tc.wantNot) {
				t.Errorf("formatScanVulnSummary() = %q, must not contain %q (Unknown was dropped)", got, tc.wantNot)
			}
		})
	}
}

// TestFormatScanVulnSummary_ServerTotalZeroButBucketsPopulated verifies
// the Codex R6 finding 2 fix: when the server returns total=0 but one or
// more per-severity buckets are non-zero (partial response, streamed
// scan, or an older server that omits the total field), the formatter
// must compute the total from the buckets and surface those findings —
// NOT fall back to "なし ✅".
//
// Before the fix, the guard was `if total == 0 && kev == 0 && u == 0`,
// which let a `Critical=1, Total=0` response render as "なし ✅", silently
// hiding the most severe possible finding.
func TestFormatScanVulnSummary_ServerTotalZeroButBucketsPopulated(t *testing.T) {
	cases := []struct {
		name    string
		summary *api.VulnerabilitySummary
		wantHas string // substring that MUST appear
		wantNot string // substring that MUST NOT appear
	}{
		{
			name: "total=0 + critical=1 surfaces critical",
			summary: &api.VulnerabilitySummary{
				Critical: 1, Total: 0,
			},
			wantHas: "1 Critical",
			wantNot: "なし",
		},
		{
			name: "total=0 + high=2 + medium=3 surfaces both",
			summary: &api.VulnerabilitySummary{
				High: 2, Medium: 3, Total: 0,
			},
			wantHas: "2 High",
			wantNot: "なし",
		},
		{
			name: "total=0 + low=1 surfaces low",
			summary: &api.VulnerabilitySummary{
				Low: 1, Total: 0,
			},
			wantHas: "1 Low",
			wantNot: "なし",
		},
		{
			name: "all buckets zero + total=0 still says なし",
			summary: &api.VulnerabilitySummary{
				Total: 0,
			},
			wantHas: "なし",
		},
		{
			name: "all buckets zero + total>0 still says なし (we trust the buckets)",
			// Pathological server: claims findings exist but does not
			// itemize them. We render "なし" because the per-severity
			// breakdown is what the operator actually consumes.
			summary: &api.VulnerabilitySummary{
				Total: 42,
			},
			wantHas: "なし",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatScanVulnSummary(nil, tc.summary)
			if tc.wantHas != "" && !strings.Contains(got, tc.wantHas) {
				t.Errorf("formatScanVulnSummary() = %q, want substring %q", got, tc.wantHas)
			}
			if tc.wantNot != "" && strings.Contains(got, tc.wantNot) {
				t.Errorf("formatScanVulnSummary() = %q, must not contain %q (server total=0 short-circuit hid real findings)", got, tc.wantNot)
			}
		})
	}
}

// TestRunScan_FailOnRequiresWaitForScan verifies the Codex R3 fix: when
// `--fail-on` is set, passing `--wait-for-scan=false` must be rejected at
// startup with a usage error. Before the fix, the combination silently
// succeeded (exit 0) after upload because the threshold check was
// short-circuited — letting critical findings slip past a gated CI.
//
// We drive runScan directly with the package globals (the same surface
// cobra binds onto), so we exercise the real guard path without standing
// up a fake server: the guard fires before any API call.
func TestRunScan_FailOnRequiresWaitForScan(t *testing.T) {
	saveFailOn, saveWait := scanFailOn, scanWaitForScan
	t.Cleanup(func() {
		scanFailOn = saveFailOn
		scanWaitForScan = saveWait
	})

	cases := []struct {
		name        string
		failOn      string
		waitForScan bool
		wantErr     bool
		wantSubstr  string // expected fragment in the error message
	}{
		{
			name:        "fail-on high + wait-for-scan=false rejected",
			failOn:      "high",
			waitForScan: false,
			wantErr:     true,
			wantSubstr:  "--fail-on requires --wait-for-scan=true",
		},
		{
			name:        "fail-on critical + wait-for-scan=false rejected",
			failOn:      "critical",
			waitForScan: false,
			wantErr:     true,
			wantSubstr:  "--fail-on requires --wait-for-scan=true",
		},
		{
			name:        "fail-on kev + wait-for-scan=false rejected",
			failOn:      "kev",
			waitForScan: false,
			wantErr:     true,
			wantSubstr:  "--fail-on requires --wait-for-scan=true",
		},
		{
			name:        "invalid --fail-on value still rejected (precedence: value check first)",
			failOn:      "bogus",
			waitForScan: false,
			wantErr:     true,
			wantSubstr:  "--fail-on の値が不正です",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scanFailOn = tc.failOn
			scanWaitForScan = tc.waitForScan

			// Point at a path that exists so we get past the os.Stat
			// guard and reach the --fail-on/--wait-for-scan check.
			err := runScan(scanCmd, []string{t.TempDir()})
			if tc.wantErr && err == nil {
				t.Fatalf("runScan returned nil, want error containing %q", tc.wantSubstr)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("runScan returned err=%v, want nil", err)
			}
			if tc.wantErr && !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("runScan err = %q, want substring %q", err.Error(), tc.wantSubstr)
			}
		})
	}
}

// TestRunScan_FailOnGuardAllowsValidCombos verifies the inverse of the
// R3 guard: combinations that are spec-legal must NOT be rejected at the
// startup check (they may fail later for unrelated reasons like missing
// credentials, but the --fail-on/--wait-for-scan invariant should be
// satisfied). We assert by checking that the error, if any, is not the
// guard message.
func TestRunScan_FailOnGuardAllowsValidCombos(t *testing.T) {
	saveFailOn, saveWait := scanFailOn, scanWaitForScan
	t.Cleanup(func() {
		scanFailOn = saveFailOn
		scanWaitForScan = saveWait
	})

	cases := []struct {
		name        string
		failOn      string
		waitForScan bool
	}{
		{"fail-on high + wait-for-scan=true ok", "high", true},
		{"fail-on critical + wait-for-scan=true ok", "critical", true},
		// --fail-on unset means the guard is irrelevant regardless of
		// the wait-for-scan value.
		{"no fail-on + wait-for-scan=false ok", "", false},
		{"no fail-on + wait-for-scan=true ok", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scanFailOn = tc.failOn
			scanWaitForScan = tc.waitForScan

			// dry-run avoids needing real credentials / API server;
			// the guard runs before the dry-run short-circuit so this
			// still exercises it.
			saveDry := scanDryRun
			scanDryRun = true
			t.Cleanup(func() { scanDryRun = saveDry })

			err := runScan(scanCmd, []string{t.TempDir()})
			if err != nil && strings.Contains(err.Error(), "--fail-on requires --wait-for-scan=true") {
				t.Errorf("guard fired on valid combo: err=%v", err)
			}
		})
	}
}

// TestScanExitError_ExitCode verifies the scanExitError contract that
// main.go relies on for exit-code routing.
func TestScanExitError_ExitCode(t *testing.T) {
	cases := []struct {
		name string
		err  *scanExitError
		want int
	}{
		{"threshold", &scanExitError{code: exitThresholdExceeded, msg: "x"}, 1},
		{"timeout", &scanExitError{code: exitScanTimeout, msg: "x"}, 2},
		{"api error", &scanExitError{code: exitAPIError, msg: "x"}, 3},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.ExitCode(); got != tt.want {
				t.Errorf("ExitCode() = %d, want %d", got, tt.want)
			}
		})
	}
}
