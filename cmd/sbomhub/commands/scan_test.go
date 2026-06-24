package commands

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	summary, timedOut, failedMsg := waitForScanCompletion(client, projectID, sbomID)
	if timedOut {
		t.Fatalf("waitForScanCompletion timed out unexpectedly (hits=%d)", atomic.LoadInt32(&hits))
	}
	if failedMsg != "" {
		t.Fatalf("waitForScanCompletion reported failed=%q", failedMsg)
	}
	if summary == nil {
		t.Fatal("summary is nil on completion")
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

	summary, timedOut, failedMsg := waitForScanCompletion(client, "p", "s")
	if !timedOut {
		t.Errorf("expected timeout, got summary=%v failedMsg=%q", summary, failedMsg)
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

	_, timedOut, failedMsg := waitForScanCompletion(client, "p", "s")
	if timedOut {
		t.Error("expected failed path, not timeout")
	}
	if failedMsg != "nvd: rate limited" {
		t.Errorf("failedMsg = %q, want %q", failedMsg, "nvd: rate limited")
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
