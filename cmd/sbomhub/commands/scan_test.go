package commands

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/youichi-uda/sbomhub-cli/internal/api"
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
				Critical: 2, High: 3, Medium: 0, Low: 0, Total: 5,
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
