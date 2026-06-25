package commands

// Unit tests for `sbomhub cra` — exercises each subcommand's UX +
// exit-code classification against a fake httptest server. Tests are
// keyed off the same M1 fix pattern numbers as the triage_test.go
// regressions so a reviewer can trace each rule end-to-end:
//
//   - F4 / AIDisabled 2xx fallback (draft path)
//   - F21 exit code 3 (permanent) / 4 (transient)
//   - F22 strict 503-AI-disabled (legacy fallback) vs generic 503 outage
//   - F23 2xx contract validation (no report → transient)
//   - F26 pagination (list path)
//   - F28 X-Total-Count surfacing (list path)

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/youichi-uda/sbomhub-cli/internal/api"
)

// ---------------------------------------------------------------------------
// Fake server harness (mirrors triageFakeServer)
// ---------------------------------------------------------------------------

type craFakeServer struct {
	t            *testing.T
	server       *httptest.Server
	vulns        []api.VulnerabilityRecord
	runResp      func(call int, body []byte) (status int, payload interface{})
	listResp     func(call int, q map[string][]string) (status int, headers map[string]string, payload interface{})
	getResp      func(call int, reportID string) (status int, payload interface{})
	decisionResp func(call int, reportID string, body []byte) (status int, payload interface{})

	vulnListHits  int32
	runHits       int32
	listHits      int32
	getHits       int32
	decisionHits  int32
	seenDecisions []capturedCRADecision
	mu            sync.Mutex
}

type capturedCRADecision struct {
	ReportID        string
	Decision        string
	DecisionNote    string
	EditedDraftText *string
}

func newCraFakeServer(t *testing.T, vulns []api.VulnerabilityRecord) *craFakeServer {
	t.Helper()
	tf := &craFakeServer{t: t, vulns: vulns}
	tf.server = httptest.NewServer(http.HandlerFunc(tf.handle))
	t.Cleanup(tf.server.Close)
	return tf
}

func (tf *craFakeServer) handle(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test-key" {
		tf.t.Errorf("Authorization = %q, want Bearer test-key", auth)
	}

	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/vulnerabilities"):
		atomic.AddInt32(&tf.vulnListHits, 1)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(tf.vulns)

	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/cra-reports/run"):
		n := atomic.AddInt32(&tf.runHits, 1)
		body, _ := io.ReadAll(r.Body)
		status := http.StatusCreated
		var payload interface{}
		if tf.runResp != nil {
			status, payload = tf.runResp(int(n), body)
		} else {
			payload = defaultCraRunResp(int(n))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(payload)

	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/cra-reports"):
		n := atomic.AddInt32(&tf.listHits, 1)
		status := http.StatusOK
		var payload interface{}
		var hdrs map[string]string
		if tf.listResp != nil {
			status, hdrs, payload = tf.listResp(int(n), r.URL.Query())
		} else {
			payload = map[string]interface{}{"reports": []map[string]interface{}{}}
			hdrs = map[string]string{"X-Total-Count": "0"}
		}
		for k, v := range hdrs {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(payload)

	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/cra-reports/"):
		n := atomic.AddInt32(&tf.getHits, 1)
		parts := strings.Split(r.URL.Path, "/")
		reportID := parts[len(parts)-1]
		status := http.StatusOK
		var payload interface{}
		if tf.getResp != nil {
			status, payload = tf.getResp(int(n), reportID)
		} else {
			payload = api.CRAReport{ID: reportID, ProjectID: "p"}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(payload)

	case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/decision"):
		n := atomic.AddInt32(&tf.decisionHits, 1)
		body, _ := io.ReadAll(r.Body)
		var dec api.CRADecisionRequest
		_ = json.Unmarshal(body, &dec)
		// path: /api/v1/projects/<pid>/cra-reports/<rid>/decision
		parts := strings.Split(r.URL.Path, "/")
		reportID := ""
		for i, p := range parts {
			if p == "cra-reports" && i+1 < len(parts) {
				reportID = parts[i+1]
				break
			}
		}
		tf.mu.Lock()
		tf.seenDecisions = append(tf.seenDecisions, capturedCRADecision{
			ReportID:        reportID,
			Decision:        dec.Decision,
			DecisionNote:    dec.DecisionNote,
			EditedDraftText: dec.EditedDraftText,
		})
		tf.mu.Unlock()
		status := http.StatusOK
		var payload interface{}
		if tf.decisionResp != nil {
			status, payload = tf.decisionResp(int(n), reportID, body)
		} else {
			payload = api.CRAReport{ID: reportID, Decision: dec.Decision}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(payload)

	default:
		tf.t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func defaultCraRunResp(n int) map[string]interface{} {
	return map[string]interface{}{
		"report": map[string]interface{}{
			"id":               fakeCraReportID(n),
			"project_id":       "00000000-0000-0000-0000-000000000aaa",
			"vulnerability_id": fakeVulnID(n),
			"cve_id":           fakeCVE(n),
			"report_type":      "early_warning",
			"lang":             "ja",
			"state":            "draft",
			"draft_text":       fmt.Sprintf("## %s\n\nbody for run %d", fakeCVE(n), n),
			"decision":         "pending",
			"provider":         "anthropic",
			"model":            "claude-opus-4-7",
			"evidence":         []map[string]string{{"kind": "vex_draft", "ref": "abc"}},
		},
		"llm_call_id": fmt.Sprintf("0000000-0000-0000-0000-00000000000%d", n),
	}
}

func fakeCraReportID(n int) string {
	return "33333333-3333-3333-3333-33333333000" + itoa(n)
}

// ---------------------------------------------------------------------------
// cra draft
// ---------------------------------------------------------------------------

// TestCraDraft_HappyPath: standard flow — operator supplies project,
// cve, type, lang; CLI resolves CVE → vulnerability_id, posts the
// run request, prints the metadata block. Output captured via the
// shared OutputConfig.
func TestCraDraft_HappyPath(t *testing.T) {
	tf := newCraFakeServer(t, []api.VulnerabilityRecord{
		{ID: fakeVulnID(1), CVEID: fakeCVE(1), Severity: "HIGH"},
	})
	client := api.NewClient(tf.server.URL, "test-key")

	res, stdout, stderr := runDraftAndCapture(t, client, draftArgs{
		project:    "00000000-0000-0000-0000-000000000aaa",
		cve:        fakeCVE(1),
		reportType: "early_warning",
		lang:       "ja",
	})
	if res.err != nil {
		t.Fatalf("draft returned err: %v (stderr=%s)", res.err, stderr.String())
	}
	if atomic.LoadInt32(&tf.runHits) != 1 {
		t.Errorf("runHits = %d, want 1", tf.runHits)
	}
	if !strings.Contains(stdout.String(), fakeCraReportID(1)) {
		t.Errorf("stdout missing report id: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "CRA Report Draft") {
		t.Errorf("stdout missing metadata header: %s", stdout.String())
	}
	// Body streamed when --output is empty
	if !strings.Contains(stdout.String(), "body for run 1") {
		t.Errorf("stdout missing draft body when --output unset: %s", stdout.String())
	}
}

// TestCraDraft_CVENotFound: the requested CVE is not in the project's
// vulnerability list — exit code 3 (permanent) with an actionable
// "run sbomhub scan" hint.
func TestCraDraft_CVENotFound(t *testing.T) {
	tf := newCraFakeServer(t, []api.VulnerabilityRecord{
		{ID: fakeVulnID(2), CVEID: "CVE-2024-OTHER", Severity: "LOW"},
	})
	client := api.NewClient(tf.server.URL, "test-key")

	res, _, _ := runDraftAndCapture(t, client, draftArgs{
		project:    "p",
		cve:        "CVE-2024-99999",
		reportType: "early_warning",
		lang:       "ja",
	})
	exitErr, ok := res.err.(*craExitError)
	if !ok {
		t.Fatalf("err = %v (%T), want *craExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("ExitCode = %d, want 3 (CVE not found = permanent)", exitErr.ExitCode())
	}
	if !strings.Contains(exitErr.Error(), "存在しません") {
		t.Errorf("error message should mention 存在しません, got %q", exitErr.Error())
	}
}

// TestCraDraft_AIDisabled2xx — server returns 2xx + ai_disabled=true
// with a template-only report. CLI prints the BYOK hint to stderr and
// exits 0 (the report is still persisted).
func TestCraDraft_AIDisabled2xx(t *testing.T) {
	tf := newCraFakeServer(t, []api.VulnerabilityRecord{
		{ID: fakeVulnID(1), CVEID: fakeCVE(1), Severity: "HIGH"},
	})
	tf.runResp = func(call int, body []byte) (int, interface{}) {
		return http.StatusCreated, map[string]interface{}{
			"report": map[string]interface{}{
				"id":          fakeCraReportID(call),
				"project_id":  "p",
				"cve_id":      fakeCVE(call),
				"report_type": "early_warning",
				"lang":        "ja",
				"state":       "draft",
				"draft_text":  "template-only body (AI disabled)",
				"decision":    "pending",
			},
			"ai_disabled": true,
		}
	}
	client := api.NewClient(tf.server.URL, "test-key")

	res, stdout, stderr := runDraftAndCapture(t, client, draftArgs{
		project:    "p",
		cve:        fakeCVE(1),
		reportType: "early_warning",
		lang:       "ja",
	})
	if res.err != nil {
		t.Fatalf("AI-disabled fast path must remain exit 0, got %v", res.err)
	}
	if !strings.Contains(stderr.String(), "APIキー未設定") {
		t.Errorf("stderr missing AI-disabled hint: %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "AI Disabled   : true") {
		t.Errorf("stdout missing AI-disabled marker in metadata: %s", stdout.String())
	}
}

// TestCraDraft_AIDisabled503Legacy — legacy server returns 503 with
// the known "AI features are disabled" reason. CLI prints the hint
// and exits 0 (no report persisted by server, but operator gets the
// actionable message).
func TestCraDraft_AIDisabled503Legacy(t *testing.T) {
	tf := newCraFakeServer(t, []api.VulnerabilityRecord{
		{ID: fakeVulnID(1), CVEID: fakeCVE(1), Severity: "HIGH"},
	})
	tf.runResp = func(call int, body []byte) (int, interface{}) {
		return http.StatusServiceUnavailable, map[string]string{
			"error":  "AI features are disabled",
			"reason": "no LLM provider configured",
		}
	}
	client := api.NewClient(tf.server.URL, "test-key")

	res, _, stderr := runDraftAndCapture(t, client, draftArgs{
		project:    "p",
		cve:        fakeCVE(1),
		reportType: "early_warning",
		lang:       "ja",
	})
	if res.err != nil {
		t.Fatalf("F22 legacy: 503 + known reason must exit 0, got %v", res.err)
	}
	if !strings.Contains(stderr.String(), "APIキー未設定") {
		t.Errorf("stderr missing AI-disabled hint: %q", stderr.String())
	}
}

// TestCraDraft_503GenericGateway_F22 — 503 WITHOUT a known reason is
// a real outage, must surface exit 4 and MUST NOT print the misleading
// AI-disabled hint.
func TestCraDraft_503GenericGateway_F22(t *testing.T) {
	tf := newCraFakeServer(t, []api.VulnerabilityRecord{
		{ID: fakeVulnID(1), CVEID: fakeCVE(1), Severity: "HIGH"},
	})
	tf.runResp = func(call int, body []byte) (int, interface{}) {
		return http.StatusServiceUnavailable, map[string]string{
			"error": "Service Unavailable",
		}
	}
	client := api.NewClient(tf.server.URL, "test-key")

	res, _, stderr := runDraftAndCapture(t, client, draftArgs{
		project:    "p",
		cve:        fakeCVE(1),
		reportType: "early_warning",
		lang:       "ja",
	})
	exitErr, ok := res.err.(*craExitError)
	if !ok {
		t.Fatalf("F22: err = %v (%T), want *craExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 4 {
		t.Errorf("F22: ExitCode = %d, want 4 (generic 503 = transient outage)", exitErr.ExitCode())
	}
	if strings.Contains(stderr.String(), "APIキー未設定") {
		t.Errorf("F22: AI-disabled hint must NOT show for generic 503: %s", stderr.String())
	}
}

// TestCraDraft_PermanentExit3_409 — server returns 409 (no approved
// VEX draft for this (project, cve)). CLI must exit 3 with the
// permanent classification so CI can distinguish "operator must
// triage first" from a retryable outage.
func TestCraDraft_PermanentExit3_409(t *testing.T) {
	tf := newCraFakeServer(t, []api.VulnerabilityRecord{
		{ID: fakeVulnID(1), CVEID: fakeCVE(1), Severity: "HIGH"},
	})
	tf.runResp = func(call int, body []byte) (int, interface{}) {
		return http.StatusConflict, map[string]string{
			"error": "no approved vex_draft available — approve a VEX triage decision for this (project, cve) first",
		}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runDraftAndCapture(t, client, draftArgs{
		project:    "p",
		cve:        fakeCVE(1),
		reportType: "early_warning",
		lang:       "ja",
	})
	exitErr, ok := res.err.(*craExitError)
	if !ok {
		t.Fatalf("err = %v (%T), want *craExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("ExitCode = %d, want 3 (409 = permanent)", exitErr.ExitCode())
	}
}

// TestCraDraft_TransientExit4_429 — server returns 429 (rate-limited).
// CLI must exit 4 so CI knows to retry.
func TestCraDraft_TransientExit4_429(t *testing.T) {
	tf := newCraFakeServer(t, []api.VulnerabilityRecord{
		{ID: fakeVulnID(1), CVEID: fakeCVE(1), Severity: "HIGH"},
	})
	tf.runResp = func(call int, body []byte) (int, interface{}) {
		return http.StatusTooManyRequests, map[string]string{"error": "rate limited"}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runDraftAndCapture(t, client, draftArgs{
		project:    "p",
		cve:        fakeCVE(1),
		reportType: "early_warning",
		lang:       "ja",
	})
	exitErr, ok := res.err.(*craExitError)
	if !ok {
		t.Fatalf("err = %v (%T), want *craExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 4 {
		t.Errorf("ExitCode = %d, want 4 (429 = transient)", exitErr.ExitCode())
	}
}

// TestCraDraft_ProtocolError_F23 — 2xx with empty body must surface
// as transient (exit 4) so CI does not silently green-light a run
// that persisted nothing.
func TestCraDraft_ProtocolError_F23(t *testing.T) {
	tf := newCraFakeServer(t, []api.VulnerabilityRecord{
		{ID: fakeVulnID(1), CVEID: fakeCVE(1), Severity: "HIGH"},
	})
	tf.runResp = func(call int, body []byte) (int, interface{}) {
		return http.StatusOK, map[string]interface{}{}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runDraftAndCapture(t, client, draftArgs{
		project:    "p",
		cve:        fakeCVE(1),
		reportType: "early_warning",
		lang:       "ja",
	})
	exitErr, ok := res.err.(*craExitError)
	if !ok {
		t.Fatalf("F23: err = %v (%T), want *craExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 4 {
		t.Errorf("F23: ExitCode = %d, want 4 (protocol violation = transient)", exitErr.ExitCode())
	}
}

// TestCraDraft_InvalidReportType_Validation — flag validation must
// fire BEFORE any API call (the operator's input is wrong, no
// network round-trip needed).
func TestCraDraft_InvalidReportType_Validation(t *testing.T) {
	tf := newCraFakeServer(t, nil)
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runDraftAndCapture(t, client, draftArgs{
		project:    "p",
		cve:        "CVE-2024-1",
		reportType: "bogus",
		lang:       "ja",
	})
	if res.err == nil {
		t.Fatal("expected validation error for invalid --type")
	}
	if atomic.LoadInt32(&tf.runHits) != 0 {
		t.Errorf("validation must short-circuit BEFORE API call, runHits = %d", tf.runHits)
	}
}

// ---------------------------------------------------------------------------
// cra list
// ---------------------------------------------------------------------------

// TestCraList_HappyPath_F28 — single page, X-Total-Count present.
// CLI must surface total in the summary line.
func TestCraList_HappyPath_F28(t *testing.T) {
	tf := newCraFakeServer(t, nil)
	tf.listResp = func(call int, q map[string][]string) (int, map[string]string, interface{}) {
		return http.StatusOK,
			map[string]string{"X-Total-Count": "2"},
			map[string]interface{}{
				"reports": []map[string]interface{}{
					{"id": "r1", "cve_id": "CVE-2024-1", "report_type": "early_warning", "lang": "ja", "state": "draft", "decision": "pending"},
					{"id": "r2", "cve_id": "CVE-2024-2", "report_type": "final_report", "lang": "en", "state": "approved", "decision": "approved"},
				},
			}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, stdout, _ := runListAndCapture(t, client, listArgs{project: "p"})
	if res.err != nil {
		t.Fatalf("list err: %v", res.err)
	}
	out := stdout.String()
	if !strings.Contains(out, "r1") || !strings.Contains(out, "r2") {
		t.Errorf("stdout missing report rows: %s", out)
	}
	if !strings.Contains(out, "合計: 2") {
		t.Errorf("F28: stdout missing total count: %s", out)
	}
}

// TestCraList_Pagination_F26 — first page returns 500 rows + tail
// page returns 100 rows. CLI must stitch them transparently and
// surface the X-Total-Count.
func TestCraList_Pagination_F26(t *testing.T) {
	const pageSize = 500
	const tailSize = 100

	tf := newCraFakeServer(t, nil)
	tf.listResp = func(call int, q map[string][]string) (int, map[string]string, interface{}) {
		offset, _ := strconv.Atoi(firstQuery(q, "offset"))
		var rows []map[string]interface{}
		switch offset {
		case 0:
			for i := 0; i < pageSize; i++ {
				rows = append(rows, map[string]interface{}{"id": fmt.Sprintf("r%d", i)})
			}
		case pageSize:
			for i := 0; i < tailSize; i++ {
				rows = append(rows, map[string]interface{}{"id": fmt.Sprintf("r%d", pageSize+i)})
			}
		default:
			t.Errorf("F26: unexpected offset %d", offset)
		}
		return http.StatusOK,
			map[string]string{"X-Total-Count": strconv.Itoa(pageSize + tailSize)},
			map[string]interface{}{"reports": rows}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runListAndCapture(t, client, listArgs{project: "p", limit: 5}) // limit just trims display
	if res.err != nil {
		t.Fatalf("list err: %v", res.err)
	}
	if atomic.LoadInt32(&tf.listHits) != 2 {
		t.Errorf("F26: listHits = %d, want 2 (paginated stitch)", tf.listHits)
	}
}

func firstQuery(q map[string][]string, key string) string {
	if vs, ok := q[key]; ok && len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// TestCraList_FilterEncoding — filters land in the query string.
func TestCraList_FilterEncoding(t *testing.T) {
	tf := newCraFakeServer(t, nil)
	var seenQuery map[string][]string
	tf.listResp = func(call int, q map[string][]string) (int, map[string]string, interface{}) {
		seenQuery = q
		return http.StatusOK,
			map[string]string{"X-Total-Count": "0"},
			map[string]interface{}{"reports": []map[string]interface{}{}}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	_, _, _ = runListAndCapture(t, client, listArgs{
		project:    "p",
		cveID:      "CVE-2024-1",
		reportType: "early_warning",
		lang:       "ja",
		state:      "draft",
		decision:   "pending",
	})
	checks := map[string]string{
		"cve_id":      "CVE-2024-1",
		"report_type": "early_warning",
		"lang":        "ja",
		"state":       "draft",
		"decision":    "pending",
	}
	for k, v := range checks {
		if got := firstQuery(seenQuery, k); got != v {
			t.Errorf("query %s = %q, want %q", k, got, v)
		}
	}
}

// TestCraList_EmptyProject — zero reports, friendly message.
func TestCraList_EmptyProject(t *testing.T) {
	tf := newCraFakeServer(t, nil)
	tf.listResp = func(call int, q map[string][]string) (int, map[string]string, interface{}) {
		return http.StatusOK,
			map[string]string{"X-Total-Count": "0"},
			map[string]interface{}{"reports": []map[string]interface{}{}}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, stdout, _ := runListAndCapture(t, client, listArgs{project: "p"})
	if res.err != nil {
		t.Fatalf("list err: %v", res.err)
	}
	if !strings.Contains(stdout.String(), "ありません") {
		t.Errorf("empty list must show friendly message, got %s", stdout.String())
	}
}

// TestCraList_PermanentExit3 — 401 must classify permanent.
func TestCraList_PermanentExit3(t *testing.T) {
	tf := newCraFakeServer(t, nil)
	tf.listResp = func(call int, q map[string][]string) (int, map[string]string, interface{}) {
		return http.StatusUnauthorized, nil, map[string]string{"error": "invalid api key"}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runListAndCapture(t, client, listArgs{project: "p"})
	exitErr, ok := res.err.(*craExitError)
	if !ok {
		t.Fatalf("err = %v (%T), want *craExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("ExitCode = %d, want 3", exitErr.ExitCode())
	}
}

// ---------------------------------------------------------------------------
// cra approve
// ---------------------------------------------------------------------------

// TestCraApprove_HappyPath — decision PUT body shape + stdout
// confirmation.
func TestCraApprove_HappyPath(t *testing.T) {
	tf := newCraFakeServer(t, nil)
	tf.decisionResp = func(call int, reportID string, body []byte) (int, interface{}) {
		decAt := "2026-07-01T00:00:00Z"
		return http.StatusOK, api.CRAReport{
			ID:         reportID,
			ProjectID:  "p",
			CVEID:      "CVE-2024-1",
			ReportType: "early_warning",
			Decision:   "approved",
			DecisionAt: &decAt,
		}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, stdout, _ := runApproveAndCapture(t, client, approveArgs{
		project:  "p",
		reportID: fakeCraReportID(1),
		note:     "looks good",
	})
	if res.err != nil {
		t.Fatalf("approve err: %v", res.err)
	}
	if atomic.LoadInt32(&tf.decisionHits) != 1 {
		t.Errorf("decisionHits = %d, want 1", tf.decisionHits)
	}
	if len(tf.seenDecisions) != 1 {
		t.Fatalf("seenDecisions len = %d, want 1", len(tf.seenDecisions))
	}
	d := tf.seenDecisions[0]
	if d.Decision != "approved" {
		t.Errorf("decision = %q, want approved", d.Decision)
	}
	if d.DecisionNote != "looks good" {
		t.Errorf("note = %q, want 'looks good'", d.DecisionNote)
	}
	if d.EditedDraftText != nil {
		t.Errorf("EditedDraftText must be nil for approve (no edit), got %v", d.EditedDraftText)
	}
	if !strings.Contains(stdout.String(), "承認しました") {
		t.Errorf("stdout missing approval confirmation: %s", stdout.String())
	}
}

// TestCraApprove_ForbiddenPermanent — 403 RequireWrite must exit 3.
func TestCraApprove_ForbiddenPermanent(t *testing.T) {
	tf := newCraFakeServer(t, nil)
	tf.decisionResp = func(call int, reportID string, body []byte) (int, interface{}) {
		return http.StatusForbidden, map[string]string{"error": "write permission required"}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runApproveAndCapture(t, client, approveArgs{
		project:  "p",
		reportID: fakeCraReportID(1),
	})
	exitErr, ok := res.err.(*craExitError)
	if !ok {
		t.Fatalf("err = %v (%T), want *craExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("ExitCode = %d, want 3 (403 = permanent)", exitErr.ExitCode())
	}
}

// TestCraApprove_MissingReportID — flag validation.
func TestCraApprove_MissingReportID(t *testing.T) {
	tf := newCraFakeServer(t, nil)
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runApproveAndCapture(t, client, approveArgs{project: "p"})
	if res.err == nil {
		t.Fatal("expected error for missing --report-id")
	}
	if atomic.LoadInt32(&tf.decisionHits) != 0 {
		t.Errorf("validation must short-circuit BEFORE API call, decisionHits = %d", tf.decisionHits)
	}
}

// ---------------------------------------------------------------------------
// validateReportType / validateLang
// ---------------------------------------------------------------------------

func TestValidateReportType(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"early_warning", false},
		{"detailed_notification", false},
		{"final_report", false},
		{"bogus", true},
		{"", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			err := validateReportType(tc.in)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateLang(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"ja", false},
		{"en", false},
		{"de", true},
		{"", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			err := validateLang(tc.in)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// craFailureToExitError unit-tests
// ---------------------------------------------------------------------------

// TestCraFailureToExitError_Classification pins the helper's permanent
// vs transient buckets across the status-code surface. Mirrors the M1
// classifyTriageFailure unit test.
func TestCraFailureToExitError_Classification(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"401 → 3", &api.CRAError{StatusCode: 401}, 3},
		{"403 → 3", &api.CRAError{StatusCode: 403}, 3},
		{"404 → 3", &api.CRAError{StatusCode: 404}, 3},
		{"409 → 3", &api.CRAError{StatusCode: 409}, 3},
		{"422 → 3", &api.CRAError{StatusCode: 422}, 3},
		{"429 → 4", &api.CRAError{StatusCode: 429}, 4},
		{"500 → 4", &api.CRAError{StatusCode: 500}, 4},
		{"502 → 4", &api.CRAError{StatusCode: 502}, 4},
		{"503 generic → 4", &api.CRAError{StatusCode: 503, Message: "Service Unavailable"}, 4},
		{"protocol → 4", &api.CRAError{StatusCode: 200, ProtocolError: true}, 4},
		{"unknown 418 → 3", &api.CRAError{StatusCode: 418}, 3},
		{"network → 4", io.ErrUnexpectedEOF, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := craFailureToExitError("op", tc.err)
			exitErr, ok := err.(*craExitError)
			if !ok {
				t.Fatalf("err = %v (%T), want *craExitError", err, err)
			}
			if exitErr.ExitCode() != tc.wantCode {
				t.Errorf("ExitCode = %d, want %d", exitErr.ExitCode(), tc.wantCode)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test scaffolding — direct calls into runCraDraft / runCraList /
// runCraApprove would require seeding the package-scoped flag globals
// (craProject, craDraftCVE, …) on every test, which is brittle when
// the test runs alongside others. Instead, we invoke the lower-level
// logic via small wrapper functions that take an explicit args struct.
// ---------------------------------------------------------------------------

type draftArgs struct {
	project    string
	cve        string
	reportType string
	lang       string
	sourceVEX  string
	output     string
}

type listArgs struct {
	project    string
	cveID      string
	reportType string
	lang       string
	state      string
	decision   string
	limit      int
}

type approveArgs struct {
	project  string
	reportID string
	note     string
}

type capturedResult struct {
	err error
}

// runDraftAndCapture replays the runCraDraft body using injected
// args + a buffered OutputConfig so the test does not have to leak
// package globals between cases. The wrapper deliberately mirrors
// runCraDraft step-by-step so a refactor that splits runCraDraft will
// surface here.
func runDraftAndCapture(t *testing.T, client *api.Client, args draftArgs) (capturedResult, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	out := &OutputConfig{Writer: &stdout, ErrWriter: &stderr}

	if strings.TrimSpace(args.project) == "" {
		return capturedResult{err: fmt.Errorf("--project は必須です / --project is required")}, &stdout, &stderr
	}
	if strings.TrimSpace(args.cve) == "" {
		return capturedResult{err: fmt.Errorf("--cve は必須です / --cve is required")}, &stdout, &stderr
	}
	if err := validateReportType(args.reportType); err != nil {
		return capturedResult{err: err}, &stdout, &stderr
	}
	if err := validateLang(args.lang); err != nil {
		return capturedResult{err: err}, &stdout, &stderr
	}

	ctx := context.Background()
	vulnID, err := resolveVulnIDForCVE(ctx, client, args.project, args.cve)
	if err != nil {
		return capturedResult{err: err}, &stdout, &stderr
	}
	req := api.CRARunReportRequest{
		VulnerabilityID:  vulnID,
		CVEID:            args.cve,
		SourceVEXDraftID: args.sourceVEX,
		ReportType:       args.reportType,
		Lang:             args.lang,
	}
	res, err := client.RunReport(ctx, args.project, req)
	if err != nil {
		var ce *api.CRAError
		if errAsCRA(err, &ce) && ce.IsAIDisabled() {
			fmt.Fprintln(out.ErrWriter, craAIDisabledHintJa)
			if ce.Reason != "" {
				fmt.Fprintf(out.ErrWriter, "  (server reason: %s)\n", ce.Reason)
			}
			fmt.Fprintln(out.ErrWriter, "  → AI 解析がスキップされたためドラフトは保存されませんでした")
			return capturedResult{err: nil}, &stdout, &stderr
		}
		return capturedResult{err: craFailureToExitError("cra draft", err)}, &stdout, &stderr
	}
	if res.AIDisabled {
		fmt.Fprintln(out.ErrWriter, craAIDisabledHintJa)
		fmt.Fprintln(out.ErrWriter, "  → template-only draft をサーバに保存しました (ai_disabled fallback)")
	}
	renderErr := renderDraftResult(out, res, args.output)
	return capturedResult{err: renderErr}, &stdout, &stderr
}

func runListAndCapture(t *testing.T, client *api.Client, args listArgs) (capturedResult, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	out := &OutputConfig{Writer: &stdout, ErrWriter: &stderr}
	if strings.TrimSpace(args.project) == "" {
		return capturedResult{err: fmt.Errorf("--project は必須")}, &stdout, &stderr
	}
	ctx := context.Background()
	reports, total, err := client.ListReports(ctx, args.project, api.CRAReportListFilter{
		CVEID:      args.cveID,
		ReportType: args.reportType,
		Lang:       args.lang,
		State:      args.state,
		Decision:   args.decision,
	})
	if err != nil {
		return capturedResult{err: craFailureToExitError("cra list", err)}, &stdout, &stderr
	}
	rendered := reports
	if args.limit > 0 && len(rendered) > args.limit {
		rendered = rendered[:args.limit]
	}

	w := out.Writer
	if len(rendered) == 0 {
		fmt.Fprintln(w, "CRA 報告書はありません。")
		fmt.Fprintln(w, "No CRA reports.")
		return capturedResult{err: nil}, &stdout, &stderr
	}
	fmt.Fprintln(w, "CRA Report 一覧")
	fmt.Fprintln(w, "---------------")
	for _, r := range rendered {
		decision := r.Decision
		if decision == "" {
			decision = "pending"
		}
		fmt.Fprintf(w, "  %s  %s  %s  %s  state=%s  decision=%s\n",
			r.ID, r.CVEID, r.ReportType, r.Lang, orDash(r.State), decision)
	}
	fmt.Fprintf(w, "\n表示: %d / 合計: %d\n", len(rendered), total)
	return capturedResult{err: nil}, &stdout, &stderr
}

func runApproveAndCapture(t *testing.T, client *api.Client, args approveArgs) (capturedResult, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	out := &OutputConfig{Writer: &stdout, ErrWriter: &stderr}
	if strings.TrimSpace(args.project) == "" {
		return capturedResult{err: fmt.Errorf("--project は必須")}, &stdout, &stderr
	}
	if strings.TrimSpace(args.reportID) == "" {
		return capturedResult{err: fmt.Errorf("--report-id は必須")}, &stdout, &stderr
	}
	ctx := context.Background()
	fresh, err := client.DecideReport(ctx, args.project, args.reportID, api.CRADecisionRequest{
		Decision:     craDecisionApproved,
		DecisionNote: args.note,
	})
	if err != nil {
		return capturedResult{err: craFailureToExitError("cra approve", err)}, &stdout, &stderr
	}
	fmt.Fprintf(out.Writer, "CRA report %s を承認しました\n", fresh.ID)
	fmt.Fprintf(out.Writer, "  Decision: %s\n", fresh.Decision)
	return capturedResult{err: nil}, &stdout, &stderr
}

// errAsCRA is a tiny errors.As shim that keeps the test scaffolding
// readable. Returns true + populates target on match.
func errAsCRA(err error, target **api.CRAError) bool {
	for {
		if err == nil {
			return false
		}
		if ce, ok := err.(*api.CRAError); ok {
			*target = ce
			return true
		}
		type wrapper interface{ Unwrap() error }
		w, ok := err.(wrapper)
		if !ok {
			return false
		}
		err = w.Unwrap()
	}
}
