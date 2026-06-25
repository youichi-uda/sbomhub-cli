package api

// Unit tests for the CRA report API client helpers. Mirrors the M1
// triage_test.go structure so each fix pattern carried over to M2 has
// regression coverage at the wire layer, independent of the
// `sbomhub cra` command interaction loop.
//
// Coverage matrix (one test class per pattern):
//   - F21 happy path + AI-disabled 2xx + AI-disabled 503 + permanent vs transient
//   - F22 strict 503-AI-disabled detection (known reason only)
//   - F23 2xx contract validation (no report / error field)
//   - F26 list pagination loop (single page + multi-page + X-Total-Count)
//   - F28 X-Total-Count surfaced through ListReports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// ----------------------------------------------------------------------------
// RunReport
// ----------------------------------------------------------------------------

// TestRunReport_HappyPath verifies the request body fields the server
// requires + the response decode path.
func TestRunReport_HappyPath(t *testing.T) {
	const projectID = "00000000-0000-0000-0000-000000000aaa"
	const vulnID = "00000000-0000-0000-0000-000000000bbb"
	const cveID = "CVE-2024-99999"
	const reportID = "00000000-0000-0000-0000-000000000ddd"

	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		wantPath := "/api/v1/projects/" + projectID + "/cra-reports/run"
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		seenBody, _ = io.ReadAll(r.Body)

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"report": map[string]interface{}{
				"id":               reportID,
				"project_id":       projectID,
				"vulnerability_id": vulnID,
				"cve_id":           cveID,
				"report_type":      "early_warning",
				"lang":             "ja",
				"state":            "draft",
				"draft_text":       "## 24時間早期警告\n\nCVE-2024-99999 ...",
				"decision":         "pending",
				"evidence":         []map[string]string{{"kind": "vex_draft", "ref": "abc"}},
			},
			"llm_call_id": "00000000-0000-0000-0000-000000000eee",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	res, err := client.RunReport(context.Background(), projectID, CRARunReportRequest{
		VulnerabilityID: vulnID,
		CVEID:           cveID,
		ReportType:      "early_warning",
		Lang:            "ja",
	})
	if err != nil {
		t.Fatalf("RunReport error: %v", err)
	}
	if res.Report == nil || res.Report.ID != reportID {
		t.Errorf("report = %+v, want id=%s", res.Report, reportID)
	}
	if res.LLMCallID == "" {
		t.Errorf("LLMCallID empty; expected server-supplied value to round-trip")
	}

	var req CRARunReportRequest
	if err := json.Unmarshal(seenBody, &req); err != nil {
		t.Fatalf("body parse: %v", err)
	}
	if req.VulnerabilityID != vulnID || req.CVEID != cveID {
		t.Errorf("body = %+v, want vuln=%s cve=%s", req, vulnID, cveID)
	}
	if req.ReportType != "early_warning" || req.Lang != "ja" {
		t.Errorf("body type/lang = %s/%s, want early_warning/ja", req.ReportType, req.Lang)
	}
}

// TestRunReport_AIDisabled2xx verifies the canonical M2-4 server path:
// 2xx + ai_disabled=true + persisted report. CLI must decode cleanly.
func TestRunReport_AIDisabled2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"report": map[string]interface{}{
				"id":          "r1",
				"report_type": "early_warning",
				"lang":        "ja",
				"draft_text":  "(template-only — AI disabled)",
				"decision":    "pending",
			},
			"ai_disabled": true,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	res, err := client.RunReport(context.Background(), "p", CRARunReportRequest{
		VulnerabilityID: "v",
		CVEID:           "CVE-2024-1",
		ReportType:      "early_warning",
		Lang:            "ja",
	})
	if err != nil {
		t.Fatalf("RunReport error: %v", err)
	}
	if !res.AIDisabled {
		t.Errorf("AIDisabled = false, want true")
	}
	if res.Report == nil {
		t.Errorf("Report nil; AI-disabled path must still persist a template-only report")
	}
}

// TestRunReport_AIDisabled503Legacy verifies the legacy server compat:
// 503 with the known disabled reason classifies as AI-disabled.
func TestRunReport_AIDisabled503Legacy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":  "AI features are disabled",
			"reason": "no LLM provider configured",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	_, err := client.RunReport(context.Background(), "p", CRARunReportRequest{
		VulnerabilityID: "v",
		CVEID:           "CVE-2024-1",
		ReportType:      "early_warning",
		Lang:            "ja",
	})
	if err == nil {
		t.Fatal("expected error for 503 response")
	}
	var ce *CRAError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v (%T), want *CRAError", err, err)
	}
	if !ce.IsAIDisabled() {
		t.Errorf("IsAIDisabled = false, want true (legacy 503 with known reason)")
	}
	if ce.Reason == "" {
		t.Errorf("Reason empty; expected server reason to round-trip")
	}
}

// TestRunReport_PermanentClientError verifies 4xx → IsPermanent matrix.
func TestRunReport_PermanentClientError(t *testing.T) {
	cases := []struct {
		name string
		code int
		want bool // IsPermanent
	}{
		{"400 bad request", http.StatusBadRequest, true},
		{"401 unauthorized", http.StatusUnauthorized, true},
		{"403 forbidden", http.StatusForbidden, true},
		{"404 not found", http.StatusNotFound, true},
		{"409 no approved vex", http.StatusConflict, true},
		{"422 unprocessable", http.StatusUnprocessableEntity, true},
		{"429 rate limit", http.StatusTooManyRequests, false},
		{"500 internal", http.StatusInternalServerError, false},
		{"503 disabled", http.StatusServiceUnavailable, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(`{"error":"x"}`))
			}))
			defer server.Close()
			client := NewClient(server.URL, "k")
			_, err := client.RunReport(context.Background(), "p", CRARunReportRequest{
				VulnerabilityID: "v", CVEID: "c", ReportType: "early_warning", Lang: "ja",
			})
			var ce *CRAError
			if !errors.As(err, &ce) {
				t.Fatalf("err = %v, want *CRAError", err)
			}
			if got := ce.IsPermanent(); got != tc.want {
				t.Errorf("IsPermanent() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// F22 — strict 503 AI-disabled detection
// ----------------------------------------------------------------------------

// TestCRAError_IsAIDisabled_503GenericNotMatch_F22 — a 503 with a
// generic gateway / overload message must NOT be classified as AI-
// disabled. Mirrors the M1 #F22 triage test.
func TestCRAError_IsAIDisabled_503GenericNotMatch_F22(t *testing.T) {
	cases := []struct {
		name    string
		message string
	}{
		{"generic Service Unavailable", "Service Unavailable"},
		{"upstream gateway timeout", "upstream connect error"},
		{"empty message", ""},
		{"some other 503", "database is starting up"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ce := &CRAError{
				StatusCode: http.StatusServiceUnavailable,
				Message:    tc.message,
			}
			if ce.IsAIDisabled() {
				t.Errorf("F22: 503 with generic %q must NOT be IsAIDisabled", tc.message)
			}
			if !ce.IsTransient() {
				t.Errorf("F22: 503 with generic %q must be IsTransient (gateway outage)", tc.message)
			}
			if ce.IsPermanent() {
				t.Errorf("F22: 503 must NOT be IsPermanent")
			}
		})
	}
}

// TestCRAError_IsAIDisabled_503KnownReasonMatch_F22 — the legacy
// disabled reason text must still flag IsAIDisabled.
func TestCRAError_IsAIDisabled_503KnownReasonMatch_F22(t *testing.T) {
	cases := []struct {
		name    string
		message string
	}{
		{"canonical", "AI features are disabled"},
		{"byok variant", "BYOK key not configured"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ce := &CRAError{
				StatusCode: http.StatusServiceUnavailable,
				Message:    tc.message,
			}
			if !ce.IsAIDisabled() {
				t.Errorf("F22: 503 with known reason %q must remain IsAIDisabled", tc.message)
			}
			if ce.IsTransient() {
				t.Errorf("F22: 503 known reason must NOT double-count as transient")
			}
		})
	}
}

// ----------------------------------------------------------------------------
// F23 — 2xx contract validation
// ----------------------------------------------------------------------------

// TestRunReport_2xxEmptyReport_ReturnsError_F23 — a 2xx with no report
// is a server protocol violation. Must surface as ProtocolError /
// transient.
func TestRunReport_2xxEmptyReport_ReturnsError_F23(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"200 empty report", http.StatusOK},
		{"201 empty report", http.StatusCreated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{}`))
			}))
			defer server.Close()
			client := NewClient(server.URL, "k")
			res, err := client.RunReport(context.Background(), "p", CRARunReportRequest{
				VulnerabilityID: "v", CVEID: "c", ReportType: "early_warning", Lang: "ja",
			})
			if err == nil {
				t.Fatalf("F23: expected error for 2xx with no report, got %+v", res)
			}
			var ce *CRAError
			if !errors.As(err, &ce) {
				t.Fatalf("F23: err = %v (%T), want *CRAError", err, err)
			}
			if !ce.IsTransient() {
				t.Errorf("F23: protocol error must classify transient")
			}
		})
	}
}

// TestRunReport_2xxWithErrorField_ReturnsError_F23 — a 2xx with an
// error field set is a server protocol violation.
func TestRunReport_2xxWithErrorField_ReturnsError_F23(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"error":"upstream LLM provider failure"}`))
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	_, err := client.RunReport(context.Background(), "p", CRARunReportRequest{
		VulnerabilityID: "v", CVEID: "c", ReportType: "early_warning", Lang: "ja",
	})
	if err == nil {
		t.Fatal("F23: expected error")
	}
	var ce *CRAError
	if !errors.As(err, &ce) {
		t.Fatalf("F23: err = %v (%T), want *CRAError", err, err)
	}
	if !strings.Contains(ce.Message, "upstream LLM provider failure") {
		t.Errorf("F23: error message must round-trip server error field, got %q", ce.Message)
	}
	if !ce.IsTransient() {
		t.Errorf("F23: 2xx + error field must classify transient")
	}
}

// TestRunReport_2xxAIDisabledWithReport_NoError_F23 — the legitimate
// AI-disabled success path (2xx + ai_disabled=true + persisted report)
// must remain a clean return.
func TestRunReport_2xxAIDisabledWithReport_NoError_F23(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"report": map[string]interface{}{
				"id":         "r1",
				"draft_text": "template-only",
				"decision":   "pending",
			},
			"ai_disabled": true,
		})
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	res, err := client.RunReport(context.Background(), "p", CRARunReportRequest{
		VulnerabilityID: "v", CVEID: "c", ReportType: "early_warning", Lang: "ja",
	})
	if err != nil {
		t.Fatalf("F23: AI-disabled with persisted report must remain a clean success, got %v", err)
	}
	if res == nil || !res.AIDisabled || res.Report == nil {
		t.Errorf("F23: expected ai_disabled=true with non-nil report, got %+v", res)
	}
}

// ----------------------------------------------------------------------------
// ListReports — pagination + X-Total-Count
// ----------------------------------------------------------------------------

// TestListReports_FilterEncoding verifies the query string the client
// builds. Empty fields must not appear.
func TestListReports_FilterEncoding(t *testing.T) {
	var seenURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenURL = r.URL.String()
		w.Header().Set("X-Total-Count", "0")
		_ = json.NewEncoder(w).Encode(craReportListResponse{Reports: []CRAReport{}})
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")

	_, _, err := client.ListReports(context.Background(), "pid", CRAReportListFilter{
		CVEID:      "CVE-2024-1",
		ReportType: "early_warning",
		Lang:       "ja",
		State:      "draft",
		Decision:   "pending",
	})
	if err != nil {
		t.Fatalf("ListReports error: %v", err)
	}
	for _, want := range []string{
		"cve_id=CVE-2024-1",
		"report_type=early_warning",
		"lang=ja",
		"state=draft",
		"decision=pending",
		"limit=500",
	} {
		if !strings.Contains(seenURL, want) {
			t.Errorf("URL missing %q: %s", want, seenURL)
		}
	}
	if strings.Contains(seenURL, "offset=") {
		t.Errorf("URL should not include offset on first page: %s", seenURL)
	}
}

// TestListReports_TotalCount_F28 verifies the X-Total-Count header is
// captured and surfaced through ListReports.
func TestListReports_TotalCount_F28(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Total-Count", "42")
		_ = json.NewEncoder(w).Encode(craReportListResponse{
			Reports: []CRAReport{{ID: "r1"}, {ID: "r2"}},
		})
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")

	reports, total, err := client.ListReports(context.Background(), "p", CRAReportListFilter{})
	if err != nil {
		t.Fatalf("ListReports error: %v", err)
	}
	if total != 42 {
		t.Errorf("F28: total = %d, want 42 (X-Total-Count must round-trip)", total)
	}
	if len(reports) != 2 {
		t.Errorf("reports len = %d, want 2", len(reports))
	}
}

// TestListReports_Pagination_F26 verifies the multi-page loop walks
// through all rows when the first page is full.
func TestListReports_Pagination_F26(t *testing.T) {
	const pageSize = 500
	const tailSize = 100
	const totalExpected = pageSize + tailSize

	var pageRequests []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if got := q.Get("limit"); got != strconv.Itoa(pageSize) {
			t.Errorf("F26: must use limit=%d, got %q", pageSize, got)
		}
		offset, _ := strconv.Atoi(q.Get("offset"))
		pageRequests = append(pageRequests, offset)

		var rows []CRAReport
		switch offset {
		case 0:
			for i := 0; i < pageSize; i++ {
				rows = append(rows, CRAReport{ID: fmt.Sprintf("r%d", i)})
			}
		case pageSize:
			for i := 0; i < tailSize; i++ {
				rows = append(rows, CRAReport{ID: fmt.Sprintf("r%d", pageSize+i)})
			}
		default:
			t.Errorf("F26: unexpected offset %d", offset)
		}
		w.Header().Set("X-Total-Count", strconv.Itoa(totalExpected))
		_ = json.NewEncoder(w).Encode(craReportListResponse{Reports: rows})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	reports, total, err := client.ListReports(context.Background(), "p", CRAReportListFilter{})
	if err != nil {
		t.Fatalf("F26: ListReports error: %v", err)
	}
	if len(reports) != totalExpected {
		t.Errorf("F26: stitched len = %d, want %d", len(reports), totalExpected)
	}
	if total != totalExpected {
		t.Errorf("F26: total = %d, want %d", total, totalExpected)
	}
	if len(pageRequests) != 2 {
		t.Errorf("F26: expected 2 page requests, got %d (offsets=%v)", len(pageRequests), pageRequests)
	}
	if reports[totalExpected-1].ID != fmt.Sprintf("r%d", totalExpected-1) {
		t.Errorf("F26: last row mismatched, got %q", reports[totalExpected-1].ID)
	}
}

// TestListReports_SinglePage_NoExtraRequest verifies the early-stop
// optimisation that complements the multi-page test.
func TestListReports_SinglePage_NoExtraRequest(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("X-Total-Count", "2")
		_ = json.NewEncoder(w).Encode(craReportListResponse{
			Reports: []CRAReport{{ID: "r1"}, {ID: "r2"}},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "k")
	reports, _, err := client.ListReports(context.Background(), "p", CRAReportListFilter{})
	if err != nil {
		t.Fatalf("ListReports error: %v", err)
	}
	if len(reports) != 2 {
		t.Errorf("got %d reports, want 2", len(reports))
	}
	if requestCount != 1 {
		t.Errorf("F26: short page must trigger exactly 1 request, got %d", requestCount)
	}
}

// ----------------------------------------------------------------------------
// GetReport
// ----------------------------------------------------------------------------

func TestGetReport_HappyPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		_ = json.NewEncoder(w).Encode(CRAReport{
			ID:         "rid",
			ProjectID:  "pid",
			ReportType: "early_warning",
			Lang:       "ja",
			DraftText:  "body",
			Decision:   "pending",
		})
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	rep, err := client.GetReport(context.Background(), "pid", "rid")
	if err != nil {
		t.Fatalf("GetReport: %v", err)
	}
	if rep.ID != "rid" {
		t.Errorf("ID = %q, want rid", rep.ID)
	}
}

func TestGetReport_404Permanent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"cra report not found"}`))
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	_, err := client.GetReport(context.Background(), "p", "r")
	var ce *CRAError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v, want *CRAError", err)
	}
	if !ce.IsPermanent() {
		t.Errorf("IsPermanent = false, want true")
	}
}

// ----------------------------------------------------------------------------
// DecideReport
// ----------------------------------------------------------------------------

// TestDecideReport_BodyShape verifies the PUT body the CLI sends.
func TestDecideReport_BodyShape(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", r.Method)
		}
		seenBody, _ = io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(CRAReport{ID: "rid", Decision: "approved"})
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")

	_, err := client.DecideReport(context.Background(), "p", "rid", CRADecisionRequest{
		Decision:     "approved",
		DecisionNote: "looks good",
	})
	if err != nil {
		t.Fatalf("DecideReport error: %v", err)
	}
	var req CRADecisionRequest
	if err := json.Unmarshal(seenBody, &req); err != nil {
		t.Fatalf("body parse: %v", err)
	}
	if req.Decision != "approved" {
		t.Errorf("decision = %s, want approved", req.Decision)
	}
	if req.DecisionNote != "looks good" {
		t.Errorf("note = %s, want 'looks good'", req.DecisionNote)
	}
	// EditedDraftText must be omitted when nil (decision="approved")
	if strings.Contains(string(seenBody), "edited_draft_text") {
		t.Errorf("body must omit edited_draft_text for approved decisions: %s", string(seenBody))
	}
}

// TestDecideReport_EditedBodyShape verifies that when EditedDraftText
// is set, it lands in the request body (pointer/nil contract).
func TestDecideReport_EditedBodyShape(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(CRAReport{ID: "rid", Decision: "edited"})
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")

	editedText := "## edited body\n\nrevised by operator"
	_, err := client.DecideReport(context.Background(), "p", "rid", CRADecisionRequest{
		Decision:        "edited",
		EditedDraftText: &editedText,
	})
	if err != nil {
		t.Fatalf("DecideReport error: %v", err)
	}
	if !strings.Contains(string(seenBody), "revised by operator") {
		t.Errorf("body must contain edited draft text, got %s", string(seenBody))
	}
	if !strings.Contains(string(seenBody), `"edited_draft_text"`) {
		t.Errorf("body must include edited_draft_text key, got %s", string(seenBody))
	}
}

// ----------------------------------------------------------------------------
// ReanalyseReport
// ----------------------------------------------------------------------------

// TestReanalyseReport_HappyPath verifies the POST hits the right URL
// and round-trips the new report.
func TestReanalyseReport_HappyPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/reanalyse") {
			t.Errorf("path = %s, want /reanalyse suffix", r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"report": CRAReport{
				ID:         "rid2",
				ProjectID:  "p",
				ReportType: "early_warning",
				Lang:       "ja",
				DraftText:  "rerun body",
				Decision:   "pending",
			},
		})
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	res, err := client.ReanalyseReport(context.Background(), "p", "rid", CRARunReportRequest{})
	if err != nil {
		t.Fatalf("ReanalyseReport: %v", err)
	}
	if res.Report == nil || res.Report.ID != "rid2" {
		t.Errorf("Report = %+v, want id=rid2", res.Report)
	}
}
