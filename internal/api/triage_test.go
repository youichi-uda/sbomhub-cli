package api

// Unit tests for the triage API client helpers. These complement the
// command-layer integration tests in cmd/sbomhub/commands/triage_test.go
// by pinning down each helper's wire contract — endpoint shape,
// request body fields, error decoding — independently of the
// interactive loop.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRunTriage_HappyPath verifies the request body fields the server
// requires (vulnerability_id + cve_id) and the response decode.
func TestRunTriage_HappyPath(t *testing.T) {
	const projectID = "00000000-0000-0000-0000-000000000aaa"
	const vulnID = "00000000-0000-0000-0000-000000000bbb"
	const cveID = "CVE-2024-99999"
	const draftID = "00000000-0000-0000-0000-000000000ddd"

	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		wantPath := "/api/v1/projects/" + projectID + "/triage/run"
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		seenBody, _ = io.ReadAll(r.Body)

		conf := 0.85
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"draft": map[string]interface{}{
				"id":         draftID,
				"project_id": projectID,
				"cve_id":     cveID,
				"state":      "not_affected",
				"confidence": conf,
				"decision":   "pending",
			},
			"parsed_decision": map[string]interface{}{
				"state":      "not_affected",
				"confidence": conf,
			},
			"clamped":   false,
			"threshold": 0.7,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	res, err := client.RunTriage(context.Background(), projectID, TriageRunRequest{
		VulnerabilityID: vulnID,
		CVEID:           cveID,
	})
	if err != nil {
		t.Fatalf("RunTriage error: %v", err)
	}
	if res.Draft == nil || res.Draft.ID != draftID {
		t.Errorf("draft = %+v, want id=%s", res.Draft, draftID)
	}
	if res.Threshold != 0.7 {
		t.Errorf("threshold = %v, want 0.7", res.Threshold)
	}

	var req TriageRunRequest
	if err := json.Unmarshal(seenBody, &req); err != nil {
		t.Fatalf("body parse: %v", err)
	}
	if req.VulnerabilityID != vulnID || req.CVEID != cveID {
		t.Errorf("body = %+v, want vuln=%s cve=%s", req, vulnID, cveID)
	}
}

// TestRunTriage_AIDisabled verifies the 503 → TriageError +
// IsAIDisabled() == true path. This is the canary that catches a
// regression where the BYOK fallback would be silently treated as a
// generic server error.
func TestRunTriage_AIDisabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":  "AI features are disabled",
			"reason": "no LLM provider configured",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	_, err := client.RunTriage(context.Background(), "p", TriageRunRequest{VulnerabilityID: "v", CVEID: "CVE-2024-1"})
	if err == nil {
		t.Fatal("expected error for 503 response")
	}
	var te *TriageError
	if !errors.As(err, &te) {
		t.Fatalf("err = %v (%T), want *TriageError", err, err)
	}
	if !te.IsAIDisabled() {
		t.Errorf("IsAIDisabled = false, want true")
	}
	if te.Reason == "" {
		t.Errorf("Reason is empty; expected the server's reason text to round-trip")
	}
}

// TestRunTriage_PermanentClientError verifies 4xx → IsPermanent.
func TestRunTriage_PermanentClientError(t *testing.T) {
	cases := []struct {
		name string
		code int
		want bool // IsPermanent
	}{
		{"400 bad request", http.StatusBadRequest, true},
		{"401 unauthorized", http.StatusUnauthorized, true},
		{"403 forbidden", http.StatusForbidden, true},
		{"404 not found", http.StatusNotFound, true},
		{"422 unprocessable", http.StatusUnprocessableEntity, true},
		{"429 rate limit", http.StatusTooManyRequests, false}, // transient
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
			_, err := client.RunTriage(context.Background(), "p", TriageRunRequest{VulnerabilityID: "v", CVEID: "c"})
			var te *TriageError
			if !errors.As(err, &te) {
				t.Fatalf("err = %v, want *TriageError", err)
			}
			if got := te.IsPermanent(); got != tc.want {
				t.Errorf("IsPermanent() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestListVEXDrafts_FilterEncoding verifies the query string the
// client builds for ListVEXDrafts. Empty fields must not appear.
func TestListVEXDrafts_FilterEncoding(t *testing.T) {
	var seenURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenURL = r.URL.String()
		_ = json.NewEncoder(w).Encode(vexDraftListResponse{Drafts: []VEXDraft{}})
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")

	_, err := client.ListVEXDrafts(context.Background(), "pid", VEXDraftListFilter{
		CVEID:    "CVE-2024-1",
		Decision: "pending",
		Limit:    25,
	})
	if err != nil {
		t.Fatalf("ListVEXDrafts error: %v", err)
	}
	if !strings.Contains(seenURL, "cve_id=CVE-2024-1") {
		t.Errorf("URL missing cve_id filter: %s", seenURL)
	}
	if !strings.Contains(seenURL, "decision=pending") {
		t.Errorf("URL missing decision filter: %s", seenURL)
	}
	if !strings.Contains(seenURL, "limit=25") {
		t.Errorf("URL missing limit: %s", seenURL)
	}
	if strings.Contains(seenURL, "offset=") {
		t.Errorf("URL should not include offset=0: %s", seenURL)
	}
}

// TestDecideDraft_BodyShape verifies the PUT body the CLI sends.
func TestDecideDraft_BodyShape(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", r.Method)
		}
		seenBody, _ = io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(VEXDraft{ID: "d", Decision: "edited"})
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")

	_, err := client.DecideDraft(context.Background(), "p", "d", DecisionRequest{
		Decision:            "edited",
		EditedState:         "under_investigation",
		EditedJustification: "code_not_reachable",
		EditedDetail:        "auto",
	})
	if err != nil {
		t.Fatalf("DecideDraft error: %v", err)
	}
	var req DecisionRequest
	if err := json.Unmarshal(seenBody, &req); err != nil {
		t.Fatalf("body parse: %v", err)
	}
	if req.Decision != "edited" {
		t.Errorf("decision = %s, want edited", req.Decision)
	}
	if req.EditedState != "under_investigation" {
		t.Errorf("edited_state = %s, want under_investigation", req.EditedState)
	}
}

// ----------------------------------------------------------------------------
// F22 regression — IsAIDisabled() must require the server's known reason
// string, not any 503. A generic gateway 503 should land in IsTransient
// so a real upstream outage cannot be silently mis-classified as "BYOK
// not configured" and silently succeed in CI.
// ----------------------------------------------------------------------------

// TestTriageError_IsAIDisabled_503GenericNotMatch_F22 — a 503 with a
// generic message (e.g. an upstream gateway 503 page or a stock
// "Service Unavailable" body) must NOT be classified as AI-disabled.
// Before this fix, every 503 was treated as the BYOK fallback and
// silently exit-0'd in the CLI loop.
func TestTriageError_IsAIDisabled_503GenericNotMatch_F22(t *testing.T) {
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
			te := &TriageError{
				StatusCode: http.StatusServiceUnavailable,
				Message:    tc.message,
			}
			if te.IsAIDisabled() {
				t.Errorf("F22: 503 with generic message %q must NOT be IsAIDisabled (silently mis-classified as BYOK off)", tc.message)
			}
			if !te.IsTransient() {
				t.Errorf("F22: 503 with generic message %q must be IsTransient (gateway outage / overload)", tc.message)
			}
			if te.IsPermanent() {
				t.Errorf("F22: 503 with generic message %q must NOT be IsPermanent", tc.message)
			}
		})
	}
}

// TestTriageError_IsAIDisabled_503KnownReasonMatch_F22 — the legacy
// BYOK-not-configured server reply (503 + the exact "AI features are
// disabled" string) must still flag IsAIDisabled=true so the CLI can
// fall back to under_investigation cleanly when talking to an older
// server that has not yet shipped the F4 2xx+ai_disabled fix.
func TestTriageError_IsAIDisabled_503KnownReasonMatch_F22(t *testing.T) {
	cases := []struct {
		name    string
		message string
	}{
		{"canonical disabled error", "AI features are disabled"},
		{"BYOK not configured variant", "BYOK key not configured"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			te := &TriageError{
				StatusCode: http.StatusServiceUnavailable,
				Message:    tc.message,
			}
			if !te.IsAIDisabled() {
				t.Errorf("F22: 503 with known reason %q must remain IsAIDisabled for legacy server compat", tc.message)
			}
			if te.IsTransient() {
				t.Errorf("F22: 503 known reason must NOT also be transient (would double-count)")
			}
		})
	}
}

// ----------------------------------------------------------------------------
// F23 regression — a 2xx response with a malformed body (error field, or
// no draft) must surface as a TriageError so the CLI's exit-code path
// can flag the problem instead of silently incrementing `skipped` and
// exiting 0.
// ----------------------------------------------------------------------------

// TestRunTriage_2xxEmptyDraft_ReturnsError_F23 — a 200/201 response
// with neither `draft` nor `drafts` is a server protocol violation.
// Before this fix RunTriage decoded it as a zero-valued success and
// the CLI bucketed the vuln as `skipped` → exit 0.
func TestRunTriage_2xxEmptyDraft_ReturnsError_F23(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"200 empty draft", http.StatusOK},
		{"201 empty draft", http.StatusCreated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"clamped":   false,
					"threshold": 0.7,
				})
			}))
			defer server.Close()

			client := NewClient(server.URL, "k")
			res, err := client.RunTriage(context.Background(), "p", TriageRunRequest{VulnerabilityID: "v", CVEID: "c"})
			if err == nil {
				t.Fatalf("F23: expected error for 2xx response with no draft, got result %+v", res)
			}
			var te *TriageError
			if !errors.As(err, &te) {
				t.Fatalf("F23: err = %v (%T), want *TriageError", err, err)
			}
			if !te.IsTransient() {
				t.Errorf("F23: protocol error must be classified transient (server bug, retry recommended)")
			}
		})
	}
}

// TestRunTriage_2xxWithErrorField_ReturnsError_F23 — a 200 response
// carrying an "error" field in the body is a server protocol violation;
// it must surface as a TriageError so the CLI does not bucket the vuln
// as skipped + exit 0.
func TestRunTriage_2xxWithErrorField_ReturnsError_F23(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"error":"upstream LLM provider failure"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "k")
	res, err := client.RunTriage(context.Background(), "p", TriageRunRequest{VulnerabilityID: "v", CVEID: "c"})
	if err == nil {
		t.Fatalf("F23: expected error for 2xx response with error field, got result %+v", res)
	}
	var te *TriageError
	if !errors.As(err, &te) {
		t.Fatalf("F23: err = %v (%T), want *TriageError", err, err)
	}
	if !strings.Contains(te.Message, "upstream LLM provider failure") {
		t.Errorf("F23: error message must round-trip server error field, got %q", te.Message)
	}
	if !te.IsTransient() {
		t.Errorf("F23: 2xx with error field must classify transient (server protocol bug, retry recommended)")
	}
}

// TestRunTriage_2xxAIDisabledWithDraft_NoError_F23 — the legitimate
// AI-disabled success path (2xx + ai_disabled=true + persisted draft)
// must remain a clean return. This is the canary that catches an
// over-aggressive F23 fix that breaks the F4 fast path.
func TestRunTriage_2xxAIDisabledWithDraft_NoError_F23(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"draft": map[string]interface{}{
				"id":    "d1",
				"state": "under_investigation",
			},
			"ai_disabled": true,
			"threshold":   0.7,
		})
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	res, err := client.RunTriage(context.Background(), "p", TriageRunRequest{VulnerabilityID: "v", CVEID: "c"})
	if err != nil {
		t.Fatalf("F23: AI-disabled with persisted draft must remain a clean success, got %v", err)
	}
	if res == nil || !res.AIDisabled || res.Draft == nil {
		t.Errorf("F23: expected ai_disabled=true with non-nil draft, got %+v", res)
	}
}

// TestListVulnerabilities_BareArray verifies that the server's bare
// JSON array shape decodes correctly (the canonical handler returns
// `[...]` not `{"vulnerabilities":[...]}`).
func TestListVulnerabilities_BareArray(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":"v1","cve_id":"CVE-2024-1","severity":"HIGH"}]`))
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	vulns, err := client.ListVulnerabilities(context.Background(), "p")
	if err != nil {
		t.Fatalf("ListVulnerabilities: %v", err)
	}
	if len(vulns) != 1 || vulns[0].ID != "v1" {
		t.Errorf("got %+v", vulns)
	}
}

// TestListVulnerabilities_EnvelopedShape verifies the defensive
// decode path for a future server that envelops the array.
func TestListVulnerabilities_EnvelopedShape(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"id":"v1","cve_id":"CVE-2024-1"}]}`))
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	vulns, err := client.ListVulnerabilities(context.Background(), "p")
	if err != nil {
		t.Fatalf("ListVulnerabilities: %v", err)
	}
	if len(vulns) != 1 || vulns[0].ID != "v1" {
		t.Errorf("got %+v", vulns)
	}
}

// TestListVulnerabilities_Pagination_F26 pins the M1 Codex review #F26
// contract: when the server paginates responses (default 100, max 500
// — handler.VulnsMaxLimit), the CLI MUST page through transparently
// rather than only fetching the first page. Without this loop, a
// project with > listVulnerabilitiesPageSize matched vulns would be
// silently truncated and `sbomhub triage` would skip the tail.
//
// Server behaviour: page 1 returns 500 rows + offset=0, page 2 returns
// 200 rows + offset=500 (truncated). CLI must request both and stitch
// the result into a 700-row slice.
func TestListVulnerabilities_Pagination_F26(t *testing.T) {
	const pageSize = 500
	const tailSize = 200
	const totalExpected = pageSize + tailSize

	var pageRequests []int // captures the `offset=` value for each request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The CLI sends `?limit=500&offset=N` — verify the limit clamp and
		// record the offset so the test can assert paging progressed.
		q := r.URL.Query()
		if got := q.Get("limit"); got != "500" {
			t.Errorf("F26: page request must use ?limit=500, got %q", got)
		}
		offsetStr := q.Get("offset")
		var offset int
		_, _ = fmt.Sscanf(offsetStr, "%d", &offset)
		pageRequests = append(pageRequests, offset)

		var rows []map[string]interface{}
		switch offset {
		case 0:
			// First page: full pageSize rows so the CLI knows to ask again.
			for i := 0; i < pageSize; i++ {
				rows = append(rows, map[string]interface{}{
					"id":     fmt.Sprintf("v%d", i),
					"cve_id": fmt.Sprintf("CVE-2024-%04d", i),
				})
			}
		case pageSize:
			// Second page: tail (< pageSize) so the CLI knows to stop.
			for i := 0; i < tailSize; i++ {
				rows = append(rows, map[string]interface{}{
					"id":     fmt.Sprintf("v%d", pageSize+i),
					"cve_id": fmt.Sprintf("CVE-2024-%04d", pageSize+i),
				})
			}
		default:
			t.Errorf("F26: unexpected offset request %d (server emits only 0 and %d)",
				offset, pageSize)
		}
		_ = json.NewEncoder(w).Encode(rows)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	vulns, err := client.ListVulnerabilities(context.Background(), "p")
	if err != nil {
		t.Fatalf("F26: ListVulnerabilities returned error: %v", err)
	}
	if len(vulns) != totalExpected {
		t.Errorf("F26: stitched result len = %d, want %d (paging truncated the result?)",
			len(vulns), totalExpected)
	}
	if len(pageRequests) != 2 {
		t.Errorf("F26: expected 2 page requests, got %d (offsets=%v)",
			len(pageRequests), pageRequests)
	}
	if len(pageRequests) >= 1 && pageRequests[0] != 0 {
		t.Errorf("F26: first page request must use offset=0, got %d", pageRequests[0])
	}
	if len(pageRequests) >= 2 && pageRequests[1] != pageSize {
		t.Errorf("F26: second page request must use offset=%d, got %d",
			pageSize, pageRequests[1])
	}
	// Verify the tail row landed (regression-proof against a loop that
	// asks for the second page but discards its body).
	if len(vulns) >= totalExpected {
		want := fmt.Sprintf("v%d", totalExpected-1)
		if vulns[totalExpected-1].ID != want {
			t.Errorf("F26: last row ID = %q, want %q (tail page may have been dropped)",
				vulns[totalExpected-1].ID, want)
		}
	}
}

// TestListVulnerabilities_SinglePage_NoExtraRequest pins the early-stop
// optimisation that complements TestListVulnerabilities_Pagination_F26:
// when the first page returns fewer rows than the page size, the CLI
// MUST stop immediately and not issue a second request. Without this,
// a tiny project would still trip the second page round-trip for
// nothing.
func TestListVulnerabilities_SinglePage_NoExtraRequest(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		// Return a tiny page (< listVulnerabilitiesPageSize) so the CLI
		// knows there's nothing more to fetch.
		_, _ = w.Write([]byte(`[{"id":"v1","cve_id":"CVE-2024-1"},{"id":"v2","cve_id":"CVE-2024-2"}]`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "k")
	vulns, err := client.ListVulnerabilities(context.Background(), "p")
	if err != nil {
		t.Fatalf("ListVulnerabilities: %v", err)
	}
	if len(vulns) != 2 {
		t.Errorf("got %d vulns, want 2", len(vulns))
	}
	if requestCount != 1 {
		t.Errorf("F26: short page must trigger exactly 1 request, got %d", requestCount)
	}
}
