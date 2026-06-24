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
