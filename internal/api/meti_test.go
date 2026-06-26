package api

// Unit tests for the METI assessment API client helpers. Mirrors the
// M2 cra_test.go structure so each fix pattern carried over to M3 has
// regression coverage at the wire layer, independent of the
// `sbomhub meti` command interaction loop.
//
// Coverage matrix (one test class per pattern):
//   - F21 happy path + permanent vs transient classification
//   - F22 strict error detection (no oracle around the 503 path —
//         METI has no AI-disabled fallback, so any 503 is transient)
//   - F23 2xx contract validation (no assessments / error field set)
//   - F26 list pagination loop (single page short-circuit + multi-page)
//   - F28 X-Total-Count surfaced through GetAssessment

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
// GetAssessment
// ----------------------------------------------------------------------------

// TestGetAssessment_HappyPath verifies the basic decode path + the
// limit query string the client builds.
func TestGetAssessment_HappyPath(t *testing.T) {
	const projectID = "00000000-0000-0000-0000-000000000aaa"
	var seenURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		wantPath := "/api/v1/projects/" + projectID + "/meti/assessment"
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		seenURL = r.URL.String()
		w.Header().Set("X-Total-Count", "1")
		_ = json.NewEncoder(w).Encode(metiAssessmentListResponse{
			Assessments: []MetiAssessment{
				{
					ID:             "rid-1",
					ProjectID:      projectID,
					CriterionID:    "env_setup.policy_documented",
					CriterionPhase: "env_setup",
					Status:         "achieved",
				},
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	rows, total, err := client.GetAssessment(context.Background(), projectID, MetiAssessmentListFilter{})
	if err != nil {
		t.Fatalf("GetAssessment error: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(rows) != 1 || rows[0].CriterionID != "env_setup.policy_documented" {
		t.Errorf("rows = %+v", rows)
	}
	if !strings.Contains(seenURL, "limit=500") {
		t.Errorf("URL missing limit=500: %s", seenURL)
	}
}

// TestGetAssessment_FilterEncoding verifies the query string the client
// builds. Empty fields must not appear; HasOverride uses pointer
// semantics (nil = no filter, *false = explicit "false").
func TestGetAssessment_FilterEncoding(t *testing.T) {
	var seenURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenURL = r.URL.String()
		w.Header().Set("X-Total-Count", "0")
		_ = json.NewEncoder(w).Encode(metiAssessmentListResponse{Assessments: []MetiAssessment{}})
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")

	hasOverride := true
	_, _, err := client.GetAssessment(context.Background(), "pid", MetiAssessmentListFilter{
		Phase:       "env_setup",
		Status:      "achieved",
		HasOverride: &hasOverride,
	})
	if err != nil {
		t.Fatalf("GetAssessment error: %v", err)
	}
	for _, want := range []string{
		"phase=env_setup",
		"status=achieved",
		"has_override=true",
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

// TestGetAssessment_HasOverrideFalse exercises the explicit-false branch
// — the CLI distinguishes "no filter" (nil) from "must not be
// overridden" (*false), and a regression that collapses them would
// silently drop evaluator-only rows from the operator's view.
func TestGetAssessment_HasOverrideFalse(t *testing.T) {
	var seenURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenURL = r.URL.String()
		_ = json.NewEncoder(w).Encode(metiAssessmentListResponse{Assessments: []MetiAssessment{}})
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	f := false
	_, _, err := client.GetAssessment(context.Background(), "p", MetiAssessmentListFilter{HasOverride: &f})
	if err != nil {
		t.Fatalf("GetAssessment error: %v", err)
	}
	if !strings.Contains(seenURL, "has_override=false") {
		t.Errorf("URL missing has_override=false: %s", seenURL)
	}
}

// TestGetAssessment_TotalCount_F28 verifies the X-Total-Count header
// is captured and surfaced through GetAssessment.
func TestGetAssessment_TotalCount_F28(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Total-Count", "27")
		_ = json.NewEncoder(w).Encode(metiAssessmentListResponse{
			Assessments: []MetiAssessment{{ID: "r1"}, {ID: "r2"}},
		})
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")

	rows, total, err := client.GetAssessment(context.Background(), "p", MetiAssessmentListFilter{})
	if err != nil {
		t.Fatalf("GetAssessment error: %v", err)
	}
	if total != 27 {
		t.Errorf("F28: total = %d, want 27 (X-Total-Count must round-trip)", total)
	}
	if len(rows) != 2 {
		t.Errorf("rows len = %d, want 2", len(rows))
	}
}

// TestGetAssessment_Pagination_F26 verifies the multi-page loop walks
// through all rows when the first page is full. The METI catalog is
// only 27 entries, so in practice the loop short-circuits — but the
// F26 invariant ("never silently truncate server-paginated data")
// must hold across the surface.
func TestGetAssessment_Pagination_F26(t *testing.T) {
	const pageSize = 500
	const tailSize = 50
	const totalExpected = pageSize + tailSize

	var pageRequests []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if got := q.Get("limit"); got != strconv.Itoa(pageSize) {
			t.Errorf("F26: must use limit=%d, got %q", pageSize, got)
		}
		offset, _ := strconv.Atoi(q.Get("offset"))
		pageRequests = append(pageRequests, offset)

		var rows []MetiAssessment
		switch offset {
		case 0:
			for i := 0; i < pageSize; i++ {
				rows = append(rows, MetiAssessment{ID: fmt.Sprintf("r%d", i)})
			}
		case pageSize:
			for i := 0; i < tailSize; i++ {
				rows = append(rows, MetiAssessment{ID: fmt.Sprintf("r%d", pageSize+i)})
			}
		default:
			t.Errorf("F26: unexpected offset %d", offset)
		}
		w.Header().Set("X-Total-Count", strconv.Itoa(totalExpected))
		_ = json.NewEncoder(w).Encode(metiAssessmentListResponse{Assessments: rows})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	rows, total, err := client.GetAssessment(context.Background(), "p", MetiAssessmentListFilter{})
	if err != nil {
		t.Fatalf("F26: GetAssessment error: %v", err)
	}
	if len(rows) != totalExpected {
		t.Errorf("F26: stitched len = %d, want %d", len(rows), totalExpected)
	}
	if total != totalExpected {
		t.Errorf("F26: total = %d, want %d", total, totalExpected)
	}
	if len(pageRequests) != 2 {
		t.Errorf("F26: expected 2 page requests, got %d (offsets=%v)", len(pageRequests), pageRequests)
	}
	if rows[totalExpected-1].ID != fmt.Sprintf("r%d", totalExpected-1) {
		t.Errorf("F26: last row mismatched, got %q", rows[totalExpected-1].ID)
	}
}

// TestGetAssessment_SinglePage_NoExtraRequest verifies the early-stop
// optimisation that complements the multi-page test. This is the
// path the real 27-entry catalog hits in production.
func TestGetAssessment_SinglePage_NoExtraRequest(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("X-Total-Count", "27")
		rows := make([]MetiAssessment, 27)
		for i := range rows {
			rows[i] = MetiAssessment{ID: fmt.Sprintf("r%d", i)}
		}
		_ = json.NewEncoder(w).Encode(metiAssessmentListResponse{Assessments: rows})
	}))
	defer server.Close()

	client := NewClient(server.URL, "k")
	rows, _, err := client.GetAssessment(context.Background(), "p", MetiAssessmentListFilter{})
	if err != nil {
		t.Fatalf("GetAssessment error: %v", err)
	}
	if len(rows) != 27 {
		t.Errorf("got %d rows, want 27", len(rows))
	}
	if requestCount != 1 {
		t.Errorf("F26: short page must trigger exactly 1 request, got %d", requestCount)
	}
}

// TestGetAssessment_PermanentClientError verifies 4xx → IsPermanent.
func TestGetAssessment_PermanentClientError(t *testing.T) {
	cases := []struct {
		name string
		code int
		want bool // IsPermanent
	}{
		{"400 bad request", http.StatusBadRequest, true},
		{"401 unauthorized", http.StatusUnauthorized, true},
		{"403 forbidden", http.StatusForbidden, true},
		{"404 not found", http.StatusNotFound, true},
		{"409 already overridden", http.StatusConflict, true},
		{"429 rate limit", http.StatusTooManyRequests, false},
		{"500 internal", http.StatusInternalServerError, false},
		{"503 service unavailable", http.StatusServiceUnavailable, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(`{"error":"x"}`))
			}))
			defer server.Close()
			client := NewClient(server.URL, "k")
			_, _, err := client.GetAssessment(context.Background(), "p", MetiAssessmentListFilter{})
			var me *MetiError
			if !errors.As(err, &me) {
				t.Fatalf("err = %v, want *MetiError", err)
			}
			if got := me.IsPermanent(); got != tc.want {
				t.Errorf("IsPermanent() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// F22 — strict error detection (no AI-disabled path in METI)
// ----------------------------------------------------------------------------

// TestMetiError_Classification_F22 verifies the 503 / 5xx / 4xx surface
// classifies symmetrically — there is no METI "AI-disabled" fallback,
// so any 503 is transient and any 4xx (except 429) is permanent. A
// regression that introduced a CRA-style AI-disabled oracle on the
// 503 path would be caught here.
func TestMetiError_Classification_F22(t *testing.T) {
	cases := []struct {
		name        string
		code        int
		message     string
		wantPerm    bool
		wantTrans   bool
		wantProto   bool // ProtocolError flag (set by F23 helpers)
	}{
		{"503 generic", 503, "Service Unavailable", false, true, false},
		{"503 with byok-ish reason", 503, "BYOK key not configured", false, true, false},
		{"429", 429, "rate limit", false, true, false},
		{"401", 401, "unauthorized", true, false, false},
		{"409", 409, "already overridden", true, false, false},
		{"500", 500, "internal", false, true, false},
		{"protocol error", 200, "x", false, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			me := &MetiError{StatusCode: tc.code, Message: tc.message, ProtocolError: tc.wantProto}
			if got := me.IsPermanent(); got != tc.wantPerm {
				t.Errorf("IsPermanent = %v, want %v", got, tc.wantPerm)
			}
			if got := me.IsTransient(); got != tc.wantTrans {
				t.Errorf("IsTransient = %v, want %v", got, tc.wantTrans)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// RefreshAssessment + F23 contract validation
// ----------------------------------------------------------------------------

// TestRefreshAssessment_HappyPath verifies the request shape and the
// decode path for the refresh result envelope.
func TestRefreshAssessment_HappyPath(t *testing.T) {
	const projectID = "00000000-0000-0000-0000-000000000aaa"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		wantPath := "/api/v1/projects/" + projectID + "/meti/assessment/refresh"
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		// Server should reach 2xx with assessments + evaluator_version.
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"assessments": []map[string]interface{}{
				{"id": "r1", "criterion_id": "c1", "status": "achieved"},
				{"id": "r2", "criterion_id": "c2", "status": "not_achieved"},
			},
			"evaluator_version": "0.3.1",
			"refreshed":         2,
		})
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	res, err := client.RefreshAssessment(context.Background(), projectID)
	if err != nil {
		t.Fatalf("RefreshAssessment error: %v", err)
	}
	if res.Refreshed != 2 || len(res.Assessments) != 2 || res.EvaluatorVersion != "0.3.1" {
		t.Errorf("RefreshAssessment res = %+v", res)
	}
}

// TestRefreshAssessment_2xxWithErrorField_F23 — a 2xx with an error
// field set is a server protocol violation.
func TestRefreshAssessment_2xxWithErrorField_F23(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"error":"evaluator panic"}`)
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	_, err := client.RefreshAssessment(context.Background(), "p")
	if err == nil {
		t.Fatal("F23: expected error for 2xx with error field")
	}
	var me *MetiError
	if !errors.As(err, &me) {
		t.Fatalf("F23: err = %v (%T), want *MetiError", err, err)
	}
	if !me.IsTransient() {
		t.Errorf("F23: 2xx + error field must classify transient")
	}
	if !strings.Contains(me.Message, "evaluator panic") {
		t.Errorf("F23: error message must round-trip server error field, got %q", me.Message)
	}
}

// TestRefreshAssessment_2xxEmptyAssessments_F23 — a 2xx with no
// assessments slice is a server protocol violation.
func TestRefreshAssessment_2xxEmptyAssessments_F23(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	_, err := client.RefreshAssessment(context.Background(), "p")
	if err == nil {
		t.Fatal("F23: expected error for 2xx with empty body")
	}
	var me *MetiError
	if !errors.As(err, &me) {
		t.Fatalf("F23: err = %v (%T), want *MetiError", err, err)
	}
	if !me.IsTransient() {
		t.Errorf("F23: protocol error must classify transient")
	}
	if !me.ProtocolError {
		t.Errorf("F23: ProtocolError flag must be set")
	}
}

// TestRefreshAssessment_403Permanent — refresh requires write
// permission server-side (RequireWrite middleware). The CLI must
// classify 403 as permanent so CI does not retry.
func TestRefreshAssessment_403Permanent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":"write permission required"}`)
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	_, err := client.RefreshAssessment(context.Background(), "p")
	var me *MetiError
	if !errors.As(err, &me) {
		t.Fatalf("err = %v, want *MetiError", err)
	}
	if !me.IsPermanent() {
		t.Errorf("403 must classify permanent")
	}
}

// ----------------------------------------------------------------------------
// OverrideCriterion
// ----------------------------------------------------------------------------

// TestOverrideCriterion_HappyPath verifies the URL path, the wire body
// shape, and the response decode.
func TestOverrideCriterion_HappyPath(t *testing.T) {
	const projectID = "00000000-0000-0000-0000-000000000aaa"
	const criterionID = "env_setup.policy_documented"

	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", r.Method)
		}
		wantPath := "/api/v1/projects/" + projectID + "/meti/assessment/" + criterionID + "/override"
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		seenBody, _ = io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(MetiAssessment{
			ID:             "rid",
			CriterionID:    criterionID,
			Status:         "needs_review",
			OverrideStatus: "achieved",
		})
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")

	impl := "rotate dependency monthly"
	row, err := client.OverrideCriterion(context.Background(), projectID, criterionID, MetiOverrideRequest{
		OverrideStatus:    "achieved",
		OverrideNote:      "verified by Tanaka 2026-09-10",
		ImprovementAction: &impl,
	})
	if err != nil {
		t.Fatalf("OverrideCriterion error: %v", err)
	}
	if row == nil || row.OverrideStatus != "achieved" {
		t.Errorf("row = %+v", row)
	}

	var req MetiOverrideRequest
	if err := json.Unmarshal(seenBody, &req); err != nil {
		t.Fatalf("body parse: %v", err)
	}
	if req.OverrideStatus != "achieved" {
		t.Errorf("body OverrideStatus = %q, want achieved", req.OverrideStatus)
	}
	if req.OverrideNote != "verified by Tanaka 2026-09-10" {
		t.Errorf("body OverrideNote = %q", req.OverrideNote)
	}
	if req.ImprovementAction == nil || *req.ImprovementAction != "rotate dependency monthly" {
		t.Errorf("body ImprovementAction = %+v", req.ImprovementAction)
	}
}

// TestOverrideCriterion_OmitsImprovementActionWhenNil verifies the
// "do not change" contract: a nil ImprovementAction must be absent
// from the marshalled body (not serialised as null), so the server's
// pointer-based "nil = preserve" semantics survive the round-trip.
func TestOverrideCriterion_OmitsImprovementActionWhenNil(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(MetiAssessment{ID: "rid", CriterionID: "c1", OverrideStatus: "achieved"})
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	_, err := client.OverrideCriterion(context.Background(), "p", "c1", MetiOverrideRequest{
		OverrideStatus: "achieved",
	})
	if err != nil {
		t.Fatalf("OverrideCriterion error: %v", err)
	}
	if strings.Contains(string(seenBody), "improvement_action") {
		t.Errorf("nil ImprovementAction must be omitted; body = %s", string(seenBody))
	}
}

// TestOverrideCriterion_Conflict_F31_Permanent — 409 is the server's
// "already overridden" signal (F31 state-machine guard at the handler
// layer). The CLI must classify this as permanent so CI surfaces the
// "clear override first" hint rather than retrying.
func TestOverrideCriterion_Conflict_F31_Permanent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"error":"meti assessment has already been overridden; clear the existing override first"}`)
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	_, err := client.OverrideCriterion(context.Background(), "p", "c1", MetiOverrideRequest{OverrideStatus: "achieved"})
	var me *MetiError
	if !errors.As(err, &me) {
		t.Fatalf("err = %v, want *MetiError", err)
	}
	if !me.IsPermanent() {
		t.Errorf("409 (F31 already-overridden) must classify permanent")
	}
}

// TestOverrideCriterion_404Permanent — unknown criterion id or missing
// row both surface as 404 (generic body — no oracle). Permanent
// classification so CI does not retry against an invalid id.
func TestOverrideCriterion_404Permanent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":"meti assessment not found"}`)
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	_, err := client.OverrideCriterion(context.Background(), "p", "c1", MetiOverrideRequest{OverrideStatus: "achieved"})
	var me *MetiError
	if !errors.As(err, &me) {
		t.Fatalf("err = %v, want *MetiError", err)
	}
	if !me.IsPermanent() {
		t.Errorf("404 must classify permanent")
	}
}

// TestOverrideCriterion_EmptyCriterion_Validates — the CLI must reject
// an empty criterion_id BEFORE hitting the server (path would 404 with
// a less actionable message otherwise).
func TestOverrideCriterion_EmptyCriterion_Validates(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	_, err := client.OverrideCriterion(context.Background(), "p", "   ", MetiOverrideRequest{OverrideStatus: "achieved"})
	if err == nil {
		t.Fatal("expected error for empty criterion_id")
	}
	if hits != 0 {
		t.Errorf("validation must short-circuit BEFORE API call, hits = %d", hits)
	}
}

// TestOverrideCriterion_2xxEmptyBody_F23 — a 2xx with an empty body
// is a server contract violation. Must surface as ProtocolError /
// transient.
func TestOverrideCriterion_2xxEmptyBody_F23(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	_, err := client.OverrideCriterion(context.Background(), "p", "c1", MetiOverrideRequest{OverrideStatus: "achieved"})
	if err == nil {
		t.Fatal("F23: expected error for 2xx with empty body")
	}
	var me *MetiError
	if !errors.As(err, &me) {
		t.Fatalf("F23: err = %v (%T), want *MetiError", err, err)
	}
	if !me.IsTransient() {
		t.Errorf("F23: empty body must classify transient")
	}
}

// ----------------------------------------------------------------------------
// GetImprovementActions
// ----------------------------------------------------------------------------

// TestGetImprovementActions_HappyPath verifies the request shape and
// the decode path for the actions response envelope.
func TestGetImprovementActions_HappyPath(t *testing.T) {
	const projectID = "00000000-0000-0000-0000-000000000aaa"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		wantPath := "/api/v1/projects/" + projectID + "/meti/improvement-actions"
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		w.Header().Set("X-Total-Count", "3")
		_ = json.NewEncoder(w).Encode(metiImprovementActionsResponse{
			Actions: []ImprovementAction{
				{CriterionID: "c1", Status: "not_achieved", EffectiveStatus: "not_achieved"},
				{CriterionID: "c2", Status: "needs_review", EffectiveStatus: "needs_review"},
				{CriterionID: "c3", Status: "achieved", OverrideStatus: "needs_review", EffectiveStatus: "needs_review"},
			},
		})
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	actions, total, err := client.GetImprovementActions(context.Background(), projectID)
	if err != nil {
		t.Fatalf("GetImprovementActions error: %v", err)
	}
	if total != 3 || len(actions) != 3 {
		t.Errorf("actions/total = %d/%d, want 3/3", len(actions), total)
	}
}

// TestGetImprovementActions_FallbackToLen verifies the X-Total-Count
// missing case falls back to len(actions) so the CLI can render a
// summary line even against a legacy server that does not set the
// header.
func TestGetImprovementActions_FallbackToLen(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// no X-Total-Count
		_ = json.NewEncoder(w).Encode(metiImprovementActionsResponse{
			Actions: []ImprovementAction{{CriterionID: "c1"}, {CriterionID: "c2"}},
		})
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	actions, total, err := client.GetImprovementActions(context.Background(), "p")
	if err != nil {
		t.Fatalf("GetImprovementActions error: %v", err)
	}
	if total != 2 || len(actions) != 2 {
		t.Errorf("actions/total = %d/%d, want 2/2 (fallback to len)", len(actions), total)
	}
}
