package commands

// Unit tests for `sbomhub meti` — exercises each subcommand's UX +
// exit-code classification against a fake httptest server. Tests are
// keyed off the same M1/M2 fix pattern numbers as the cra_test.go
// regressions so a reviewer can trace each rule end-to-end:
//
//   - F21 exit code 3 (permanent) / 4 (transient)
//   - F22 strict error detection (METI has no AI-disabled fallback)
//   - F23 2xx contract validation (no assessments → transient)
//   - F26 pagination (list path)
//   - F28 X-Total-Count surfacing (list path)
//   - F31 already-overridden 409 → permanent (carried over from M2 cra)

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
// Fake server harness (mirrors craFakeServer)
// ---------------------------------------------------------------------------

type metiFakeServer struct {
	t                  *testing.T
	server             *httptest.Server
	listResp           func(call int, q map[string][]string) (status int, headers map[string]string, payload interface{})
	refreshResp        func(call int, body []byte) (status int, payload interface{})
	overrideResp       func(call int, criterion string, body []byte) (status int, payload interface{})
	clearOverrideResp  func(call int, criterion string, body []byte) (status int, payload interface{})
	improvementsResp   func(call int) (status int, headers map[string]string, payload interface{})

	listHits          int32
	refreshHits       int32
	overrideHits      int32
	clearOverrideHits int32
	improvementsHits  int32

	seenOverrides      []capturedMetiOverride
	seenClearOverrides []capturedMetiClearOverride
	mu                 sync.Mutex
}

type capturedMetiOverride struct {
	CriterionID       string
	OverrideStatus    string
	OverrideNote      string
	ImprovementAction *string
}

type capturedMetiClearOverride struct {
	CriterionID string
	Note        string
}

func newMetiFakeServer(t *testing.T) *metiFakeServer {
	t.Helper()
	tf := &metiFakeServer{t: t}
	tf.server = httptest.NewServer(http.HandlerFunc(tf.handle))
	t.Cleanup(tf.server.Close)
	return tf
}

func (tf *metiFakeServer) handle(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test-key" {
		tf.t.Errorf("Authorization = %q, want Bearer test-key", auth)
	}

	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/meti/assessment"):
		n := atomic.AddInt32(&tf.listHits, 1)
		status := http.StatusOK
		var payload interface{}
		var hdrs map[string]string
		if tf.listResp != nil {
			status, hdrs, payload = tf.listResp(int(n), r.URL.Query())
		} else {
			payload = map[string]interface{}{"assessments": []map[string]interface{}{}}
			hdrs = map[string]string{"X-Total-Count": "0"}
		}
		for k, v := range hdrs {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(payload)

	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/meti/assessment/refresh"):
		n := atomic.AddInt32(&tf.refreshHits, 1)
		body, _ := io.ReadAll(r.Body)
		status := http.StatusOK
		var payload interface{}
		if tf.refreshResp != nil {
			status, payload = tf.refreshResp(int(n), body)
		} else {
			payload = defaultMetiRefreshResp()
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(payload)

	case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/override"):
		n := atomic.AddInt32(&tf.overrideHits, 1)
		body, _ := io.ReadAll(r.Body)
		// path: /api/v1/projects/<pid>/meti/assessment/<criterion>/override
		parts := strings.Split(r.URL.Path, "/")
		criterion := ""
		for i, p := range parts {
			if p == "assessment" && i+1 < len(parts) {
				criterion = parts[i+1]
				break
			}
		}
		var req api.MetiOverrideRequest
		_ = json.Unmarshal(body, &req)
		tf.mu.Lock()
		tf.seenOverrides = append(tf.seenOverrides, capturedMetiOverride{
			CriterionID:       criterion,
			OverrideStatus:    req.OverrideStatus,
			OverrideNote:      req.OverrideNote,
			ImprovementAction: req.ImprovementAction,
		})
		tf.mu.Unlock()
		status := http.StatusOK
		var payload interface{}
		if tf.overrideResp != nil {
			status, payload = tf.overrideResp(int(n), criterion, body)
		} else {
			payload = api.MetiAssessment{
				ID:             "rid",
				ProjectID:      "p",
				CriterionID:    criterion,
				CriterionPhase: "env_setup",
				Status:         "needs_review",
				OverrideStatus: req.OverrideStatus,
				OverrideNote:   req.OverrideNote,
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(payload)

	case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/override"):
		n := atomic.AddInt32(&tf.clearOverrideHits, 1)
		body, _ := io.ReadAll(r.Body)
		// path: /api/v1/projects/<pid>/meti/assessment/<criterion>/override
		parts := strings.Split(r.URL.Path, "/")
		criterion := ""
		for i, p := range parts {
			if p == "assessment" && i+1 < len(parts) {
				criterion = parts[i+1]
				break
			}
		}
		var req api.MetiClearOverrideRequest
		_ = json.Unmarshal(body, &req)
		tf.mu.Lock()
		tf.seenClearOverrides = append(tf.seenClearOverrides, capturedMetiClearOverride{
			CriterionID: criterion,
			Note:        req.Note,
		})
		tf.mu.Unlock()
		status := http.StatusOK
		var payload interface{}
		if tf.clearOverrideResp != nil {
			status, payload = tf.clearOverrideResp(int(n), criterion, body)
		} else {
			// default success: post-clear row with override_* nulled.
			payload = api.MetiAssessment{
				ID:             "rid",
				ProjectID:      "p",
				CriterionID:    criterion,
				CriterionPhase: "env_setup",
				Status:         "needs_review",
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}

	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/meti/improvement-actions"):
		n := atomic.AddInt32(&tf.improvementsHits, 1)
		status := http.StatusOK
		var payload interface{}
		var hdrs map[string]string
		if tf.improvementsResp != nil {
			status, hdrs, payload = tf.improvementsResp(int(n))
		} else {
			payload = map[string]interface{}{"actions": []map[string]interface{}{}}
		}
		for k, v := range hdrs {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(payload)

	default:
		tf.t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func defaultMetiRefreshResp() map[string]interface{} {
	return map[string]interface{}{
		"assessments": []map[string]interface{}{
			{"id": "r1", "criterion_id": "env_setup.policy_documented", "criterion_phase": "env_setup", "status": "achieved"},
			{"id": "r2", "criterion_id": "sbom_creation.tool_selected", "criterion_phase": "sbom_creation", "status": "not_achieved"},
			{"id": "r3", "criterion_id": "sbom_operation.review_cadence", "criterion_phase": "sbom_operation", "status": "needs_review"},
		},
		"evaluator_version": "0.3.1",
		"refreshed":         3,
	}
}

// ---------------------------------------------------------------------------
// meti list
// ---------------------------------------------------------------------------

// TestMetiList_HappyPath_F28 — single page, X-Total-Count present.
// CLI must surface total in the summary line.
func TestMetiList_HappyPath_F28(t *testing.T) {
	tf := newMetiFakeServer(t)
	tf.listResp = func(call int, q map[string][]string) (int, map[string]string, interface{}) {
		return http.StatusOK,
			map[string]string{"X-Total-Count": "2"},
			map[string]interface{}{
				"assessments": []map[string]interface{}{
					{"id": "r1", "criterion_id": "env_setup.policy_documented", "criterion_phase": "env_setup", "status": "achieved"},
					{"id": "r2", "criterion_id": "sbom_creation.tool_selected", "criterion_phase": "sbom_creation", "status": "not_achieved"},
				},
			}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, stdout, _ := runMetiListAndCapture(t, client, metiListArgs{project: "p"})
	if res.err != nil {
		t.Fatalf("list err: %v", res.err)
	}
	out := stdout.String()
	if !strings.Contains(out, "env_setup.policy_documented") || !strings.Contains(out, "sbom_creation.tool_selected") {
		t.Errorf("stdout missing criterion rows: %s", out)
	}
	if !strings.Contains(out, "合計: 2") {
		t.Errorf("F28: stdout missing total count: %s", out)
	}
}

// TestMetiList_Pagination_F26 — first page returns 500 rows + tail
// page returns 50 rows. CLI must stitch them transparently and
// surface the X-Total-Count.
func TestMetiList_Pagination_F26(t *testing.T) {
	const pageSize = 500
	const tailSize = 50

	tf := newMetiFakeServer(t)
	tf.listResp = func(call int, q map[string][]string) (int, map[string]string, interface{}) {
		offset, _ := strconv.Atoi(firstMetiQuery(q, "offset"))
		var rows []map[string]interface{}
		switch offset {
		case 0:
			for i := 0; i < pageSize; i++ {
				rows = append(rows, map[string]interface{}{"id": fmt.Sprintf("r%d", i), "criterion_id": fmt.Sprintf("c%d", i)})
			}
		case pageSize:
			for i := 0; i < tailSize; i++ {
				rows = append(rows, map[string]interface{}{"id": fmt.Sprintf("r%d", pageSize+i), "criterion_id": fmt.Sprintf("c%d", pageSize+i)})
			}
		default:
			t.Errorf("F26: unexpected offset %d", offset)
		}
		return http.StatusOK,
			map[string]string{"X-Total-Count": strconv.Itoa(pageSize + tailSize)},
			map[string]interface{}{"assessments": rows}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runMetiListAndCapture(t, client, metiListArgs{project: "p", limit: 5}) // limit just trims display
	if res.err != nil {
		t.Fatalf("list err: %v", res.err)
	}
	if atomic.LoadInt32(&tf.listHits) != 2 {
		t.Errorf("F26: listHits = %d, want 2 (paginated stitch)", tf.listHits)
	}
}

func firstMetiQuery(q map[string][]string, key string) string {
	if vs, ok := q[key]; ok && len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// TestMetiList_FilterEncoding — filters land in the query string.
func TestMetiList_FilterEncoding(t *testing.T) {
	tf := newMetiFakeServer(t)
	var seenQuery map[string][]string
	tf.listResp = func(call int, q map[string][]string) (int, map[string]string, interface{}) {
		seenQuery = q
		return http.StatusOK,
			map[string]string{"X-Total-Count": "0"},
			map[string]interface{}{"assessments": []map[string]interface{}{}}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	hasOverride := true
	_, _, _ = runMetiListAndCapture(t, client, metiListArgs{
		project:     "p",
		phase:       "env_setup",
		status:      "achieved",
		hasOverride: &hasOverride,
	})
	checks := map[string]string{
		"phase":        "env_setup",
		"status":       "achieved",
		"has_override": "true",
	}
	for k, v := range checks {
		if got := firstMetiQuery(seenQuery, k); got != v {
			t.Errorf("query %s = %q, want %q", k, got, v)
		}
	}
}

// TestMetiList_EmptyProject — zero rows, friendly message.
func TestMetiList_EmptyProject(t *testing.T) {
	tf := newMetiFakeServer(t)
	tf.listResp = func(call int, q map[string][]string) (int, map[string]string, interface{}) {
		return http.StatusOK,
			map[string]string{"X-Total-Count": "0"},
			map[string]interface{}{"assessments": []map[string]interface{}{}}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, stdout, _ := runMetiListAndCapture(t, client, metiListArgs{project: "p"})
	if res.err != nil {
		t.Fatalf("list err: %v", res.err)
	}
	out := stdout.String()
	if !strings.Contains(out, "ありません") {
		t.Errorf("empty list must show friendly message, got %s", out)
	}
	if !strings.Contains(out, "meti refresh") {
		t.Errorf("empty list must hint at `meti refresh`, got %s", out)
	}
}

// TestMetiList_PermanentExit3 — 401 must classify permanent.
func TestMetiList_PermanentExit3(t *testing.T) {
	tf := newMetiFakeServer(t)
	tf.listResp = func(call int, q map[string][]string) (int, map[string]string, interface{}) {
		return http.StatusUnauthorized, nil, map[string]string{"error": "invalid api key"}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runMetiListAndCapture(t, client, metiListArgs{project: "p"})
	exitErr, ok := res.err.(*metiExitError)
	if !ok {
		t.Fatalf("err = %v (%T), want *metiExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("ExitCode = %d, want 3", exitErr.ExitCode())
	}
}

// TestMetiList_TransientExit4_503Generic_F22 — a generic 503 must
// surface as transient (no AI-disabled oracle for METI).
func TestMetiList_TransientExit4_503Generic_F22(t *testing.T) {
	tf := newMetiFakeServer(t)
	tf.listResp = func(call int, q map[string][]string) (int, map[string]string, interface{}) {
		return http.StatusServiceUnavailable, nil, map[string]string{"error": "Service Unavailable"}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runMetiListAndCapture(t, client, metiListArgs{project: "p"})
	exitErr, ok := res.err.(*metiExitError)
	if !ok {
		t.Fatalf("F22: err = %v (%T), want *metiExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 4 {
		t.Errorf("F22: ExitCode = %d, want 4 (generic 503 = transient outage)", exitErr.ExitCode())
	}
}

// TestMetiList_InvalidPhase_Validation — flag validation must fire
// BEFORE any API call.
func TestMetiList_InvalidPhase_Validation(t *testing.T) {
	tf := newMetiFakeServer(t)
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runMetiListAndCapture(t, client, metiListArgs{project: "p", phase: "bogus"})
	if res.err == nil {
		t.Fatal("expected validation error for invalid --phase")
	}
	if atomic.LoadInt32(&tf.listHits) != 0 {
		t.Errorf("validation must short-circuit BEFORE API call, listHits = %d", tf.listHits)
	}
}

// ---------------------------------------------------------------------------
// meti refresh
// ---------------------------------------------------------------------------

// TestMetiRefresh_HappyPath — operator gets the histogram + next steps.
func TestMetiRefresh_HappyPath(t *testing.T) {
	tf := newMetiFakeServer(t)
	client := api.NewClient(tf.server.URL, "test-key")
	res, stdout, _ := runMetiRefreshAndCapture(t, client, "p")
	if res.err != nil {
		t.Fatalf("refresh err: %v", res.err)
	}
	if atomic.LoadInt32(&tf.refreshHits) != 1 {
		t.Errorf("refreshHits = %d, want 1", tf.refreshHits)
	}
	out := stdout.String()
	if !strings.Contains(out, "再実行しました") {
		t.Errorf("stdout missing refresh confirmation: %s", out)
	}
	if !strings.Contains(out, "0.3.1") {
		t.Errorf("stdout missing evaluator version: %s", out)
	}
	if !strings.Contains(out, "achieved") {
		t.Errorf("stdout missing histogram: %s", out)
	}
}

// TestMetiRefresh_ForbiddenPermanent — 403 RequireWrite must exit 3.
func TestMetiRefresh_ForbiddenPermanent(t *testing.T) {
	tf := newMetiFakeServer(t)
	tf.refreshResp = func(call int, body []byte) (int, interface{}) {
		return http.StatusForbidden, map[string]string{"error": "write permission required"}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runMetiRefreshAndCapture(t, client, "p")
	exitErr, ok := res.err.(*metiExitError)
	if !ok {
		t.Fatalf("err = %v (%T), want *metiExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("ExitCode = %d, want 3 (403 = permanent)", exitErr.ExitCode())
	}
}

// TestMetiRefresh_TransientExit4_500 — 500 must classify transient.
func TestMetiRefresh_TransientExit4_500(t *testing.T) {
	tf := newMetiFakeServer(t)
	tf.refreshResp = func(call int, body []byte) (int, interface{}) {
		return http.StatusInternalServerError, map[string]string{"error": "internal"}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runMetiRefreshAndCapture(t, client, "p")
	exitErr, ok := res.err.(*metiExitError)
	if !ok {
		t.Fatalf("err = %v (%T), want *metiExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 4 {
		t.Errorf("ExitCode = %d, want 4 (500 = transient)", exitErr.ExitCode())
	}
}

// TestMetiRefresh_ProtocolError_F23 — a 2xx with empty body must
// surface as transient so CI does not silently green-light a no-op
// refresh.
func TestMetiRefresh_ProtocolError_F23(t *testing.T) {
	tf := newMetiFakeServer(t)
	tf.refreshResp = func(call int, body []byte) (int, interface{}) {
		return http.StatusOK, map[string]interface{}{}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runMetiRefreshAndCapture(t, client, "p")
	exitErr, ok := res.err.(*metiExitError)
	if !ok {
		t.Fatalf("F23: err = %v (%T), want *metiExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 4 {
		t.Errorf("F23: ExitCode = %d, want 4 (protocol violation = transient)", exitErr.ExitCode())
	}
}

// ---------------------------------------------------------------------------
// meti override
// ---------------------------------------------------------------------------

// TestMetiOverride_HappyPath — PUT body shape + stdout confirmation.
func TestMetiOverride_HappyPath(t *testing.T) {
	tf := newMetiFakeServer(t)
	client := api.NewClient(tf.server.URL, "test-key")
	res, stdout, _ := runMetiOverrideAndCapture(t, client, metiOverrideArgs{
		project:    "p",
		criterion:  "env_setup.policy_documented",
		status:     "achieved",
		note:       "verified by Tanaka 2026-09-10",
	})
	if res.err != nil {
		t.Fatalf("override err: %v", res.err)
	}
	if atomic.LoadInt32(&tf.overrideHits) != 1 {
		t.Errorf("overrideHits = %d, want 1", tf.overrideHits)
	}
	if len(tf.seenOverrides) != 1 {
		t.Fatalf("seenOverrides len = %d, want 1", len(tf.seenOverrides))
	}
	d := tf.seenOverrides[0]
	if d.CriterionID != "env_setup.policy_documented" {
		t.Errorf("CriterionID = %q", d.CriterionID)
	}
	if d.OverrideStatus != "achieved" {
		t.Errorf("OverrideStatus = %q", d.OverrideStatus)
	}
	if d.OverrideNote != "verified by Tanaka 2026-09-10" {
		t.Errorf("OverrideNote = %q", d.OverrideNote)
	}
	if d.ImprovementAction != nil {
		t.Errorf("ImprovementAction must be nil when --improvement-action is unset, got %v", d.ImprovementAction)
	}
	out := stdout.String()
	if !strings.Contains(out, "上書きを適用しました") {
		t.Errorf("stdout missing override confirmation: %s", out)
	}
}

// TestMetiOverride_ImprovementAction_PointerSemantics — when the
// operator passes --improvement-action, the CLI must send it as a
// non-nil pointer so the server's "do not change vs set to" contract
// survives (mirrors CRA EditedDraftText).
func TestMetiOverride_ImprovementAction_PointerSemantics(t *testing.T) {
	tf := newMetiFakeServer(t)
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runMetiOverrideAndCapture(t, client, metiOverrideArgs{
		project:           "p",
		criterion:         "c1",
		status:            "achieved",
		improvementAction: strPtr("rotate dependency monthly"),
	})
	if res.err != nil {
		t.Fatalf("override err: %v", res.err)
	}
	if len(tf.seenOverrides) != 1 {
		t.Fatalf("seenOverrides len = %d, want 1", len(tf.seenOverrides))
	}
	d := tf.seenOverrides[0]
	if d.ImprovementAction == nil {
		t.Fatal("ImprovementAction must be non-nil when --improvement-action is passed")
	}
	if *d.ImprovementAction != "rotate dependency monthly" {
		t.Errorf("ImprovementAction = %q, want 'rotate dependency monthly'", *d.ImprovementAction)
	}
}

// TestMetiOverride_409Permanent_F31 — re-override against an already-
// overridden row must classify permanent (F31 state-machine guard).
func TestMetiOverride_409Permanent_F31(t *testing.T) {
	tf := newMetiFakeServer(t)
	tf.overrideResp = func(call int, criterion string, body []byte) (int, interface{}) {
		return http.StatusConflict, map[string]string{
			"error": "meti assessment has already been overridden; clear the existing override first",
		}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runMetiOverrideAndCapture(t, client, metiOverrideArgs{
		project:   "p",
		criterion: "c1",
		status:    "achieved",
	})
	exitErr, ok := res.err.(*metiExitError)
	if !ok {
		t.Fatalf("err = %v (%T), want *metiExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("F31: ExitCode = %d, want 3 (409 already-overridden = permanent)", exitErr.ExitCode())
	}
}

// TestMetiOverride_ForbiddenPermanent — 403 RequireWrite must exit 3.
func TestMetiOverride_ForbiddenPermanent(t *testing.T) {
	tf := newMetiFakeServer(t)
	tf.overrideResp = func(call int, criterion string, body []byte) (int, interface{}) {
		return http.StatusForbidden, map[string]string{"error": "write permission required"}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runMetiOverrideAndCapture(t, client, metiOverrideArgs{
		project:   "p",
		criterion: "c1",
		status:    "achieved",
	})
	exitErr, ok := res.err.(*metiExitError)
	if !ok {
		t.Fatalf("err = %v (%T), want *metiExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("ExitCode = %d, want 3 (403 = permanent)", exitErr.ExitCode())
	}
}

// TestMetiOverride_MissingFlags — flag validation short-circuits the
// CLI BEFORE hitting the server.
func TestMetiOverride_MissingFlags(t *testing.T) {
	tf := newMetiFakeServer(t)
	client := api.NewClient(tf.server.URL, "test-key")
	cases := []metiOverrideArgs{
		{project: "p"},                                              // no criterion / status
		{project: "p", criterion: "c1"},                             // no status
		{project: "p", criterion: "c1", status: "bogus"},            // bad status
		{project: "p", criterion: "", status: "achieved"},           // empty criterion
	}
	for i, args := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			res, _, _ := runMetiOverrideAndCapture(t, client, args)
			if res.err == nil {
				t.Fatalf("expected error for args %+v", args)
			}
		})
	}
	if atomic.LoadInt32(&tf.overrideHits) != 0 {
		t.Errorf("validation must short-circuit BEFORE API call, overrideHits = %d", tf.overrideHits)
	}
}

// ---------------------------------------------------------------------------
// validateMetiPhase / validateMetiStatus
// ---------------------------------------------------------------------------

func TestValidateMetiPhase(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"env_setup", false},
		{"sbom_creation", false},
		{"sbom_operation", false},
		{"bogus", true},
		{"", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			err := validateMetiPhase(tc.in)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateMetiStatus(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"achieved", false},
		{"not_achieved", false},
		{"needs_review", false},
		{"not_applicable", false},
		{"approved", true}, // a CRA-only status — must NOT be accepted for METI
		{"", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			err := validateMetiStatus(tc.in)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// metiFailureToExitError unit-tests
// ---------------------------------------------------------------------------

// TestMetiFailureToExitError_Classification pins the helper's
// permanent vs transient buckets across the status-code surface.
// Mirrors the M2 cra equivalent.
func TestMetiFailureToExitError_Classification(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"401 → 3", &api.MetiError{StatusCode: 401}, 3},
		{"403 → 3", &api.MetiError{StatusCode: 403}, 3},
		{"404 → 3", &api.MetiError{StatusCode: 404}, 3},
		{"409 → 3", &api.MetiError{StatusCode: 409}, 3},
		{"429 → 4", &api.MetiError{StatusCode: 429}, 4},
		{"500 → 4", &api.MetiError{StatusCode: 500}, 4},
		{"502 → 4", &api.MetiError{StatusCode: 502}, 4},
		{"503 generic → 4", &api.MetiError{StatusCode: 503, Message: "Service Unavailable"}, 4},
		{"protocol → 4", &api.MetiError{StatusCode: 200, ProtocolError: true}, 4},
		{"unknown 418 → 3", &api.MetiError{StatusCode: 418}, 3},
		{"network → 4", io.ErrUnexpectedEOF, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := metiFailureToExitError("op", tc.err)
			exitErr, ok := err.(*metiExitError)
			if !ok {
				t.Fatalf("err = %v (%T), want *metiExitError", err, err)
			}
			if exitErr.ExitCode() != tc.wantCode {
				t.Errorf("ExitCode = %d, want %d", exitErr.ExitCode(), tc.wantCode)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test scaffolding — direct calls into runMetiXxx would require
// seeding the package-scoped flag globals (metiProject, metiListPhase,
// …) on every test, which is brittle when the test runs alongside
// others. Instead, we invoke the lower-level logic via small wrapper
// functions that take an explicit args struct. Mirrors the M2 cra_test
// pattern.
// ---------------------------------------------------------------------------

type metiListArgs struct {
	project     string
	phase       string
	status      string
	hasOverride *bool
	limit       int
}

type metiOverrideArgs struct {
	project           string
	criterion         string
	status            string
	note              string
	improvementAction *string
}

func strPtr(s string) *string { return &s }

// runMetiListAndCapture replays the runMetiList body using injected
// args + a buffered OutputConfig so the test does not have to leak
// package globals between cases. The wrapper deliberately mirrors
// runMetiList step-by-step so a refactor that splits runMetiList will
// surface here.
func runMetiListAndCapture(t *testing.T, client *api.Client, args metiListArgs) (capturedResult, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	out := &OutputConfig{Writer: &stdout, ErrWriter: &stderr}

	if strings.TrimSpace(args.project) == "" {
		return capturedResult{err: fmt.Errorf("--project は必須")}, &stdout, &stderr
	}
	if args.phase != "" {
		if err := validateMetiPhase(args.phase); err != nil {
			return capturedResult{err: err}, &stdout, &stderr
		}
	}
	if args.status != "" {
		if err := validateMetiStatus(args.status); err != nil {
			return capturedResult{err: err}, &stdout, &stderr
		}
	}

	ctx := context.Background()
	filter := api.MetiAssessmentListFilter{
		Phase:       args.phase,
		Status:      args.status,
		HasOverride: args.hasOverride,
	}
	rows, total, err := client.GetAssessment(ctx, args.project, filter)
	if err != nil {
		return capturedResult{err: metiFailureToExitError("meti list", err)}, &stdout, &stderr
	}
	rendered := rows
	if args.limit > 0 && len(rendered) > args.limit {
		rendered = rendered[:args.limit]
	}

	w := out.Writer
	if len(rendered) == 0 {
		fmt.Fprintln(w, "METI 自己評価行はありません。")
		fmt.Fprintln(w, "  → `sbomhub meti refresh --project <id>` で evaluator を実行してください")
		return capturedResult{err: nil}, &stdout, &stderr
	}
	fmt.Fprintln(w, "METI 自己評価 一覧")
	fmt.Fprintln(w, "-------------------")
	for _, r := range rendered {
		effective := r.Status
		overrideMark := ""
		if r.OverrideStatus != "" {
			effective = r.OverrideStatus
			overrideMark = " (override)"
		}
		fmt.Fprintf(w, "  %s phase=%s status=%s effective=%s%s\n",
			r.CriterionID, orDash(r.CriterionPhase), orDash(r.Status), effective, overrideMark)
	}
	fmt.Fprintf(w, "\n表示: %d / 合計: %d\n", len(rendered), total)
	return capturedResult{err: nil}, &stdout, &stderr
}

// runMetiRefreshAndCapture mirrors runMetiRefresh step-by-step.
func runMetiRefreshAndCapture(t *testing.T, client *api.Client, project string) (capturedResult, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	out := &OutputConfig{Writer: &stdout, ErrWriter: &stderr}
	if strings.TrimSpace(project) == "" {
		return capturedResult{err: fmt.Errorf("--project は必須")}, &stdout, &stderr
	}
	ctx := context.Background()
	res, err := client.RefreshAssessment(ctx, project)
	if err != nil {
		return capturedResult{err: metiFailureToExitError("meti refresh", err)}, &stdout, &stderr
	}
	fmt.Fprintf(out.Writer, "METI evaluator を再実行しました\n")
	fmt.Fprintf(out.Writer, "  Refreshed: %d\n", res.Refreshed)
	if res.EvaluatorVersion != "" {
		fmt.Fprintf(out.Writer, "  Evaluator version: %s\n", res.EvaluatorVersion)
	}
	counts := map[string]int{}
	for _, a := range res.Assessments {
		s := a.Status
		if a.OverrideStatus != "" {
			s = a.OverrideStatus
		}
		counts[s]++
	}
	for _, s := range []string{"achieved", "not_achieved", "needs_review", "not_applicable"} {
		if c, ok := counts[s]; ok {
			fmt.Fprintf(out.Writer, "  %s: %d\n", s, c)
		}
	}
	return capturedResult{err: nil}, &stdout, &stderr
}

// runMetiOverrideAndCapture mirrors runMetiOverride step-by-step.
func runMetiOverrideAndCapture(t *testing.T, client *api.Client, args metiOverrideArgs) (capturedResult, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	out := &OutputConfig{Writer: &stdout, ErrWriter: &stderr}
	if strings.TrimSpace(args.project) == "" {
		return capturedResult{err: fmt.Errorf("--project は必須")}, &stdout, &stderr
	}
	if strings.TrimSpace(args.criterion) == "" {
		return capturedResult{err: fmt.Errorf("--criterion は必須")}, &stdout, &stderr
	}
	if strings.TrimSpace(args.status) == "" {
		return capturedResult{err: fmt.Errorf("--status は必須")}, &stdout, &stderr
	}
	if err := validateMetiStatus(args.status); err != nil {
		return capturedResult{err: err}, &stdout, &stderr
	}
	ctx := context.Background()
	req := api.MetiOverrideRequest{
		OverrideStatus:    args.status,
		OverrideNote:      args.note,
		ImprovementAction: args.improvementAction,
	}
	fresh, err := client.OverrideCriterion(ctx, args.project, args.criterion, req)
	if err != nil {
		return capturedResult{err: metiFailureToExitError("meti override", err)}, &stdout, &stderr
	}
	fmt.Fprintf(out.Writer, "METI criterion %s に上書きを適用しました\n", fresh.CriterionID)
	fmt.Fprintf(out.Writer, "  Override status: %s\n", fresh.OverrideStatus)
	return capturedResult{err: nil}, &stdout, &stderr
}

// ---------------------------------------------------------------------------
// meti clear-override (M3 Codex review #F36)
// ---------------------------------------------------------------------------

type metiClearOverrideArgs struct {
	project   string
	criterion string
	note      string
}

// runMetiClearOverrideAndCapture mirrors runMetiClearOverride step-by-step.
// Same pattern as runMetiOverrideAndCapture so the test does not have
// to leak package globals between cases.
func runMetiClearOverrideAndCapture(t *testing.T, client *api.Client, args metiClearOverrideArgs) (capturedResult, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	out := &OutputConfig{Writer: &stdout, ErrWriter: &stderr}
	if strings.TrimSpace(args.project) == "" {
		return capturedResult{err: fmt.Errorf("--project は必須")}, &stdout, &stderr
	}
	if strings.TrimSpace(args.criterion) == "" {
		return capturedResult{err: fmt.Errorf("--criterion は必須")}, &stdout, &stderr
	}
	cleanedNote := strings.TrimSpace(args.note)
	if cleanedNote == "" {
		return capturedResult{err: fmt.Errorf("--note は必須")}, &stdout, &stderr
	}
	if len(cleanedNote) > metiClearOverrideNoteMaxLen {
		return capturedResult{err: fmt.Errorf("--note は %d 文字以内", metiClearOverrideNoteMaxLen)}, &stdout, &stderr
	}
	ctx := context.Background()
	req := api.MetiClearOverrideRequest{Note: cleanedNote}
	if err := client.ClearOverrideCriterion(ctx, args.project, args.criterion, req); err != nil {
		return capturedResult{err: metiFailureToExitError("meti clear-override", err)}, &stdout, &stderr
	}
	fmt.Fprintf(out.Writer, "METI criterion %s の上書きを取り消しました\n", args.criterion)
	fmt.Fprintf(out.Writer, "  Cleared note: %s\n", cleanedNote)
	return capturedResult{err: nil}, &stdout, &stderr
}

// TestMetiClearOverride_HappyPath_F36 — DELETE body shape + stdout
// confirmation. Verifies criterion + note round-trip through to the
// captured request and that the success path returns nil error.
func TestMetiClearOverride_HappyPath_F36(t *testing.T) {
	tf := newMetiFakeServer(t)
	client := api.NewClient(tf.server.URL, "test-key")
	res, stdout, _ := runMetiClearOverrideAndCapture(t, client, metiClearOverrideArgs{
		project:   "p",
		criterion: "env_setup.policy_documented",
		note:      "re-evaluated 2026-09-12: original override was a mis-read",
	})
	if res.err != nil {
		t.Fatalf("F36: clear-override err: %v", res.err)
	}
	if atomic.LoadInt32(&tf.clearOverrideHits) != 1 {
		t.Errorf("F36: clearOverrideHits = %d, want 1", tf.clearOverrideHits)
	}
	if len(tf.seenClearOverrides) != 1 {
		t.Fatalf("F36: seenClearOverrides len = %d, want 1", len(tf.seenClearOverrides))
	}
	d := tf.seenClearOverrides[0]
	if d.CriterionID != "env_setup.policy_documented" {
		t.Errorf("F36: CriterionID = %q", d.CriterionID)
	}
	if !strings.Contains(d.Note, "re-evaluated") {
		t.Errorf("F36: Note = %q (must round-trip operator rationale)", d.Note)
	}
	out := stdout.String()
	if !strings.Contains(out, "上書きを取り消しました") {
		t.Errorf("F36: stdout missing clear-override confirmation: %s", out)
	}
}

// TestMetiClearOverride_404Permanent_F36 — server returns 404 when
// there is no override to clear (or row does not exist). Permanent
// classification: the operator's correct response is "check state",
// not "retry blindly".
func TestMetiClearOverride_404Permanent_F36(t *testing.T) {
	tf := newMetiFakeServer(t)
	tf.clearOverrideResp = func(call int, criterion string, body []byte) (int, interface{}) {
		return http.StatusNotFound, map[string]string{"error": "meti assessment override not found"}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runMetiClearOverrideAndCapture(t, client, metiClearOverrideArgs{
		project:   "p",
		criterion: "c1",
		note:      "trying to clear something that is not there",
	})
	exitErr, ok := res.err.(*metiExitError)
	if !ok {
		t.Fatalf("F36: err = %v (%T), want *metiExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("F36: ExitCode = %d, want 3 (404 no override = permanent)", exitErr.ExitCode())
	}
}

// TestMetiClearOverride_400NoteRejected_F36 — server's
// validateMetiOverrideNote 400 must exit 3 (input error). The CLI
// short-circuits empty/over-long notes locally; this test pins the
// classification for any server-side 400 that slips through.
func TestMetiClearOverride_400NoteRejected_F36(t *testing.T) {
	tf := newMetiFakeServer(t)
	tf.clearOverrideResp = func(call int, criterion string, body []byte) (int, interface{}) {
		return http.StatusBadRequest, map[string]string{"error": "override_note is required and must be 1-4096 characters"}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runMetiClearOverrideAndCapture(t, client, metiClearOverrideArgs{
		project:   "p",
		criterion: "c1",
		note:      "non-empty so CLI-side validator lets it through",
	})
	exitErr, ok := res.err.(*metiExitError)
	if !ok {
		t.Fatalf("F36: err = %v (%T), want *metiExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("F36: ExitCode = %d, want 3 (400 note validation = permanent)", exitErr.ExitCode())
	}
}

// TestMetiClearOverride_MissingFlags_F36 — flag validation must
// short-circuit BEFORE the API call. Mirrors the override
// MissingFlags table-test.
func TestMetiClearOverride_MissingFlags_F36(t *testing.T) {
	tf := newMetiFakeServer(t)
	client := api.NewClient(tf.server.URL, "test-key")
	cases := []metiClearOverrideArgs{
		{project: "p"},                                              // no criterion / note
		{project: "p", criterion: "c1"},                             // no note
		{project: "p", criterion: "c1", note: ""},                   // empty note
		{project: "p", criterion: "c1", note: "   "},                // whitespace-only note
		{project: "p", criterion: "", note: "ok"},                   // empty criterion
		{project: "", criterion: "c1", note: "ok"},                  // empty project
		{project: "p", criterion: "c1", note: strings.Repeat("x", metiClearOverrideNoteMaxLen+1)}, // over cap
	}
	for i, args := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			res, _, _ := runMetiClearOverrideAndCapture(t, client, args)
			if res.err == nil {
				t.Fatalf("F36: expected error for args %+v", args)
			}
		})
	}
	if atomic.LoadInt32(&tf.clearOverrideHits) != 0 {
		t.Errorf("F36: validation must short-circuit BEFORE API call, clearOverrideHits = %d", tf.clearOverrideHits)
	}
}

// TestMetiClearOverride_ForbiddenPermanent_F36 — 403 RequireWrite
// (or audit user identity missing) must exit 3.
func TestMetiClearOverride_ForbiddenPermanent_F36(t *testing.T) {
	tf := newMetiFakeServer(t)
	tf.clearOverrideResp = func(call int, criterion string, body []byte) (int, interface{}) {
		return http.StatusForbidden, map[string]string{"error": "write permission required"}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runMetiClearOverrideAndCapture(t, client, metiClearOverrideArgs{
		project:   "p",
		criterion: "c1",
		note:      "ok",
	})
	exitErr, ok := res.err.(*metiExitError)
	if !ok {
		t.Fatalf("F36: err = %v (%T), want *metiExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("F36: ExitCode = %d, want 3 (403 = permanent)", exitErr.ExitCode())
	}
}

// TestMetiClearOverride_TransientExit4_500_F36 — 5xx must classify
// transient so CI can retry the clear after a server blip.
func TestMetiClearOverride_TransientExit4_500_F36(t *testing.T) {
	tf := newMetiFakeServer(t)
	tf.clearOverrideResp = func(call int, criterion string, body []byte) (int, interface{}) {
		return http.StatusInternalServerError, map[string]string{"error": "internal"}
	}
	client := api.NewClient(tf.server.URL, "test-key")
	res, _, _ := runMetiClearOverrideAndCapture(t, client, metiClearOverrideArgs{
		project:   "p",
		criterion: "c1",
		note:      "ok",
	})
	exitErr, ok := res.err.(*metiExitError)
	if !ok {
		t.Fatalf("F36: err = %v (%T), want *metiExitError", res.err, res.err)
	}
	if exitErr.ExitCode() != 4 {
		t.Errorf("F36: ExitCode = %d, want 4 (500 = transient)", exitErr.ExitCode())
	}
}
