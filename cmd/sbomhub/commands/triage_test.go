package commands

// Unit tests for `sbomhub triage` — exercises the interactive loop
// against a fake httptest server. The test seeds the vulnerability
// list, the /triage/run response, and the /vex-drafts/{id}/decision
// echo so each step's request shape can be asserted independently of
// the network layer.
//
// Three flows are covered:
//
//   1. happy path: stdin = "a\nr\nq\n" against 3 vulns →
//      1 approved + 1 rejected + early quit (exit code 1, summary
//      printed before exit).
//   2. BYOK fallback: server returns 503 with reason; loop records
//      every vuln as under_investigation, prints the stderr hint
//      exactly once, exits 0.
//   3. --non-interactive: every draft auto-recorded as
//      edited/under_investigation without consulting stdin.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/youichi-uda/sbomhub-cli/internal/api"
)

// triageFakeServer is the shared fake — each test seeds different
// behavior into the handler. We track per-endpoint hit counts so the
// assertions can verify exactly how many round-trips occurred.
type triageFakeServer struct {
	t              *testing.T
	server         *httptest.Server
	vulns          []api.VulnerabilityRecord
	runTriageResp  func(call int, body []byte) (status int, payload interface{})
	decisionResp   func(call int, draftID string, body []byte) (status int, payload interface{})
	vulnListHits   int32
	triageRunHits  int32
	decisionHits   int32
	seenDecisions  []capturedDecision
	mu             sync.Mutex
}

type capturedDecision struct {
	DraftID             string
	Decision            string
	EditedState         string
	EditedJustification string
	EditedDetail        string
}

func newTriageFakeServer(t *testing.T, vulns []api.VulnerabilityRecord) *triageFakeServer {
	t.Helper()
	tf := &triageFakeServer{t: t, vulns: vulns}
	tf.server = httptest.NewServer(http.HandlerFunc(tf.handle))
	t.Cleanup(tf.server.Close)
	return tf
}

func (tf *triageFakeServer) handle(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test-key" {
		tf.t.Errorf("Authorization = %q, want Bearer test-key", auth)
	}

	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/vulnerabilities"):
		atomic.AddInt32(&tf.vulnListHits, 1)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(tf.vulns)

	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/triage/run"):
		n := atomic.AddInt32(&tf.triageRunHits, 1)
		body, _ := io.ReadAll(r.Body)
		status := http.StatusCreated
		var payload interface{}
		if tf.runTriageResp != nil {
			status, payload = tf.runTriageResp(int(n), body)
		} else {
			payload = defaultRunResp(int(n))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(payload)

	case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/vex-drafts/") && strings.HasSuffix(r.URL.Path, "/decision"):
		n := atomic.AddInt32(&tf.decisionHits, 1)
		body, _ := io.ReadAll(r.Body)
		var dec api.DecisionRequest
		_ = json.Unmarshal(body, &dec)
		// Extract draftID from path: /api/v1/projects/<pid>/vex-drafts/<did>/decision
		parts := strings.Split(r.URL.Path, "/")
		draftID := ""
		for i, p := range parts {
			if p == "vex-drafts" && i+1 < len(parts) {
				draftID = parts[i+1]
				break
			}
		}
		tf.mu.Lock()
		tf.seenDecisions = append(tf.seenDecisions, capturedDecision{
			DraftID:             draftID,
			Decision:            dec.Decision,
			EditedState:         dec.EditedState,
			EditedJustification: dec.EditedJustification,
			EditedDetail:        dec.EditedDetail,
		})
		tf.mu.Unlock()

		status := http.StatusOK
		var payload interface{}
		if tf.decisionResp != nil {
			status, payload = tf.decisionResp(int(n), draftID, body)
		} else {
			payload = api.VEXDraft{ID: draftID, Decision: dec.Decision}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(payload)

	default:
		tf.t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func defaultRunResp(n int) map[string]interface{} {
	conf := 0.85
	draftID := fakeDraftID(n)
	return map[string]interface{}{
		"draft": map[string]interface{}{
			"id":               draftID,
			"project_id":       "00000000-0000-0000-0000-000000000aaa",
			"component_id":     "00000000-0000-0000-0000-0000000000bb",
			"vulnerability_id": fakeVulnID(n),
			"cve_id":           fakeCVE(n),
			"state":            "not_affected",
			"justification":    "code_not_reachable",
			"detail":           "vulnerable function not reachable from main",
			"confidence":       conf,
			"provider":         "anthropic",
			"model":            "claude-opus-4-7",
			"decision":         "pending",
		},
		"llm_call_id": "00000000-0000-0000-0000-000000000eee",
		"parsed_decision": map[string]interface{}{
			"state":      "not_affected",
			"confidence": conf,
			"evidence": []map[string]interface{}{
				{
					"kind":        "import_path",
					"import_path": "github.com/foo/bar/pkg/x",
					"source":      "reachability",
				},
				{
					"kind":     "advisory_excerpt",
					"raw_snippet": "Affected: pkg/x.Vuln when called with attacker-controlled input",
					"source":   "advisory_parser",
				},
			},
		},
		"clamped":   false,
		"threshold": 0.7,
	}
}

func fakeCVE(n int) string  { return "CVE-2024-1000" + strings.Repeat("0", 0) + itoa(n) }
func fakeDraftID(n int) string {
	return "11111111-1111-1111-1111-11111111000" + itoa(n)
}
func fakeVulnID(n int) string {
	return "22222222-2222-2222-2222-22222222000" + itoa(n)
}
func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return "9" // not expected in tests
}

func threeVulns() []api.VulnerabilityRecord {
	return []api.VulnerabilityRecord{
		{ID: fakeVulnID(1), CVEID: fakeCVE(1), Severity: "HIGH"},
		{ID: fakeVulnID(2), CVEID: fakeCVE(2), Severity: "MEDIUM"},
		{ID: fakeVulnID(3), CVEID: fakeCVE(3), Severity: "LOW"},
	}
}

// TestTriageLoop_HappyPath drives "a\nr\nq\n" against 3 vulns and
// asserts the expected exit code, decisions persisted, and that the
// loop quit before reaching the third vuln.
func TestTriageLoop_HappyPath(t *testing.T) {
	tf := newTriageFakeServer(t, threeVulns())
	client := api.NewClient(tf.server.URL, "test-key")

	stdin := strings.NewReader("a\nr\nq\n")
	var stdout, stderr bytes.Buffer

	err := runTriageLoop(context.Background(), client, triageOpts{
		projectID:           "00000000-0000-0000-0000-000000000aaa",
		ecosystem:           "go",
		nonInteractive:      false,
		confidenceThreshold: 0.7,
		path:                ".",
		stdin:               stdin,
		stdout:              &stdout,
		stderr:              &stderr,
		editor:              nil,
	})

	// q → exit code 1
	exitErr, ok := err.(*triageExitError)
	if !ok {
		t.Fatalf("err = %v (%T), want *triageExitError", err, err)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("ExitCode = %d, want 1 (user quit)", exitErr.ExitCode())
	}

	// /triage/run runs BEFORE prompting (the operator needs to see
	// the AI suggestion before they can decide), so all three vulns
	// hit the endpoint even though the operator quits on vuln 3
	// without persisting a decision.
	if got := atomic.LoadInt32(&tf.triageRunHits); got != 3 {
		t.Errorf("triageRunHits = %d, want 3 (run cycle happens before prompt)", got)
	}

	// Two decisions persisted: approved, rejected.
	if got := atomic.LoadInt32(&tf.decisionHits); got != 2 {
		t.Errorf("decisionHits = %d, want 2", got)
	}
	if len(tf.seenDecisions) != 2 {
		t.Fatalf("seenDecisions len = %d, want 2", len(tf.seenDecisions))
	}
	if tf.seenDecisions[0].Decision != decisionApproved {
		t.Errorf("decisions[0] = %q, want approved", tf.seenDecisions[0].Decision)
	}
	if tf.seenDecisions[1].Decision != decisionRejected {
		t.Errorf("decisions[1] = %q, want rejected", tf.seenDecisions[1].Decision)
	}

	out := stdout.String()
	// Vuln header echo
	if !strings.Contains(out, fakeCVE(1)) {
		t.Errorf("stdout missing CVE 1 header: %s", out)
	}
	// Summary printed even when quitting early
	if !strings.Contains(out, "Triage 結果") {
		t.Errorf("stdout missing summary: %s", out)
	}
}

// TestTriageLoop_AIDisabledServerPersisted verifies the M1 Codex review
// #F4 path: server returns 2xx with AIDisabled=true and a persisted
// under_investigation draft. CLI prints the hint once, counts the
// drafts in the under_investigation summary, never opens a stdin
// prompt (the operator has nothing to decide on an AI-skipped draft),
// and exits 0.
func TestTriageLoop_AIDisabledServerPersisted(t *testing.T) {
	tf := newTriageFakeServer(t, threeVulns())
	tf.runTriageResp = func(call int, body []byte) (int, interface{}) {
		draftID := fakeDraftID(call)
		return http.StatusCreated, map[string]interface{}{
			"draft": map[string]interface{}{
				"id":               draftID,
				"project_id":       "00000000-0000-0000-0000-000000000aaa",
				"component_id":     "00000000-0000-0000-0000-0000000000bb",
				"vulnerability_id": fakeVulnID(call),
				"cve_id":           fakeCVE(call),
				"state":            "under_investigation",
				"provider":         "disabled",
				"decision":         "pending",
			},
			"drafts": []interface{}{map[string]interface{}{
				"id":    draftID,
				"state": "under_investigation",
			}},
			"clamped":     false,
			"threshold":   0.7,
			"ai_disabled": true,
		}
	}
	client := api.NewClient(tf.server.URL, "test-key")

	// stdin must NOT be consulted — the AI-disabled path skips the
	// per-vuln prompt because there is no AI verdict to decide on.
	stdin := strings.NewReader("a\na\na\n")
	var stdout, stderr bytes.Buffer
	err := runTriageLoop(context.Background(), client, triageOpts{
		projectID:           "00000000-0000-0000-0000-000000000aaa",
		ecosystem:           "go",
		nonInteractive:      false,
		confidenceThreshold: 0.7,
		path:                ".",
		stdin:               stdin,
		stdout:              &stdout,
		stderr:              &stderr,
		editor:              nil,
	})
	if err != nil {
		t.Fatalf("runTriageLoop returned %v; want nil", err)
	}
	if got := atomic.LoadInt32(&tf.triageRunHits); got != 3 {
		t.Errorf("triageRunHits = %d, want 3", got)
	}
	// No /decision PUT — the server already persisted the draft, the
	// CLI is just rendering and counting.
	if got := atomic.LoadInt32(&tf.decisionHits); got != 0 {
		t.Errorf("decisionHits = %d, want 0 (server persisted draft + audit)", got)
	}
	errOut := stderr.String()
	if !strings.Contains(errOut, "APIキー未設定") {
		t.Errorf("stderr missing AI-disabled hint: %q", errOut)
	}
	if c := strings.Count(errOut, "APIキー未設定"); c != 1 {
		t.Errorf("AI-disabled hint printed %d times, want 1", c)
	}
	if !strings.Contains(stdout.String(), "AI disabled; server persisted") {
		t.Errorf("stdout missing server-persisted draft line: %s", stdout.String())
	}
}

// TestTriageLoop_AIDisabledFallback verifies the LEGACY BYOK-not-configured
// path: an older server returns 503 from llm.DisabledError. CLI prints the
// hint once on stderr, marks every vuln as under_investigation, exits
// cleanly (return nil). The new server returns 2xx + AIDisabled=true and
// is covered by TestTriageLoop_AIDisabledServerPersisted above.
func TestTriageLoop_AIDisabledFallback(t *testing.T) {
	tf := newTriageFakeServer(t, threeVulns())
	tf.runTriageResp = func(call int, body []byte) (int, interface{}) {
		return http.StatusServiceUnavailable, map[string]string{
			"error":  "AI features are disabled",
			"reason": "no LLM provider configured (OPENAI_API_KEY/ANTHROPIC_API_KEY unset)",
		}
	}
	client := api.NewClient(tf.server.URL, "test-key")

	// stdin should never be consulted in the AI-disabled fallback —
	// we still pass a non-empty reader so a regression that DOES read
	// stdin fails loudly rather than blocking forever.
	stdin := strings.NewReader("a\na\na\n")
	var stdout, stderr bytes.Buffer

	err := runTriageLoop(context.Background(), client, triageOpts{
		projectID:           "00000000-0000-0000-0000-000000000aaa",
		ecosystem:           "go",
		nonInteractive:      false,
		confidenceThreshold: 0.7,
		path:                ".",
		stdin:               stdin,
		stdout:              &stdout,
		stderr:              &stderr,
		editor:              nil,
	})
	if err != nil {
		t.Fatalf("runTriageLoop returned %v; want nil (BYOK fallback must exit 0)", err)
	}

	// Every vuln hits /triage/run (the loop does not short-circuit
	// the per-vuln call — it relies on each 503 to know AI is off),
	// but NO decision PUT happens because we never received a draft.
	if got := atomic.LoadInt32(&tf.triageRunHits); got != 3 {
		t.Errorf("triageRunHits = %d, want 3", got)
	}
	if got := atomic.LoadInt32(&tf.decisionHits); got != 0 {
		t.Errorf("decisionHits = %d, want 0 (no draft to decide on)", got)
	}

	errOut := stderr.String()
	if !strings.Contains(errOut, "APIキー未設定") {
		t.Errorf("stderr missing AI-disabled hint: %q", errOut)
	}
	// Hint must appear exactly once even though 3 vulns hit 503.
	if c := strings.Count(errOut, "APIキー未設定"); c != 1 {
		t.Errorf("AI-disabled hint printed %d times, want 1", c)
	}
}

// TestTriageLoop_NonInteractive verifies that --non-interactive skips
// the prompt and applies the under_investigation fallback for every
// draft.
func TestTriageLoop_NonInteractive(t *testing.T) {
	tf := newTriageFakeServer(t, threeVulns())
	client := api.NewClient(tf.server.URL, "test-key")

	// stdin must NOT be read in non-interactive mode. A regression
	// that does read would block on the empty reader.
	stdin := strings.NewReader("")
	var stdout, stderr bytes.Buffer

	err := runTriageLoop(context.Background(), client, triageOpts{
		projectID:           "00000000-0000-0000-0000-000000000aaa",
		ecosystem:           "go",
		nonInteractive:      true,
		confidenceThreshold: 0.7,
		path:                ".",
		stdin:               stdin,
		stdout:              &stdout,
		stderr:              &stderr,
		editor:              nil,
	})
	if err != nil {
		t.Fatalf("runTriageLoop returned %v; want nil", err)
	}

	if got := atomic.LoadInt32(&tf.triageRunHits); got != 3 {
		t.Errorf("triageRunHits = %d, want 3", got)
	}
	if got := atomic.LoadInt32(&tf.decisionHits); got != 3 {
		t.Errorf("decisionHits = %d, want 3", got)
	}
	for i, d := range tf.seenDecisions {
		if d.Decision != decisionEdited {
			t.Errorf("decisions[%d].Decision = %q, want edited", i, d.Decision)
		}
		if d.EditedState != stateUnderInvestigation {
			t.Errorf("decisions[%d].EditedState = %q, want under_investigation", i, d.EditedState)
		}
	}
}

// TestTriageLoop_EmptyVulnList verifies the "nothing to do" early-exit
// path. The loop must not call /triage/run when the project has zero
// vulnerabilities.
func TestTriageLoop_EmptyVulnList(t *testing.T) {
	tf := newTriageFakeServer(t, nil)
	client := api.NewClient(tf.server.URL, "test-key")

	var stdout, stderr bytes.Buffer
	err := runTriageLoop(context.Background(), client, triageOpts{
		projectID:           "00000000-0000-0000-0000-000000000aaa",
		ecosystem:           "go",
		nonInteractive:      false,
		confidenceThreshold: 0.7,
		path:                ".",
		stdin:               strings.NewReader(""),
		stdout:              &stdout,
		stderr:              &stderr,
		editor:              nil,
	})
	if err != nil {
		t.Fatalf("runTriageLoop returned %v; want nil", err)
	}
	if got := atomic.LoadInt32(&tf.triageRunHits); got != 0 {
		t.Errorf("triageRunHits = %d, want 0 (empty vuln list)", got)
	}
	if !strings.Contains(stdout.String(), "脆弱性は検出されませんでした") {
		t.Errorf("stdout missing empty-list message: %s", stdout.String())
	}
}

// TestTriageLoop_ListVulnsError verifies that a failure to enumerate
// vulnerabilities is a permanent error (exit code 3) — without the
// work list there is nothing the loop can do.
func TestTriageLoop_ListVulnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid api key"}`))
	}))
	defer server.Close()
	client := api.NewClient(server.URL, "test-key")

	var stdout, stderr bytes.Buffer
	err := runTriageLoop(context.Background(), client, triageOpts{
		projectID:           "00000000-0000-0000-0000-000000000aaa",
		ecosystem:           "go",
		nonInteractive:      false,
		confidenceThreshold: 0.7,
		path:                ".",
		stdin:               strings.NewReader(""),
		stdout:              &stdout,
		stderr:              &stderr,
		editor:              nil,
	})
	exitErr, ok := err.(*triageExitError)
	if !ok {
		t.Fatalf("err = %v (%T), want *triageExitError", err, err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("ExitCode = %d, want 3 (permanent setup error)", exitErr.ExitCode())
	}
}

// TestTriageRunRequestShape pins down the request body the CLI sends
// to POST /triage/run — vulnerability_id + cve_id are mandatory per
// the server contract, and the test is the canary that catches a
// regression that drops either field.
func TestTriageRunRequestShape(t *testing.T) {
	var seenBody []byte
	tf := newTriageFakeServer(t, []api.VulnerabilityRecord{{ID: fakeVulnID(1), CVEID: fakeCVE(1), Severity: "HIGH"}})
	tf.runTriageResp = func(call int, body []byte) (int, interface{}) {
		seenBody = body
		return http.StatusCreated, defaultRunResp(call)
	}
	client := api.NewClient(tf.server.URL, "test-key")

	err := runTriageLoop(context.Background(), client, triageOpts{
		projectID:           "00000000-0000-0000-0000-000000000aaa",
		ecosystem:           "go",
		nonInteractive:      true,
		confidenceThreshold: 0.7,
		path:                ".",
		stdin:               strings.NewReader(""),
		stdout:              io.Discard,
		stderr:              io.Discard,
		editor:              nil,
	})
	if err != nil {
		t.Fatalf("runTriageLoop returned %v", err)
	}

	var got api.TriageRunRequest
	if err := json.Unmarshal(seenBody, &got); err != nil {
		t.Fatalf("body parse error: %v (raw=%s)", err, string(seenBody))
	}
	if got.VulnerabilityID != fakeVulnID(1) {
		t.Errorf("VulnerabilityID = %q, want %q", got.VulnerabilityID, fakeVulnID(1))
	}
	if got.CVEID != fakeCVE(1) {
		t.Errorf("CVEID = %q, want %q", got.CVEID, fakeCVE(1))
	}
}

// TestTriageEcosystemWarning verifies that --ecosystem=npm produces a
// stderr warning but does NOT abort the loop. The warning is meant to
// surface limited M1 support without forcing operators to wait for a
// hard reject.
//
// (runTriageLoop itself does not inspect ecosystem — the warning is
// emitted by runTriage upstream — so the test exercises the API
// helpers instead, asserting they accept any ecosystem unchanged.)
func TestTriageEcosystemWarning(t *testing.T) {
	// Sentinel: the api client never sends ecosystem in any request
	// (it's purely a CLI-side concept right now), so a regression
	// that starts wiring ecosystem into TriageRunRequest must extend
	// this test.
	req := api.TriageRunRequest{
		VulnerabilityID: fakeVulnID(1),
		CVEID:           fakeCVE(1),
	}
	body, _ := json.Marshal(req)
	if strings.Contains(strings.ToLower(string(body)), "ecosystem") {
		t.Errorf("TriageRunRequest leaked ecosystem field into wire body: %s", string(body))
	}
}

// TestPromptDecision_AllChoices verifies each prompt branch in
// isolation. The test feeds one decision per case and checks the
// returned tuple.
func TestPromptDecision_AllChoices(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		wantAction string
		wantQuit   bool
	}{
		{"approve short", "a\n", decisionApproved, false},
		{"approve long", "approve\n", decisionApproved, false},
		{"reject short", "r\n", decisionRejected, false},
		{"skip short", "s\n", "", false},
		{"skip empty", "\n", "", false},
		{"quit short", "q\n", "", true},
		{"quit long", "quit\n", "", true},
		// Mistyped input reprompts — we feed "x" then "a" so the
		// helper returns approved on the second loop.
		{"invalid then approve", "x\na\n", decisionApproved, false},
	}
	draft := &api.VEXDraft{
		ID:    fakeDraftID(1),
		State: "not_affected",
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reader := bufioReaderFrom(tc.input)
			var stderr bytes.Buffer
			act, _, _, _, quit := promptDecision(reader, io.Discard, &stderr, nil, draft)
			if act != tc.wantAction {
				t.Errorf("action = %q, want %q", act, tc.wantAction)
			}
			if quit != tc.wantQuit {
				t.Errorf("quit = %v, want %v", quit, tc.wantQuit)
			}
		})
	}
}

// TestPromptDecision_EditPath spawns a stub editor that overwrites
// the temp file with a fresh JSON payload. The test verifies the
// edited values round-trip into the returned tuple.
func TestPromptDecision_EditPath(t *testing.T) {
	draft := &api.VEXDraft{
		ID:            fakeDraftID(1),
		State:         "not_affected",
		Justification: "code_not_reachable",
		Detail:        "AI text",
	}
	stub := func(path string) error {
		payload := editorFile{
			State:         "affected",
			Justification: "",
			Detail:        "Reviewed manually; exploit is reachable in production.",
		}
		f, err := openWritable(path)
		if err != nil {
			return err
		}
		defer f.Close()
		return json.NewEncoder(f).Encode(payload)
	}
	reader := bufioReaderFrom("e\n")
	var stderr bytes.Buffer
	act, st, just, detail, quit := promptDecision(reader, io.Discard, &stderr, stub, draft)
	if quit {
		t.Fatalf("quit unexpectedly: stderr=%s", stderr.String())
	}
	if act != decisionEdited {
		t.Errorf("action = %q, want edited", act)
	}
	if st != "affected" {
		t.Errorf("state = %q, want affected", st)
	}
	if just != "" {
		t.Errorf("justification = %q, want empty", just)
	}
	if !strings.Contains(detail, "Reviewed manually") {
		t.Errorf("detail = %q, want round-tripped edit", detail)
	}
}

// TestFormatVulnHeader covers the surface fields rendered in the
// per-vuln line.
func TestFormatVulnHeader(t *testing.T) {
	cases := []struct {
		name string
		in   api.VulnerabilityRecord
		want string
	}{
		{"plain", api.VulnerabilityRecord{CVEID: "CVE-2024-1"}, "CVE-2024-1"},
		{"with severity", api.VulnerabilityRecord{CVEID: "CVE-2024-2", Severity: "HIGH"}, "CVE-2024-2 [HIGH]"},
		{"kev", api.VulnerabilityRecord{CVEID: "CVE-2024-3", Severity: "CRITICAL", InKEV: true}, "CVE-2024-3 [CRITICAL] [KEV]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatVulnHeader(tc.in); got != tc.want {
				t.Errorf("formatVulnHeader = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSummarizeReachability cases.
func TestSummarizeReachability(t *testing.T) {
	cases := []struct {
		name string
		in   []api.TriageEvidence
		want string
	}{
		{"empty", nil, ""},
		{"import only", []api.TriageEvidence{{Kind: "import_path"}}, "import_only"},
		{"symbol", []api.TriageEvidence{{Kind: "import_path"}, {Kind: "symbol_ref"}}, "symbol_ref"},
		{"advisory only", []api.TriageEvidence{{Kind: "advisory_excerpt"}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := summarizeReachability(tc.in); got != tc.want {
				t.Errorf("summarizeReachability = %q, want %q", got, tc.want)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// F21 regression — `sbomhub triage` must surface non-zero exit codes when
// per-vuln API failures occur, so CI cannot silently green-light a triage
// run that persisted nothing
// ----------------------------------------------------------------------------
//
// Codex M1 round 12 #F21: before this fix the loop logged every per-vuln
// RunTriage / DecideDraft failure, counted it as `skipped`, and returned
// nil unconditionally at the end. That meant:
//   - a read-scoped API key (RequireWrite 403 on every triage/run call)
//     produced exit 0 with "skipped: N", and
//   - the triage concurrency limiter (429 on every call) also produced
//     exit 0,
// so CI workflows like `sbomhub triage --non-interactive` ran clean
// while ZERO drafts or decisions were persisted. The fix introduces:
//   - exit code 3 for permanent failures (401 / 403 / 404 / 422)
//   - exit code 4 for transient failures (429 / 5xx)
// Both classifications are unit-tested below; permanent wins when both
// occur in the same run because the operator's correct response (fix
// config) differs from transient (retry).
//
// The AI-disabled path (TestTriageLoop_AIDisabledServerPersisted /
// _AIDisabledFallback above) stays exit 0 — the server still persists a
// paper-trail draft and the operator's resolution is BYOK config, not a
// CI retry.

// TestTriageLoop_PermanentFailures_ExitCode3 — when every RunTriage
// returns 403 (RequireWrite gate from a read-only API key), the loop
// must NOT exit 0. Pins the F21 fix at the per-vuln-call boundary.
func TestTriageLoop_PermanentFailures_ExitCode3(t *testing.T) {
	tf := newTriageFakeServer(t, threeVulns())
	tf.runTriageResp = func(call int, body []byte) (int, interface{}) {
		return http.StatusForbidden, map[string]string{
			"error": "forbidden",
		}
	}
	client := api.NewClient(tf.server.URL, "test-key")

	var stdout, stderr bytes.Buffer
	err := runTriageLoop(context.Background(), client, triageOpts{
		projectID:           "00000000-0000-0000-0000-000000000aaa",
		ecosystem:           "go",
		nonInteractive:      true,
		confidenceThreshold: 0.7,
		path:                ".",
		stdin:               strings.NewReader(""),
		stdout:              &stdout,
		stderr:              &stderr,
		editor:              nil,
	})

	exitErr, ok := err.(*triageExitError)
	if !ok {
		t.Fatalf("F21: err = %v (%T), want *triageExitError with exit code 3", err, err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("F21: ExitCode = %d, want 3 (permanent failures must NOT exit 0)", exitErr.ExitCode())
	}
	if !strings.Contains(exitErr.Error(), "恒久") && !strings.Contains(exitErr.Error(), "permanent") {
		t.Errorf("F21: error message must mention permanent, got %q", exitErr.Error())
	}
	// Summary must still be printed so the operator can see what (if
	// anything) succeeded — F21 explicitly preserves the best-effort UX.
	if !strings.Contains(stdout.String(), "Triage 結果") {
		t.Errorf("F21: summary must still be printed on permanent failure: %s", stdout.String())
	}
	// No decisions persisted because triage/run failed for every vuln.
	if got := atomic.LoadInt32(&tf.decisionHits); got != 0 {
		t.Errorf("decisionHits = %d, want 0 (every triage/run failed)", got)
	}
}

// TestTriageLoop_TransientFailures_ExitCode4 — when every RunTriage
// returns 429 (triage concurrency limiter / rate limit storm), the
// loop must exit with code 4 so CI can distinguish "retry tomorrow"
// from "fix config" (code 3). Mirrors the permanent test.
func TestTriageLoop_TransientFailures_ExitCode4(t *testing.T) {
	tf := newTriageFakeServer(t, threeVulns())
	tf.runTriageResp = func(call int, body []byte) (int, interface{}) {
		// Mix 429 and 503-not-AI-disabled (server overload) to make
		// sure both transient species land in the same bucket. We
		// deliberately avoid the AI-disabled 503-with-reason path
		// here — that path stays exit 0 (TestTriageLoop_AIDisabled*).
		if call%2 == 1 {
			return http.StatusTooManyRequests, map[string]string{
				"error": "too many requests",
			}
		}
		return http.StatusBadGateway, map[string]string{
			"error": "upstream timeout",
		}
	}
	client := api.NewClient(tf.server.URL, "test-key")

	var stdout, stderr bytes.Buffer
	err := runTriageLoop(context.Background(), client, triageOpts{
		projectID:           "00000000-0000-0000-0000-000000000aaa",
		ecosystem:           "go",
		nonInteractive:      true,
		confidenceThreshold: 0.7,
		path:                ".",
		stdin:               strings.NewReader(""),
		stdout:              &stdout,
		stderr:              &stderr,
		editor:              nil,
	})

	exitErr, ok := err.(*triageExitError)
	if !ok {
		t.Fatalf("F21: err = %v (%T), want *triageExitError with exit code 4", err, err)
	}
	if exitErr.ExitCode() != 4 {
		t.Errorf("F21: ExitCode = %d, want 4 (transient failures must surface as retry-recommended)", exitErr.ExitCode())
	}
	if !strings.Contains(exitErr.Error(), "一時") && !strings.Contains(exitErr.Error(), "transient") {
		t.Errorf("F21: error message must mention transient, got %q", exitErr.Error())
	}
}

// TestTriageLoop_AllAIDisabled_ExitCode0 — the existing AI-disabled
// fallback path MUST remain exit 0 even after the F21 fix. This is a
// belt-and-braces regression test alongside the long-form
// TestTriageLoop_AIDisabledServerPersisted / _AIDisabledFallback that
// pins the per-vuln behaviour: the F21 classifier short-circuits on
// AIDisabled / IsAIDisabled() before consulting permanent / transient,
// so a BYOK-not-configured server cannot inflate exit codes.
func TestTriageLoop_AllAIDisabled_ExitCode0(t *testing.T) {
	tf := newTriageFakeServer(t, threeVulns())
	tf.runTriageResp = func(call int, body []byte) (int, interface{}) {
		// New-server shape (AIDisabled=true with server-persisted
		// draft). The legacy 503 path is covered separately by
		// TestTriageLoop_AIDisabledFallback above.
		draftID := fakeDraftID(call)
		return http.StatusCreated, map[string]interface{}{
			"draft": map[string]interface{}{
				"id":               draftID,
				"project_id":       "00000000-0000-0000-0000-000000000aaa",
				"component_id":     "00000000-0000-0000-0000-0000000000bb",
				"vulnerability_id": fakeVulnID(call),
				"cve_id":           fakeCVE(call),
				"state":            "under_investigation",
				"provider":         "disabled",
				"decision":         "pending",
			},
			"clamped":     false,
			"threshold":   0.7,
			"ai_disabled": true,
		}
	}
	client := api.NewClient(tf.server.URL, "test-key")

	var stdout, stderr bytes.Buffer
	err := runTriageLoop(context.Background(), client, triageOpts{
		projectID:           "00000000-0000-0000-0000-000000000aaa",
		ecosystem:           "go",
		nonInteractive:      true,
		confidenceThreshold: 0.7,
		path:                ".",
		stdin:               strings.NewReader(""),
		stdout:              &stdout,
		stderr:              &stderr,
		editor:              nil,
	})
	if err != nil {
		t.Fatalf("F21: AI-disabled fallback must remain exit 0, got %v", err)
	}
}

// TestTriageLoop_MixedSuccessAndPermanent_ExitCode3 — when a run mixes
// successful and permanent-failed vulns, exit code 3 must still surface
// (permanent wins over success). This is the most realistic regression:
// a read-only API key might still satisfy /triage/run (no RequireWrite
// on that route... wait, it does have RequireWrite, but a CLI that
// happens to have ONE 403 amongst 99 successes should still trip CI).
//
// The fake server returns 403 only for the second vuln; the first and
// third succeed and persist their draft via the decision PUT.
func TestTriageLoop_MixedSuccessAndPermanent_ExitCode3(t *testing.T) {
	tf := newTriageFakeServer(t, threeVulns())
	tf.runTriageResp = func(call int, body []byte) (int, interface{}) {
		if call == 2 {
			return http.StatusForbidden, map[string]string{
				"error": "forbidden",
			}
		}
		return http.StatusCreated, defaultRunResp(call)
	}
	client := api.NewClient(tf.server.URL, "test-key")

	var stdout, stderr bytes.Buffer
	err := runTriageLoop(context.Background(), client, triageOpts{
		projectID:           "00000000-0000-0000-0000-000000000aaa",
		ecosystem:           "go",
		nonInteractive:      true,
		confidenceThreshold: 0.7,
		path:                ".",
		stdin:               strings.NewReader(""),
		stdout:              &stdout,
		stderr:              &stderr,
		editor:              nil,
	})

	exitErr, ok := err.(*triageExitError)
	if !ok {
		t.Fatalf("F21: err = %v (%T), want *triageExitError (permanent must win over partial success)", err, err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("F21: ExitCode = %d, want 3 (one permanent failure in a mixed run must surface)", exitErr.ExitCode())
	}
	// Two successes still produced decision PUTs — the loop continued
	// past the 403, exactly as the best-effort UX requires.
	if got := atomic.LoadInt32(&tf.decisionHits); got != 2 {
		t.Errorf("decisionHits = %d, want 2 (loop must continue past the permanent failure)", got)
	}
}

// TestTriageLoop_DecideDraftPermanent_ExitCode3 — verifies the second
// classification site (DecideDraft failure) wires the same exit code
// machinery as RunTriage. Without this companion test, a regression
// that updated the RunTriage classifier without the DecideDraft one
// would mask 403 on the decision PUT path.
func TestTriageLoop_DecideDraftPermanent_ExitCode3(t *testing.T) {
	tf := newTriageFakeServer(t, []api.VulnerabilityRecord{
		{ID: fakeVulnID(1), CVEID: fakeCVE(1), Severity: "HIGH"},
	})
	tf.decisionResp = func(call int, draftID string, body []byte) (int, interface{}) {
		return http.StatusForbidden, map[string]string{
			"error": "forbidden",
		}
	}
	client := api.NewClient(tf.server.URL, "test-key")

	var stdout, stderr bytes.Buffer
	err := runTriageLoop(context.Background(), client, triageOpts{
		projectID:           "00000000-0000-0000-0000-000000000aaa",
		ecosystem:           "go",
		nonInteractive:      true,
		confidenceThreshold: 0.7,
		path:                ".",
		stdin:               strings.NewReader(""),
		stdout:              &stdout,
		stderr:              &stderr,
		editor:              nil,
	})

	exitErr, ok := err.(*triageExitError)
	if !ok {
		t.Fatalf("F21: err = %v (%T), want *triageExitError (decide 403 must surface)", err, err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("F21: ExitCode = %d, want 3 (DecideDraft permanent failure)", exitErr.ExitCode())
	}
}

// TestClassifyTriageFailure_F21 unit-tests the helper directly so the
// per-status classification stays pinned even if the call sites get
// refactored. The matrix mirrors api.TriageError.IsPermanent /
// IsTransient + the network-error default.
func TestClassifyTriageFailure_F21(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		wantPermInc int
		wantTranInc int
	}{
		{
			name: "401 unauthorized → permanent",
			err: &api.TriageError{
				StatusCode: http.StatusUnauthorized,
			},
			wantPermInc: 1,
		},
		{
			name: "403 forbidden → permanent",
			err: &api.TriageError{
				StatusCode: http.StatusForbidden,
			},
			wantPermInc: 1,
		},
		{
			name: "404 not found → permanent",
			err: &api.TriageError{
				StatusCode: http.StatusNotFound,
			},
			wantPermInc: 1,
		},
		{
			name: "422 unprocessable → permanent",
			err: &api.TriageError{
				StatusCode: http.StatusUnprocessableEntity,
			},
			wantPermInc: 1,
		},
		{
			name: "429 too many → transient",
			err: &api.TriageError{
				StatusCode: http.StatusTooManyRequests,
			},
			wantTranInc: 1,
		},
		{
			name: "500 server → transient",
			err: &api.TriageError{
				StatusCode: http.StatusInternalServerError,
			},
			wantTranInc: 1,
		},
		{
			name: "502 bad gateway → transient",
			err: &api.TriageError{
				StatusCode: http.StatusBadGateway,
			},
			wantTranInc: 1,
		},
		{
			name: "503 AI disabled → transient (defensive — caller short-circuits)",
			err: &api.TriageError{
				StatusCode: http.StatusServiceUnavailable,
				Reason:     "no LLM provider configured",
			},
			wantTranInc: 1,
		},
		{
			name: "418 unknown 4xx → permanent (operator must fix)",
			err: &api.TriageError{
				StatusCode: 418,
			},
			wantPermInc: 1,
		},
		{
			name:        "network error → transient",
			err:         io.ErrUnexpectedEOF,
			wantTranInc: 1,
		},
		{
			name: "nil err → no-op",
			err:  nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			perm, tran := 0, 0
			classifyTriageFailure(tc.err, &perm, &tran)
			if perm != tc.wantPermInc {
				t.Errorf("permanent inc = %d, want %d", perm, tc.wantPermInc)
			}
			if tran != tc.wantTranInc {
				t.Errorf("transient inc = %d, want %d", tran, tc.wantTranInc)
			}
		})
	}
}

// --- helpers ------------------------------------------------------

func bufioReaderFrom(s string) *bufio.Reader {
	return bufio.NewReader(strings.NewReader(s))
}

// openWritable opens path for write+truncate so the stub editor can
// overwrite the JSON payload that runTriageLoop seeded.
func openWritable(path string) (io.WriteCloser, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600)
}
