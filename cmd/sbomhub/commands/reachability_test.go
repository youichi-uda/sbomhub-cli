package commands

// Unit tests for `sbomhub reachability` — drives runReachabilityAnalysis
// against a fake httptest server and a REAL vendored analyzer running on a
// testdata fixture (no analyzer mock). Asserts:
//
//   1. targets fetched from GET /reachability/targets are analyzed and the
//      verdicts POSTed to /reachability with the exact frozen contract JSON
//      shape (field names + status enum + values),
//   2. a non-2xx upload surfaces as an error (no partial-success claim),
//   3. a target with an empty purl is skipped (no derivable module) and
//      reported on stderr,
//   4. --cve narrows the analyzed set.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/youichi-uda/sbomhub-cli/internal/api"
	"github.com/youichi-uda/sbomhub-cli/internal/reachability"
)

// reachFixturePath is a source tree whose go.mod requires
// example.test/vulnpkg. Analyzed with no vulnerable symbols, the module
// example.test/vulnpkg → import_only; any absent module → not_present.
const reachFixturePath = "testdata/reach_fixture"

const reachTestProject = "00000000-0000-0000-0000-000000000aaa"

type reachFakeServer struct {
	t          *testing.T
	server     *httptest.Server
	targets    []api.ReachabilityTarget
	uploadCode int // status returned by POST /reachability (default 201)

	mu             sync.Mutex
	targetsGetHits int
	lastTargetsQ   string // raw ?ecosystem= value seen on the targets GET
	uploadHits     int
	lastPostBody   []byte
}

func newReachFakeServer(t *testing.T, targets []api.ReachabilityTarget) *reachFakeServer {
	t.Helper()
	rf := &reachFakeServer{t: t, targets: targets, uploadCode: http.StatusCreated}
	rf.server = httptest.NewServer(http.HandlerFunc(rf.handle))
	t.Cleanup(rf.server.Close)
	return rf
}

func (rf *reachFakeServer) handle(w http.ResponseWriter, r *http.Request) {
	if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
		rf.t.Errorf("Authorization = %q, want Bearer test-key", got)
	}
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/reachability/targets"):
		rf.mu.Lock()
		rf.targetsGetHits++
		rf.lastTargetsQ = r.URL.Query().Get("ecosystem")
		rf.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"targets": rf.targets})

	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/reachability"):
		body, _ := io.ReadAll(r.Body)
		rf.mu.Lock()
		rf.uploadHits++
		rf.lastPostBody = body
		code := rf.uploadCode
		rf.mu.Unlock()
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			rf.t.Errorf("POST Content-Type = %q, want application/json", ct)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		if code >= 400 {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: read-only api key"})
		}

	default:
		rf.t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

// TestReachability_HappyPath_UploadsFrozenContract runs the real analyzer
// over the fixture and asserts the POST body matches the frozen contract.
func TestReachability_HappyPath_UploadsFrozenContract(t *testing.T) {
	targets := []api.ReachabilityTarget{
		{
			CVEID:            "CVE-2024-0001",
			ComponentID:      "aaaaaaaa-0000-0000-0000-000000000001",
			Purl:             "pkg:golang/example.test/vulnpkg@v1.0.0",
			ComponentName:    "vulnpkg",
			ComponentVersion: "v1.0.0",
			Ecosystem:        "go",
		},
		{
			CVEID:            "CVE-2024-0002",
			ComponentID:      "aaaaaaaa-0000-0000-0000-000000000002",
			Purl:             "pkg:golang/example.test/absent@v2.0.0",
			ComponentName:    "absent",
			ComponentVersion: "v2.0.0",
			Ecosystem:        "go",
		},
	}
	rf := newReachFakeServer(t, targets)
	client := api.NewClient(rf.server.URL, "test-key")

	var stdout, stderr bytes.Buffer
	err := runReachabilityAnalysis(context.Background(), client, reachOpts{
		projectID: reachTestProject,
		ecosystem: "go",
		path:      reachFixturePath,
		analyzer:  &reachability.GoAnalyzer{},
		stdout:    &stdout,
		stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("runReachabilityAnalysis returned error: %v (stderr=%s)", err, stderr.String())
	}

	// The targets GET must have forwarded ?ecosystem=go.
	if rf.lastTargetsQ != "go" {
		t.Errorf("targets ?ecosystem = %q, want go", rf.lastTargetsQ)
	}
	if rf.uploadHits != 1 {
		t.Fatalf("uploadHits = %d, want 1", rf.uploadHits)
	}

	// The body envelope must be {"results":[...]}.
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(rf.lastPostBody, &envelope); err != nil {
		t.Fatalf("POST body not JSON object: %v (body=%s)", err, rf.lastPostBody)
	}
	rawResults, ok := envelope["results"]
	if !ok {
		t.Fatalf("POST body missing top-level \"results\" key: %s", rf.lastPostBody)
	}

	// Field-name check against the frozen contract on the first row.
	var rowMaps []map[string]json.RawMessage
	if err := json.Unmarshal(rawResults, &rowMaps); err != nil {
		t.Fatalf("results not an array of objects: %v", err)
	}
	if len(rowMaps) != 2 {
		t.Fatalf("results len = %d, want 2", len(rowMaps))
	}
	for _, field := range []string{"component_id", "cve_id", "ecosystem", "status", "confidence", "analyzer_version", "analyzed_at"} {
		if _, present := rowMaps[0][field]; !present {
			t.Errorf("result row missing frozen-contract field %q; got keys %v", field, keysOf(rowMaps[0]))
		}
	}

	// Value check via the typed struct, keyed by CVE (order-independent).
	var results []api.ReachabilityUploadResult
	if err := json.Unmarshal(rawResults, &results); err != nil {
		t.Fatalf("decode results: %v", err)
	}
	byCVE := map[string]api.ReachabilityUploadResult{}
	for _, r := range results {
		byCVE[r.CVEID] = r
	}

	imp, ok := byCVE["CVE-2024-0001"]
	if !ok {
		t.Fatal("missing verdict for CVE-2024-0001")
	}
	if imp.ComponentID != "aaaaaaaa-0000-0000-0000-000000000001" {
		t.Errorf("component_id = %q, want aaaaaaaa-...0001", imp.ComponentID)
	}
	if imp.Ecosystem != "go" {
		t.Errorf("ecosystem = %q, want go (forwarded from target)", imp.Ecosystem)
	}
	if imp.Status != string(reachability.StatusImportOnly) {
		t.Errorf("status = %q, want import_only", imp.Status)
	}
	if imp.Confidence != 0.60 {
		t.Errorf("confidence = %v, want 0.60", imp.Confidence)
	}
	if imp.AnalyzerVersion != "go_analyzer/v1" {
		t.Errorf("analyzer_version = %q, want go_analyzer/v1", imp.AnalyzerVersion)
	}
	if imp.AnalyzedAt.IsZero() {
		t.Error("analyzed_at is zero, want a populated timestamp")
	}
	if len(imp.Evidence) == 0 {
		t.Error("import_only verdict should carry evidence")
	}

	notp, ok := byCVE["CVE-2024-0002"]
	if !ok {
		t.Fatal("missing verdict for CVE-2024-0002")
	}
	if notp.Status != string(reachability.StatusNotPresent) {
		t.Errorf("status = %q, want not_present", notp.Status)
	}
	if notp.Confidence != 0.90 {
		t.Errorf("confidence = %v, want 0.90", notp.Confidence)
	}

	if !strings.Contains(stdout.String(), "uploaded") {
		t.Errorf("summary missing 'uploaded' line: %s", stdout.String())
	}
}

// TestReachability_UploadError_Surfaces asserts a non-2xx upload becomes
// an error rather than a silent success.
func TestReachability_UploadError_Surfaces(t *testing.T) {
	targets := []api.ReachabilityTarget{
		{
			CVEID:       "CVE-2024-0001",
			ComponentID: "aaaaaaaa-0000-0000-0000-000000000001",
			Purl:        "pkg:golang/example.test/vulnpkg@v1.0.0",
			Ecosystem:   "go",
		},
	}
	rf := newReachFakeServer(t, targets)
	rf.uploadCode = http.StatusForbidden
	client := api.NewClient(rf.server.URL, "test-key")

	var stdout, stderr bytes.Buffer
	err := runReachabilityAnalysis(context.Background(), client, reachOpts{
		projectID: reachTestProject,
		ecosystem: "go",
		path:      reachFixturePath,
		analyzer:  &reachability.GoAnalyzer{},
		stdout:    &stdout,
		stderr:    &stderr,
	})
	if err == nil {
		t.Fatal("expected error on 403 upload, got nil")
	}
	var apiErr *api.ReachabilityError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want a wrapped *api.ReachabilityError", err)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403", apiErr.StatusCode)
	}
	if !apiErr.IsPermanent() {
		t.Error("403 should classify as permanent")
	}
}

// TestReachability_EmptyPurl_Skipped asserts a target with no purl is
// skipped (no derivable module) and reported on stderr, while the one with
// a purl is still uploaded.
func TestReachability_EmptyPurl_Skipped(t *testing.T) {
	targets := []api.ReachabilityTarget{
		{CVEID: "CVE-2024-0001", ComponentID: "c1", Purl: "", ComponentName: "nopurl", Ecosystem: ""},
		{CVEID: "CVE-2024-0002", ComponentID: "c2", Purl: "pkg:golang/example.test/vulnpkg@v1.0.0", Ecosystem: "go"},
	}
	rf := newReachFakeServer(t, targets)
	client := api.NewClient(rf.server.URL, "test-key")

	var stdout, stderr bytes.Buffer
	err := runReachabilityAnalysis(context.Background(), client, reachOpts{
		projectID: reachTestProject,
		ecosystem: "go",
		path:      reachFixturePath,
		analyzer:  &reachability.GoAnalyzer{},
		stdout:    &stdout,
		stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("runReachabilityAnalysis error: %v", err)
	}
	if !strings.Contains(stderr.String(), "purl") {
		t.Errorf("stderr should report the skipped empty-purl target: %s", stderr.String())
	}
	var envelope struct {
		Results []api.ReachabilityUploadResult `json:"results"`
	}
	if err := json.Unmarshal(rf.lastPostBody, &envelope); err != nil {
		t.Fatalf("decode POST body: %v", err)
	}
	if len(envelope.Results) != 1 {
		t.Fatalf("results len = %d, want 1 (empty-purl target skipped)", len(envelope.Results))
	}
	if envelope.Results[0].CVEID != "CVE-2024-0002" {
		t.Errorf("uploaded CVE = %q, want CVE-2024-0002", envelope.Results[0].CVEID)
	}
}

// TestReachability_CVEScope asserts --cve narrows the analyzed set.
func TestReachability_CVEScope(t *testing.T) {
	targets := []api.ReachabilityTarget{
		{CVEID: "CVE-2024-0001", ComponentID: "c1", Purl: "pkg:golang/example.test/vulnpkg@v1.0.0", Ecosystem: "go"},
		{CVEID: "CVE-2024-0002", ComponentID: "c2", Purl: "pkg:golang/example.test/absent@v2.0.0", Ecosystem: "go"},
	}
	rf := newReachFakeServer(t, targets)
	client := api.NewClient(rf.server.URL, "test-key")

	var stdout, stderr bytes.Buffer
	err := runReachabilityAnalysis(context.Background(), client, reachOpts{
		projectID: reachTestProject,
		ecosystem: "go",
		cve:       "CVE-2024-0001",
		path:      reachFixturePath,
		analyzer:  &reachability.GoAnalyzer{},
		stdout:    &stdout,
		stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("runReachabilityAnalysis error: %v", err)
	}
	var envelope struct {
		Results []api.ReachabilityUploadResult `json:"results"`
	}
	if err := json.Unmarshal(rf.lastPostBody, &envelope); err != nil {
		t.Fatalf("decode POST body: %v", err)
	}
	if len(envelope.Results) != 1 {
		t.Fatalf("results len = %d, want 1 (scoped to one CVE)", len(envelope.Results))
	}
	if envelope.Results[0].CVEID != "CVE-2024-0001" {
		t.Errorf("scoped CVE = %q, want CVE-2024-0001", envelope.Results[0].CVEID)
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
