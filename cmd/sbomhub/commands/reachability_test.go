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
//   4. --cve narrows the analyzed set,
//   5. (M43, issue #168) targets' vuln_funcs are forwarded to the
//      analyzer's VulnerableSymbols — unioned across duplicate
//      (component, cve) rows, nil when absent/blank (graceful degrade
//      against pre-M43 servers),
//   6. (M43 Phase D review) malformed vuln_funcs shapes — anything the
//      vendored analyzer's parseSymbolSelectors would reject with an
//      error — are dropped CLI-side so one bad selector cannot downgrade
//      the whole work item to the degraded import_only + analyzer_error
//      path; legitimate symbols in the same list survive,
//   7. (M43 Phase D round 2 review) the per-work-item symbol union is
//      capped at maxVulnFuncsPerItem (= server maxVulnFuncsPerCVE = 200):
//      elements past the cap are dropped first-wins, exactly 200 is
//      untouched, and the cap holds across the union of duplicate
//      (component, cve) rows — so a drift/hostile server publishing
//      thousands of well-formed selectors cannot bloat the AST walk,
//   8. (M44 Wave 4, F472) npm targets — plain and "@scope/name" purls —
//      dispatch to the NpmAnalyzer (go rows keep the GoAnalyzer, rows in
//      ecosystems with no analyzer are skipped + counted), the default
//      --ecosystem=all fetches unfiltered while explicit go/npm forwards
//      the server-side filter, the vuln_funcs shape filter dispatches on
//      the row's ecosystem (npm bare exports / "$" survive; lockstep with
//      the server's isNpmVulnFuncSelector), and a symbol-carrying npm
//      target reaches a symbol-level `reachable` verdict end-to-end
//      through the REAL NpmAnalyzer on a real fixture tree.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
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
	rawTargets []byte // when non-nil, served verbatim as the targets GET body (field-presence control)
	uploadCode int    // status returned by POST /reachability (default 201)

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
		raw := rf.rawTargets
		rf.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if raw != nil {
			_, _ = w.Write(raw)
			return
		}
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
		analyzers: map[string]reachAnalyzer{"go": &reachability.GoAnalyzer{}},
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
		analyzers: map[string]reachAnalyzer{"go": &reachability.GoAnalyzer{}},
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
		analyzers: map[string]reachAnalyzer{"go": &reachability.GoAnalyzer{}},
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
		analyzers: map[string]reachAnalyzer{"go": &reachability.GoAnalyzer{}},
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

// recordingAnalyzer wraps a REAL vendored analyzer (source/AST stages
// disabled in the default constructors — offline-safe, dependency-graph
// stage only) and records every ReachabilityInput it receives, so tests
// can assert exactly what the command forwarded (M43: targets' vuln_funcs
// → VulnerableSymbols; M44: per-ecosystem dispatch) without mocking
// verdicts or the upload path.
type recordingAnalyzer struct {
	mu     sync.Mutex
	inputs []reachability.ReachabilityInput
	real   reachAnalyzer
}

func newRecordingAnalyzer() *recordingAnalyzer {
	return &recordingAnalyzer{real: &reachability.GoAnalyzer{SkipPackagesLoad: true}}
}

func newRecordingNpmAnalyzer() *recordingAnalyzer {
	return &recordingAnalyzer{real: &reachability.NpmAnalyzer{SkipSourceScan: true}}
}

func (ra *recordingAnalyzer) Analyze(ctx context.Context, projectPath string, input reachability.ReachabilityInput) (*reachability.ReachabilityResult, error) {
	ra.mu.Lock()
	ra.inputs = append(ra.inputs, input)
	ra.mu.Unlock()
	return ra.real.Analyze(ctx, projectPath, input)
}

func (ra *recordingAnalyzer) inputByCVE(cve string) (reachability.ReachabilityInput, bool) {
	ra.mu.Lock()
	defer ra.mu.Unlock()
	for _, in := range ra.inputs {
		if in.AdvisoryID == cve {
			return in, true
		}
	}
	return reachability.ReachabilityInput{}, false
}

// TestReachability_VulnFuncs_ForwardedAndUnioned — M43 (issue #168):
//
//   - a target's vuln_funcs reach the analyzer input verbatim,
//   - duplicate (component, cve) rows union their vuln_funcs with
//     order-preserving dedupe,
//   - blank-only lists collapse to nil,
//   - a row without the vuln_funcs field (exactly what a pre-M43 server
//     sends — hence the raw JSON body) yields nil VulnerableSymbols, i.e.
//     the analyzer stays at stage 1 / import_only (graceful degrade).
func TestReachability_VulnFuncs_ForwardedAndUnioned(t *testing.T) {
	rf := newReachFakeServer(t, nil)
	rf.rawTargets = []byte(`{"targets":[
		{"cve_id":"CVE-2024-0001","component_id":"c1","purl":"pkg:golang/example.test/vulnpkg@v1.0.0","ecosystem":"go","vuln_funcs":["vulnpkg.Parse","vulnpkg.Decoder.Decode"]},
		{"cve_id":"CVE-2024-0001","component_id":"c1","purl":"pkg:golang/example.test/vulnpkg@v1.0.0","ecosystem":"go","vuln_funcs":["vulnpkg.Parse","vulnpkg.Render"]},
		{"cve_id":"CVE-2024-0002","component_id":"c2","purl":"pkg:golang/example.test/vulnpkg@v1.0.0","ecosystem":"go","vuln_funcs":[""," "]},
		{"cve_id":"CVE-2024-0003","component_id":"c3","purl":"pkg:golang/example.test/vulnpkg@v1.0.0","ecosystem":"go"}
	]}`)
	client := api.NewClient(rf.server.URL, "test-key")
	rec := newRecordingAnalyzer()

	var stdout, stderr bytes.Buffer
	err := runReachabilityAnalysis(context.Background(), client, reachOpts{
		projectID: reachTestProject,
		ecosystem: "go",
		path:      reachFixturePath,
		analyzers: map[string]reachAnalyzer{"go": rec},
		stdout:    &stdout,
		stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("runReachabilityAnalysis error: %v (stderr=%s)", err, stderr.String())
	}

	if got := len(rec.inputs); got != 3 {
		t.Fatalf("analyzer invocations = %d, want 3 (duplicate (component,cve) rows must merge)", got)
	}

	// Union across the two CVE-2024-0001 rows, first-seen order, deduped.
	in1, ok := rec.inputByCVE("CVE-2024-0001")
	if !ok {
		t.Fatal("no analyzer input recorded for CVE-2024-0001")
	}
	wantSyms := []string{"vulnpkg.Parse", "vulnpkg.Decoder.Decode", "vulnpkg.Render"}
	if !reflect.DeepEqual(in1.VulnerableSymbols, wantSyms) {
		t.Errorf("VulnerableSymbols = %#v, want %#v (union, order-preserving dedupe)", in1.VulnerableSymbols, wantSyms)
	}

	// Blank-only vuln_funcs collapse to nil (analyzer stays at stage 1).
	in2, ok := rec.inputByCVE("CVE-2024-0002")
	if !ok {
		t.Fatal("no analyzer input recorded for CVE-2024-0002")
	}
	if in2.VulnerableSymbols != nil {
		t.Errorf("VulnerableSymbols = %#v, want nil for blank-only vuln_funcs", in2.VulnerableSymbols)
	}

	// Field absent (pre-M43 server) → nil → import_only granularity.
	in3, ok := rec.inputByCVE("CVE-2024-0003")
	if !ok {
		t.Fatal("no analyzer input recorded for CVE-2024-0003")
	}
	if in3.VulnerableSymbols != nil {
		t.Errorf("VulnerableSymbols = %#v, want nil when vuln_funcs is absent (old server)", in3.VulnerableSymbols)
	}

	// The upload path is unchanged: one POST carrying all three verdicts.
	if rf.uploadHits != 1 {
		t.Fatalf("uploadHits = %d, want 1", rf.uploadHits)
	}
	var envelope struct {
		Results []api.ReachabilityUploadResult `json:"results"`
	}
	if err := json.Unmarshal(rf.lastPostBody, &envelope); err != nil {
		t.Fatalf("decode POST body: %v", err)
	}
	if len(envelope.Results) != 3 {
		t.Fatalf("results len = %d, want 3", len(envelope.Results))
	}
}

// TestReachability_VulnFuncs_MalformedShapesDropped — M43 Phase D review:
// a targets response mixing malformed selectors (bare name, 4 dot-parts,
// non-identifier characters, interior space, blank) with legitimate ones
// must forward ONLY the legitimate shapes to the analyzer's
// VulnerableSymbols (first-seen order). Without the CLI-side shape filter
// the malformed entries reach the vendored analyzer verbatim and its
// parseSymbolSelectors fails the WHOLE symbol walk — losing the
// legitimate symbols alongside the bad one.
//
// Uses the recording analyzer (SkipPackagesLoad — offline-safe) because
// the surviving legitimate selectors would otherwise trigger a real
// packages.Load.
func TestReachability_VulnFuncs_MalformedShapesDropped(t *testing.T) {
	rf := newReachFakeServer(t, nil)
	rf.rawTargets = []byte(`{"targets":[
		{"cve_id":"CVE-2024-0001","component_id":"c1","purl":"pkg:golang/example.test/vulnpkg@v1.0.0","ecosystem":"go","vuln_funcs":["Foo","yaml.Unmarshal","a.b.c.d","Pkg.Type.Method","Bar.baz()","_pkg.F1","pkg name.Func","","パッケージ.解析"]}
	]}`)
	client := api.NewClient(rf.server.URL, "test-key")
	rec := newRecordingAnalyzer()

	var stdout, stderr bytes.Buffer
	err := runReachabilityAnalysis(context.Background(), client, reachOpts{
		projectID: reachTestProject,
		ecosystem: "go",
		path:      reachFixturePath,
		analyzers: map[string]reachAnalyzer{"go": rec},
		stdout:    &stdout,
		stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("runReachabilityAnalysis error: %v (stderr=%s)", err, stderr.String())
	}

	in, ok := rec.inputByCVE("CVE-2024-0001")
	if !ok {
		t.Fatal("no analyzer input recorded for CVE-2024-0001")
	}
	// Legitimate shapes only: Pkg.Func, Pkg.Type.Method, underscore-led
	// identifier, unicode-letter identifiers. Malformed shapes (bare name,
	// 4 dot-parts, "()" suffix, interior space, blank) must be gone.
	wantSyms := []string{"yaml.Unmarshal", "Pkg.Type.Method", "_pkg.F1", "パッケージ.解析"}
	if !reflect.DeepEqual(in.VulnerableSymbols, wantSyms) {
		t.Errorf("VulnerableSymbols = %#v, want %#v (malformed shapes dropped, legit survive)", in.VulnerableSymbols, wantSyms)
	}

	if rf.uploadHits != 1 {
		t.Fatalf("uploadHits = %d, want 1", rf.uploadHits)
	}
}

// TestReachability_VulnFuncs_AllMalformed_NoAnalyzerError — M43 Phase D
// review, driven through the REAL analyzer (SkipPackagesLoad=false): when
// every published vuln_func is malformed, the CLI must drop them all
// (collapsing to nil = stage 1 only) instead of forwarding them into the
// analyzer, where parseSymbolSelectors would fail the symbol walk and
// downgrade the verdict to the degraded import_only path (confidence
// 0.50 + "symbol AST walk failed: invalid symbol selector ..."
// analyzer_error evidence).
//
// Offline-safe in both states: pre-fix the analyzer errors in
// parseSymbolSelectors BEFORE packages.Load; post-fix the nil symbol list
// stops the analyzer at stage 1, so packages.Load never runs.
func TestReachability_VulnFuncs_AllMalformed_NoAnalyzerError(t *testing.T) {
	rf := newReachFakeServer(t, nil)
	rf.rawTargets = []byte(`{"targets":[
		{"cve_id":"CVE-2024-0001","component_id":"c1","purl":"pkg:golang/example.test/vulnpkg@v1.0.0","ecosystem":"go","vuln_funcs":["Foo","a.b.c.d","Bar.baz()","pkg name.Func",""]}
	]}`)
	client := api.NewClient(rf.server.URL, "test-key")
	// Real analyzer with the symbol walk ENABLED — this is the path the
	// finding is about.
	rec := &recordingAnalyzer{real: &reachability.GoAnalyzer{}}

	var stdout, stderr bytes.Buffer
	err := runReachabilityAnalysis(context.Background(), client, reachOpts{
		projectID: reachTestProject,
		ecosystem: "go",
		path:      reachFixturePath,
		analyzers: map[string]reachAnalyzer{"go": rec},
		stdout:    &stdout,
		stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("runReachabilityAnalysis error: %v (stderr=%s)", err, stderr.String())
	}

	// All-malformed must collapse to nil (stage 1 only), exactly like the
	// blank-only / absent vuln_funcs cases.
	in, ok := rec.inputByCVE("CVE-2024-0001")
	if !ok {
		t.Fatal("no analyzer input recorded for CVE-2024-0001")
	}
	if in.VulnerableSymbols != nil {
		t.Errorf("VulnerableSymbols = %#v, want nil (all-malformed vuln_funcs dropped)", in.VulnerableSymbols)
	}

	var envelope struct {
		Results []api.ReachabilityUploadResult `json:"results"`
	}
	if err := json.Unmarshal(rf.lastPostBody, &envelope); err != nil {
		t.Fatalf("decode POST body: %v", err)
	}
	if len(envelope.Results) != 1 {
		t.Fatalf("results len = %d, want 1", len(envelope.Results))
	}
	verdict := envelope.Results[0]
	if verdict.Status != string(reachability.StatusImportOnly) {
		t.Errorf("status = %q, want import_only", verdict.Status)
	}
	// 0.60 = clean import_only; 0.50 is the degraded symbol-walk-failed
	// path the malformed selectors would trigger without the filter.
	if verdict.Confidence != 0.60 {
		t.Errorf("confidence = %v, want 0.60 (clean import_only, not the 0.50 degraded walk-failed path)", verdict.Confidence)
	}
	evidence := string(verdict.Evidence)
	if strings.Contains(evidence, "invalid symbol selector") || strings.Contains(evidence, "symbol AST walk failed") {
		t.Errorf("evidence carries a symbol-walk failure — malformed selectors reached the analyzer: %s", evidence)
	}
}

// TestReachability_VulnFuncs_CappedPerWorkItem — M43 Phase D round 2
// review: the CLI must mirror the server's serving-edge cap
// (maxVulnFuncsPerCVE = 200) on the per-work-item symbol union, so a
// drifted / hostile / non-conforming server publishing thousands of
// well-formed selectors cannot inflate the analyzer's AST symbol walk or
// the merge itself. Three work items pin the semantics:
//
//   - 300 well-formed selectors on one row → exactly the first 200 reach
//     the analyzer (order preserved, first wins, tail dropped),
//   - exactly 200 on one row → untouched (boundary),
//   - duplicate (component, cve) rows unioning 150 + 100 (with one
//     cross-row duplicate that must not consume cap budget) → the union
//     is capped at 200: all 150 from the first row + the first 50 new
//     symbols from the second.
//
// Uses the recording analyzer (SkipPackagesLoad — offline-safe) so the
// forwarded VulnerableSymbols can be asserted verbatim.
func TestReachability_VulnFuncs_CappedPerWorkItem(t *testing.T) {
	mkSyms := func(prefix string, n int) []string {
		syms := make([]string, n)
		for i := range syms {
			syms[i] = fmt.Sprintf("vulnpkg.%s%03d", prefix, i)
		}
		return syms
	}

	over := mkSyms("Over", 300)   // > cap: tail must be dropped
	exact := mkSyms("Exact", 200) // == cap: must be untouched
	unionA := mkSyms("UnionA", 150)
	// Second row for the same (component, cve): leads with a duplicate of
	// the first row's first symbol (must dedupe, not consume cap budget),
	// then 100 fresh symbols of which only the first 50 fit under the cap.
	unionB := append([]string{unionA[0]}, mkSyms("UnionB", 100)...)

	const purl = "pkg:golang/example.test/vulnpkg@v1.0.0"
	targets := []api.ReachabilityTarget{
		{CVEID: "CVE-2024-0001", ComponentID: "c1", Purl: purl, Ecosystem: "go", VulnFuncs: over},
		{CVEID: "CVE-2024-0002", ComponentID: "c2", Purl: purl, Ecosystem: "go", VulnFuncs: exact},
		{CVEID: "CVE-2024-0003", ComponentID: "c3", Purl: purl, Ecosystem: "go", VulnFuncs: unionA},
		{CVEID: "CVE-2024-0003", ComponentID: "c3", Purl: purl, Ecosystem: "go", VulnFuncs: unionB},
	}
	rf := newReachFakeServer(t, targets)
	client := api.NewClient(rf.server.URL, "test-key")
	rec := newRecordingAnalyzer()

	var stdout, stderr bytes.Buffer
	err := runReachabilityAnalysis(context.Background(), client, reachOpts{
		projectID: reachTestProject,
		ecosystem: "go",
		path:      reachFixturePath,
		analyzers: map[string]reachAnalyzer{"go": rec},
		stdout:    &stdout,
		stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("runReachabilityAnalysis error: %v (stderr=%s)", err, stderr.String())
	}

	if got := len(rec.inputs); got != 3 {
		t.Fatalf("analyzer invocations = %d, want 3", got)
	}

	// Over cap: exactly the first 200, in published order (first wins).
	in1, ok := rec.inputByCVE("CVE-2024-0001")
	if !ok {
		t.Fatal("no analyzer input recorded for CVE-2024-0001")
	}
	if got := len(in1.VulnerableSymbols); got != maxVulnFuncsPerItem {
		t.Errorf("over-cap VulnerableSymbols len = %d, want %d (cap)", got, maxVulnFuncsPerItem)
	}
	if !reflect.DeepEqual(in1.VulnerableSymbols, over[:200]) {
		t.Errorf("over-cap VulnerableSymbols != first 200 published symbols (order-preserving, first wins)")
	}

	// Boundary: exactly 200 survives untouched.
	in2, ok := rec.inputByCVE("CVE-2024-0002")
	if !ok {
		t.Fatal("no analyzer input recorded for CVE-2024-0002")
	}
	if !reflect.DeepEqual(in2.VulnerableSymbols, exact) {
		t.Errorf("exactly-at-cap VulnerableSymbols mutated: len = %d, want all 200 untouched", len(in2.VulnerableSymbols))
	}

	// Union across duplicate rows: cap applies to the merged total. The
	// cross-row duplicate is deduped without consuming cap budget, so the
	// first 50 fresh UnionB symbols still fit.
	in3, ok := rec.inputByCVE("CVE-2024-0003")
	if !ok {
		t.Fatal("no analyzer input recorded for CVE-2024-0003")
	}
	wantUnion := append(append([]string{}, unionA...), mkSyms("UnionB", 100)[:50]...)
	if got := len(in3.VulnerableSymbols); got != maxVulnFuncsPerItem {
		t.Errorf("unioned VulnerableSymbols len = %d, want %d (cap across merged rows)", got, maxVulnFuncsPerItem)
	}
	if !reflect.DeepEqual(in3.VulnerableSymbols, wantUnion) {
		t.Errorf("unioned VulnerableSymbols != first row's 150 + first 50 fresh symbols of second row")
	}

	// Upload path unchanged: one POST carrying all three verdicts.
	if rf.uploadHits != 1 {
		t.Fatalf("uploadHits = %d, want 1", rf.uploadHits)
	}
	var envelope struct {
		Results []api.ReachabilityUploadResult `json:"results"`
	}
	if err := json.Unmarshal(rf.lastPostBody, &envelope); err != nil {
		t.Fatalf("decode POST body: %v", err)
	}
	if len(envelope.Results) != 3 {
		t.Fatalf("results len = %d, want 3", len(envelope.Results))
	}
}

// TestMergeVulnFuncs_WhitespaceVariantDedupes pins the M43 Phase D R9
// finding 3 fix: mergeVulnFuncs validates the TrimSpace'd selector but used
// to append/dedupe the RAW string, so whitespace variants of the same
// selector (" yaml.Unmarshal " vs "yaml.Unmarshal") slipped past dedupe,
// consumed cap budget, and reached the analyzer un-trimmed. Both append and
// dedupe must operate on the trimmed form.
func TestMergeVulnFuncs_WhitespaceVariantDedupes(t *testing.T) {
	got := mergeVulnFuncs(nil, []string{"yaml.Unmarshal", " yaml.Unmarshal "}, "go")
	if len(got) != 1 || got[0] != "yaml.Unmarshal" {
		t.Fatalf("mergeVulnFuncs = %#v, want exactly [yaml.Unmarshal] (whitespace variant must dedupe)", got)
	}
	// Across calls too (duplicate (component, cve) rows merge into the same
	// dst): an untrimmed re-publication of an already-merged selector
	// dedupes, and fresh selectors are stored trimmed.
	got = mergeVulnFuncs(got, []string{"\tyaml.Unmarshal\n", "  yaml.Decoder.Decode  "}, "go")
	want := []string{"yaml.Unmarshal", "yaml.Decoder.Decode"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeVulnFuncs = %#v, want %#v (trimmed append + trimmed dedupe)", got, want)
	}
}

// writeNpmFixture writes a minimal npm project to a temp dir (the vendored
// analyzer testdata under internal/reachability is reference-only for this
// package): package.json + package-lock.json (v3) declaring evil-pkg and
// @acme/scoped-lib, plus sources that import both — a CJS receiver binding
// with an `evil.pwn(...)` member call, and an ESM named import of
// `deepMerge` — so symbol-carrying targets can reach `reachable` and
// symbol-less ones stop at `import_only`. withGoMod additionally writes
// the reach_fixture go.mod (requiring example.test/vulnpkg) so one root
// serves a mixed go+npm run.
func writeNpmFixture(t *testing.T, withGoMod bool) string {
	t.Helper()
	dir := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	write("package.json", `{
  "name": "reach-npm-fixture",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "evil-pkg": "^1.0.0",
    "@acme/scoped-lib": "^1.2.0"
  }
}
`)
	write("package-lock.json", `{
  "name": "reach-npm-fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "reach-npm-fixture",
      "version": "1.0.0",
      "dependencies": {
        "evil-pkg": "^1.0.0",
        "@acme/scoped-lib": "^1.2.0"
      }
    },
    "node_modules/evil-pkg": {
      "version": "1.0.3",
      "resolved": "https://registry.example.test/evil-pkg/-/evil-pkg-1.0.3.tgz"
    },
    "node_modules/@acme/scoped-lib": {
      "version": "1.2.3",
      "resolved": "https://registry.example.test/@acme/scoped-lib/-/scoped-lib-1.2.3.tgz"
    }
  }
}
`)
	write("src/app.js", `'use strict';
const evil = require('evil-pkg');
module.exports = function run(a, b) {
  return evil.pwn(a, b);
};
`)
	write("src/scoped.mjs", `import { deepMerge } from '@acme/scoped-lib';
export const combine = (a, b) => deepMerge(a, b);
`)
	if withGoMod {
		write("go.mod", "module example.test/reachfixture\n\ngo 1.22\n\nrequire example.test/vulnpkg v1.0.0\n")
		write("main.go", "package main\n\nfunc main() {}\n")
	}
	return dir
}

// TestReachability_NpmTargets_NotDropped — M44 Wave 4 (F472), red 1 in the
// red→green record: with the pre-F472 code an npm target (plain AND scoped
// purl) fell into droppedNoModule (no derivable Go module), so nothing was
// analyzed or uploaded. Now both derive an npm package coordinate, reach
// the REAL NpmAnalyzer, and upload verdicts. Also pins that an explicit
// --ecosystem=npm forwards the server-side ?ecosystem= filter.
func TestReachability_NpmTargets_NotDropped(t *testing.T) {
	targets := []api.ReachabilityTarget{
		{CVEID: "CVE-2024-1001", ComponentID: "n1", Purl: "pkg:npm/evil-pkg@1.0.0", Ecosystem: "npm"},
		{CVEID: "CVE-2024-1002", ComponentID: "n2", Purl: "pkg:npm/%40acme%2Fscoped-lib@1.2.3", Ecosystem: "npm"},
	}
	rf := newReachFakeServer(t, targets)
	client := api.NewClient(rf.server.URL, "test-key")

	var stdout, stderr bytes.Buffer
	err := runReachabilityAnalysis(context.Background(), client, reachOpts{
		projectID: reachTestProject,
		ecosystem: "npm",
		path:      writeNpmFixture(t, false),
		analyzers: map[string]reachAnalyzer{"npm": &reachability.NpmAnalyzer{}},
		stdout:    &stdout,
		stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("runReachabilityAnalysis error: %v (stderr=%s)", err, stderr.String())
	}
	if rf.lastTargetsQ != "npm" {
		t.Errorf("targets ?ecosystem = %q, want npm (explicit flag forwards the filter)", rf.lastTargetsQ)
	}
	if rf.uploadHits != 1 {
		t.Fatalf("uploadHits = %d, want 1 (npm targets must be analyzed, not dropped; stderr=%s)", rf.uploadHits, stderr.String())
	}
	var envelope struct {
		Results []api.ReachabilityUploadResult `json:"results"`
	}
	if err := json.Unmarshal(rf.lastPostBody, &envelope); err != nil {
		t.Fatalf("decode POST body: %v", err)
	}
	if len(envelope.Results) != 2 {
		t.Fatalf("results len = %d, want 2 (plain + scoped npm targets)", len(envelope.Results))
	}
	for _, r := range envelope.Results {
		if r.AnalyzerVersion != "npm_analyzer/v1" {
			t.Errorf("analyzer_version = %q, want npm_analyzer/v1 (npm target must reach the npm analyzer)", r.AnalyzerVersion)
		}
		if r.Ecosystem != "npm" {
			t.Errorf("ecosystem = %q, want npm (verbatim forward)", r.Ecosystem)
		}
		// No symbols published → the analyzer stops at the import stage.
		if r.Status != string(reachability.StatusImportOnly) {
			t.Errorf("cve %s status = %q, want import_only (both packages are in the dependency graph)", r.CVEID, r.Status)
		}
	}
}

// TestReachability_MixedEcosystems_Dispatch — M44 Wave 4 (F472): the
// default --ecosystem=all fetches the targets UNFILTERED (no ?ecosystem=,
// the M32 wire behavior) and dispatches per row — go rows to the
// GoAnalyzer, npm rows to the NpmAnalyzer, rows in ecosystems with no
// analyzer skipped and counted on stderr. One POST carries every verdict.
func TestReachability_MixedEcosystems_Dispatch(t *testing.T) {
	targets := []api.ReachabilityTarget{
		{CVEID: "CVE-2024-0001", ComponentID: "g1", Purl: "pkg:golang/example.test/vulnpkg@v1.0.0", Ecosystem: "go"},
		{CVEID: "CVE-2024-0002", ComponentID: "g2", Purl: "pkg:golang/example.test/absent@v2.0.0", Ecosystem: "go"},
		{CVEID: "CVE-2024-1001", ComponentID: "n1", Purl: "pkg:npm/evil-pkg@1.0.0", Ecosystem: "npm"},
		{CVEID: "CVE-2024-1002", ComponentID: "n2", Purl: "pkg:npm/%40acme%2Fscoped-lib@1.2.3", Ecosystem: "npm"},
		{CVEID: "CVE-2024-2001", ComponentID: "m1", Purl: "pkg:maven/org.acme/thing@1.0.0", Ecosystem: "maven"},
	}
	rf := newReachFakeServer(t, targets)
	client := api.NewClient(rf.server.URL, "test-key")
	goRec := newRecordingAnalyzer()
	npmRec := newRecordingNpmAnalyzer()

	var stdout, stderr bytes.Buffer
	err := runReachabilityAnalysis(context.Background(), client, reachOpts{
		projectID: reachTestProject,
		ecosystem: "all",
		path:      writeNpmFixture(t, true),
		analyzers: map[string]reachAnalyzer{"go": goRec, "npm": npmRec},
		stdout:    &stdout,
		stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("runReachabilityAnalysis error: %v (stderr=%s)", err, stderr.String())
	}

	// --ecosystem=all must fetch WITHOUT the server-side filter.
	if rf.lastTargetsQ != "" {
		t.Errorf("targets ?ecosystem = %q, want \"\" (unfiltered fetch under --ecosystem=all)", rf.lastTargetsQ)
	}

	// go rows → GoAnalyzer, with the Go module coordinate and ecosystem.
	if got := len(goRec.inputs); got != 2 {
		t.Fatalf("GoAnalyzer invocations = %d, want 2", got)
	}
	for cve, wantModule := range map[string]string{
		"CVE-2024-0001": "example.test/vulnpkg",
		"CVE-2024-0002": "example.test/absent",
	} {
		in, ok := goRec.inputByCVE(cve)
		if !ok {
			t.Fatalf("no GoAnalyzer input recorded for %s", cve)
		}
		if in.Ecosystem != "go" || !reflect.DeepEqual(in.VulnerableModules, []string{wantModule}) {
			t.Errorf("%s GoAnalyzer input = (eco=%q, modules=%v), want (go, [%s])", cve, in.Ecosystem, in.VulnerableModules, wantModule)
		}
	}

	// npm rows → NpmAnalyzer, with the npm package name ("@scope/name"
	// decoded from the purl) and ecosystem npm.
	if got := len(npmRec.inputs); got != 2 {
		t.Fatalf("NpmAnalyzer invocations = %d, want 2", got)
	}
	for cve, wantPkg := range map[string]string{
		"CVE-2024-1001": "evil-pkg",
		"CVE-2024-1002": "@acme/scoped-lib",
	} {
		in, ok := npmRec.inputByCVE(cve)
		if !ok {
			t.Fatalf("no NpmAnalyzer input recorded for %s", cve)
		}
		if in.Ecosystem != "npm" || !reflect.DeepEqual(in.VulnerableModules, []string{wantPkg}) {
			t.Errorf("%s NpmAnalyzer input = (eco=%q, modules=%v), want (npm, [%s])", cve, in.Ecosystem, in.VulnerableModules, wantPkg)
		}
	}

	// The maven row has no analyzer: skipped + counted, distinct from the
	// no-module skip.
	if !strings.Contains(stderr.String(), "skipped 1 targets in unsupported ecosystems") {
		t.Errorf("stderr should report the unsupported-ecosystem skip: %s", stderr.String())
	}

	// One POST with all four verdicts; ecosystem forwarded per row.
	if rf.uploadHits != 1 {
		t.Fatalf("uploadHits = %d, want 1", rf.uploadHits)
	}
	var envelope struct {
		Results []api.ReachabilityUploadResult `json:"results"`
	}
	if err := json.Unmarshal(rf.lastPostBody, &envelope); err != nil {
		t.Fatalf("decode POST body: %v", err)
	}
	if len(envelope.Results) != 4 {
		t.Fatalf("results len = %d, want 4 (2 go + 2 npm; maven skipped)", len(envelope.Results))
	}
	wantRows := map[string]struct{ eco, version, status string }{
		"CVE-2024-0001": {"go", "go_analyzer/v1", string(reachability.StatusImportOnly)},
		"CVE-2024-0002": {"go", "go_analyzer/v1", string(reachability.StatusNotPresent)},
		"CVE-2024-1001": {"npm", "npm_analyzer/v1", string(reachability.StatusImportOnly)},
		"CVE-2024-1002": {"npm", "npm_analyzer/v1", string(reachability.StatusImportOnly)},
	}
	for _, r := range envelope.Results {
		want, ok := wantRows[r.CVEID]
		if !ok {
			t.Errorf("unexpected uploaded CVE %q", r.CVEID)
			continue
		}
		if r.Ecosystem != want.eco || r.AnalyzerVersion != want.version || r.Status != want.status {
			t.Errorf("cve %s uploaded (eco=%q, analyzer=%q, status=%q), want (%q, %q, %q)",
				r.CVEID, r.Ecosystem, r.AnalyzerVersion, r.Status, want.eco, want.version, want.status)
		}
	}
}

// TestReachability_NpmVulnFuncs_BareSelectorsForwarded — M44 Wave 4
// (F472), red 2 in the red→green record: an npm row's server-normalized
// vuln_funcs use the npm shape — most often a BARE export name
// ("defaultsDeep"), and "$" is a legal JS identifier rune — which the
// Go-only shape filter dropped 100% of the time (pre-fix run: only
// "_.merge" survived). The filter now dispatches on the work item's
// ecosystem: the npm row keeps its npm-form selectors (while npm-malformed
// junk still drops), and a go row in the same run keeps the Go rule — a
// bare export never reaches the Go analyzer (mirrors the server's per-row
// normalisation, TestReachabilityHandler_GetTargets_UnscopedUnionEcosystemNormalized).
func TestReachability_NpmVulnFuncs_BareSelectorsForwarded(t *testing.T) {
	oversized := strings.Repeat("a", maxNpmVulnFuncBytes+1)
	targets := []api.ReachabilityTarget{
		{CVEID: "CVE-2024-1001", ComponentID: "n1", Purl: "pkg:npm/evil-pkg@1.0.0", Ecosystem: "npm",
			VulnFuncs: []string{"defaultsDeep", "$.ajax", "_.merge", "a.b.c.d", "1pkg.foo", "lib/lodash.js", "", "prototype pollution", oversized}},
		{CVEID: "CVE-2024-0001", ComponentID: "g1", Purl: "pkg:golang/example.test/vulnpkg@v1.0.0", Ecosystem: "go",
			VulnFuncs: []string{"defaultsDeep", "yaml.Unmarshal"}},
	}
	rf := newReachFakeServer(t, targets)
	client := api.NewClient(rf.server.URL, "test-key")
	goRec := newRecordingAnalyzer()
	npmRec := newRecordingNpmAnalyzer()

	var stdout, stderr bytes.Buffer
	err := runReachabilityAnalysis(context.Background(), client, reachOpts{
		projectID: reachTestProject,
		ecosystem: "all",
		path:      writeNpmFixture(t, true),
		analyzers: map[string]reachAnalyzer{"go": goRec, "npm": npmRec},
		stdout:    &stdout,
		stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("runReachabilityAnalysis error: %v (stderr=%s)", err, stderr.String())
	}

	npmIn, ok := npmRec.inputByCVE("CVE-2024-1001")
	if !ok {
		t.Fatal("no NpmAnalyzer input recorded for CVE-2024-1001 (npm target dropped?)")
	}
	wantNpm := []string{"defaultsDeep", "$.ajax", "_.merge"}
	if !reflect.DeepEqual(npmIn.VulnerableSymbols, wantNpm) {
		t.Errorf("npm VulnerableSymbols = %#v, want %#v (bare/dollar selectors survive, npm-malformed junk drops)", npmIn.VulnerableSymbols, wantNpm)
	}

	goIn, ok := goRec.inputByCVE("CVE-2024-0001")
	if !ok {
		t.Fatal("no GoAnalyzer input recorded for CVE-2024-0001")
	}
	wantGo := []string{"yaml.Unmarshal"}
	if !reflect.DeepEqual(goIn.VulnerableSymbols, wantGo) {
		t.Errorf("go VulnerableSymbols = %#v, want %#v (a bare npm export must NOT pass the Go rule)", goIn.VulnerableSymbols, wantGo)
	}
}

// TestMergeVulnFuncs_NpmSelectorShapes pins the npm shape-acceptance rule
// of the vuln_funcs filter (M44 Wave 4 / F472). LOCKSTEP: the accept/drop
// verdicts mirror the acceptance subset of the server-side
// TestNormalizeVulnFuncsNpm table
// (sbomhub apps/api/internal/handler/reachability_targets_test.go, M44
// Wave 3 / F471 — isNpmVulnFuncSelector). Two deliberate pipeline
// differences from that table, both pre-existing CLI policy shared with
// the Go arm: the CLI DROPS a trailing-"()" variant instead of stripping
// it (the CLI never rewrites selector content; a conforming server never
// ships "()"), and blank entries are dropped before the shape check.
func TestMergeVulnFuncs_NpmSelectorShapes(t *testing.T) {
	atCap := strings.Repeat("a", maxNpmVulnFuncBytes)
	overCap := strings.Repeat("a", maxNpmVulnFuncBytes+1)
	cases := []struct {
		name string
		in   string
		keep bool
	}{
		{"bare export kept", "defaultsDeep", true},
		{"underscore receiver kept", "_.merge", true},
		{"dollar receiver kept", "$.ajax", true},
		{"bare dollar kept", "$", true},
		{"node module selector kept", "child_process.exec", true},
		{"three parts kept", "a.b.c", true},
		// Form-valid but semantically generic: FORM-ONLY check, the
		// analyzer's binding-aware matching owns precision (server note).
		{"generic property access kept (form-only)", "headers.location", true},
		// Unicode letters are legal identifier runes in both grammars.
		{"unicode selector kept", "パッケージ.解析", true},
		// A Go-shaped selector is a valid JS shape too — harmless, the
		// analyzer only matches symbols the package actually binds.
		{"go-shaped selector kept", "Pkg.Type.Method", true},
		{"exactly cap bytes kept", atCap, true},

		{"trailing parens dropped (CLI never rewrites)", "defaultsDeep()", false},
		{"url dropped", "https://evil", false},
		{"path dropped", "lib/lodash.js", false},
		{"bare version dropped", "1.2.3", false},
		{"digit-led part dropped", "1pkg.foo", false},
		{"four parts dropped", "a.b.c.d", false},
		{"embedded space dropped", "prototype pollution", false},
		{"leading empty part dropped", ".foo", false},
		{"trailing empty part dropped", "foo.", false},
		{"over cap bytes dropped", overCap, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeVulnFuncs(nil, []string{tc.in}, "npm")
			if tc.keep {
				if !reflect.DeepEqual(got, []string{tc.in}) {
					t.Errorf("mergeVulnFuncs(nil, [%q], npm) = %#v, want [%q]", tc.in, got, tc.in)
				}
			} else if got != nil {
				t.Errorf("mergeVulnFuncs(nil, [%q], npm) = %#v, want nil (shape must drop)", tc.in, got)
			}
		})
	}
}

// TestReachability_NpmReachable_EndToEnd — M44 Wave 4 (F472): the full
// path with a fake server and the REAL NpmAnalyzer (source scan ENABLED)
// against a real npm fixture tree. Symbol-carrying npm targets reach
// symbol-level `reachable` verdicts — via a receiver-binding member call
// (`evil.pwn(...)`) for the plain package and a named ESM import binding
// (`import { deepMerge }`) for the scoped one — and the verdicts land on
// the frozen POST contract.
func TestReachability_NpmReachable_EndToEnd(t *testing.T) {
	targets := []api.ReachabilityTarget{
		{CVEID: "CVE-2024-1001", ComponentID: "n1", Purl: "pkg:npm/evil-pkg@1.0.0", Ecosystem: "npm",
			VulnFuncs: []string{"pwn"}},
		{CVEID: "CVE-2024-1002", ComponentID: "n2", Purl: "pkg:npm/%40acme%2Fscoped-lib@1.2.3", Ecosystem: "npm",
			VulnFuncs: []string{"deepMerge"}},
	}
	rf := newReachFakeServer(t, targets)
	client := api.NewClient(rf.server.URL, "test-key")

	var stdout, stderr bytes.Buffer
	err := runReachabilityAnalysis(context.Background(), client, reachOpts{
		projectID: reachTestProject,
		ecosystem: "npm",
		path:      writeNpmFixture(t, false),
		analyzers: map[string]reachAnalyzer{"npm": &reachability.NpmAnalyzer{}},
		stdout:    &stdout,
		stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("runReachabilityAnalysis error: %v (stderr=%s)", err, stderr.String())
	}
	if rf.uploadHits != 1 {
		t.Fatalf("uploadHits = %d, want 1", rf.uploadHits)
	}
	var envelope struct {
		Results []api.ReachabilityUploadResult `json:"results"`
	}
	if err := json.Unmarshal(rf.lastPostBody, &envelope); err != nil {
		t.Fatalf("decode POST body: %v", err)
	}
	if len(envelope.Results) != 2 {
		t.Fatalf("results len = %d, want 2", len(envelope.Results))
	}
	for _, r := range envelope.Results {
		if r.Status != string(reachability.StatusReachable) {
			t.Errorf("cve %s status = %q, want reachable", r.CVEID, r.Status)
		}
		if r.Confidence != 0.70 {
			t.Errorf("cve %s confidence = %v, want 0.70 (single symbol hit)", r.CVEID, r.Confidence)
		}
		if r.AnalyzerVersion != "npm_analyzer/v1" {
			t.Errorf("cve %s analyzer_version = %q, want npm_analyzer/v1", r.CVEID, r.AnalyzerVersion)
		}
		if r.Ecosystem != "npm" {
			t.Errorf("cve %s ecosystem = %q, want npm", r.CVEID, r.Ecosystem)
		}
		if r.AnalyzedAt.IsZero() {
			t.Errorf("cve %s analyzed_at is zero", r.CVEID)
		}
		if len(r.Evidence) == 0 {
			t.Errorf("cve %s reachable verdict should carry evidence", r.CVEID)
		}
	}
	// The symbol evidence names the matched selector.
	byCVE := map[string]api.ReachabilityUploadResult{}
	for _, r := range envelope.Results {
		byCVE[r.CVEID] = r
	}
	if !strings.Contains(string(byCVE["CVE-2024-1001"].Evidence), "pwn") {
		t.Errorf("CVE-2024-1001 evidence should reference symbol pwn: %s", byCVE["CVE-2024-1001"].Evidence)
	}
	if !strings.Contains(string(byCVE["CVE-2024-1002"].Evidence), "deepMerge") {
		t.Errorf("CVE-2024-1002 evidence should reference symbol deepMerge: %s", byCVE["CVE-2024-1002"].Evidence)
	}
}

// TestReachability_NpmVulnFuncsAbsent_ImportOnly — old-server / no-symbol
// compat (the npm arm of the M43 graceful degrade): an npm target row
// WITHOUT the vuln_funcs field (exactly what a server without symbol data
// sends — hence the raw JSON body) forwards nil VulnerableSymbols, the
// REAL NpmAnalyzer (source scan enabled) stops at the import stage, and
// the verdict is the clean import_only 0.60 — not reachable, not the
// degraded 0.50 path.
func TestReachability_NpmVulnFuncsAbsent_ImportOnly(t *testing.T) {
	rf := newReachFakeServer(t, nil)
	rf.rawTargets = []byte(`{"targets":[
		{"cve_id":"CVE-2024-1001","component_id":"n1","purl":"pkg:npm/evil-pkg@1.0.0","ecosystem":"npm"}
	]}`)
	client := api.NewClient(rf.server.URL, "test-key")
	rec := &recordingAnalyzer{real: &reachability.NpmAnalyzer{}}

	var stdout, stderr bytes.Buffer
	err := runReachabilityAnalysis(context.Background(), client, reachOpts{
		projectID: reachTestProject,
		ecosystem: "npm",
		path:      writeNpmFixture(t, false),
		analyzers: map[string]reachAnalyzer{"npm": rec},
		stdout:    &stdout,
		stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("runReachabilityAnalysis error: %v (stderr=%s)", err, stderr.String())
	}
	in, ok := rec.inputByCVE("CVE-2024-1001")
	if !ok {
		t.Fatal("no analyzer input recorded for CVE-2024-1001")
	}
	if in.VulnerableSymbols != nil {
		t.Errorf("VulnerableSymbols = %#v, want nil when vuln_funcs is absent", in.VulnerableSymbols)
	}
	var envelope struct {
		Results []api.ReachabilityUploadResult `json:"results"`
	}
	if err := json.Unmarshal(rf.lastPostBody, &envelope); err != nil {
		t.Fatalf("decode POST body: %v", err)
	}
	if len(envelope.Results) != 1 {
		t.Fatalf("results len = %d, want 1", len(envelope.Results))
	}
	if got := envelope.Results[0]; got.Status != string(reachability.StatusImportOnly) || got.Confidence != 0.60 {
		t.Errorf("verdict = (%q, %v), want (import_only, 0.60) — symbol-less npm target must degrade gracefully", got.Status, got.Confidence)
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
