package reachability

// Tests for the VENDORED npm reachability analyzer (M44 Wave 1, F469).
// Ported from the backend suite (sbomhub/apps/api/internal/service/
// reachability/npm_analyzer_test.go) but rewritten to the CLI's
// stdlib-testing convention (the CLI does not vendor testify).
//
// All fixtures under testdata/npm_* use fake package names (acme-lodash,
// @acme/scoped-lib, …) that do not exist in the public registry, and the
// analyzer never touches the network or spawns a toolchain — the whole
// suite is offline-safe. Cases that need directories the repo cannot carry
// as fixtures (node_modules/, dist/) build a temp project instead.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// npmEvidenceOfKind filters a result's evidence by kind.
func npmEvidenceOfKind(res *ReachabilityResult, kind EvidenceKind) []EvidencePointer {
	var out []EvidencePointer
	for _, e := range res.Evidence {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// npmHasDescription reports whether any evidence description contains substr.
func npmHasDescription(res *ReachabilityResult, substr string) bool {
	for _, e := range res.Evidence {
		if strings.Contains(e.Description, substr) {
			return true
		}
	}
	return false
}

func npmMustAnalyze(t *testing.T, a *NpmAnalyzer, path string, input ReachabilityInput) *ReachabilityResult {
	t.Helper()
	res, err := a.Analyze(context.Background(), path, input)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if res == nil {
		t.Fatal("Analyze returned nil result")
	}
	return res
}

func TestNpmAnalyze_NotPresent_WithLockfile(t *testing.T) {
	t.Parallel()
	res := npmMustAnalyze(t, &NpmAnalyzer{}, "testdata/npm_project",
		ReachabilityInput{
			AdvisoryID:        "GHSA-npm-0001",
			Ecosystem:         "npm",
			VulnerableModules: []string{"totally-absent-pkg"},
			VulnerableSymbols: []string{"defaultsDeep"},
		})
	if res.Status != StatusNotPresent {
		t.Errorf("Status = %q, want %q", res.Status, StatusNotPresent)
	}
	if res.Confidence != 0.90 {
		t.Errorf("Confidence = %v, want 0.90", res.Confidence)
	}
	if res.Ecosystem != "npm" {
		t.Errorf("Ecosystem = %q, want npm", res.Ecosystem)
	}
	if res.AnalyzerName != npmAnalyzerName {
		t.Errorf("AnalyzerName = %q, want %q", res.AnalyzerName, npmAnalyzerName)
	}
	if !npmHasDescription(res, "package-lock.json") {
		t.Errorf("expected lockfile mention in evidence, got %+v", res.Evidence)
	}
}

func TestNpmAnalyze_NotPresent_NoLockfile_ReducedConfidence(t *testing.T) {
	t.Parallel()
	res := npmMustAnalyze(t, &NpmAnalyzer{}, "testdata/npm_no_lockfile_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"totally-absent-pkg"},
		})
	if res.Status != StatusNotPresent {
		t.Errorf("Status = %q, want %q", res.Status, StatusNotPresent)
	}
	if res.Confidence != 0.60 {
		t.Errorf("Confidence = %v, want 0.60 (reduced without lockfile)", res.Confidence)
	}
	if !npmHasDescription(res, "no lockfile found") {
		t.Errorf("expected reduced-confidence explanation, got %+v", res.Evidence)
	}
}

func TestNpmAnalyze_Reachable_RequireBinding_BareSelector(t *testing.T) {
	t.Parallel()
	res := npmMustAnalyze(t, &NpmAnalyzer{}, "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"defaultsDeep"},
		})
	if res.Status != StatusReachable {
		t.Fatalf("Status = %q, want %q (evidence: %+v)", res.Status, StatusReachable, res.Evidence)
	}
	if res.Confidence != 0.70 {
		t.Errorf("Confidence = %v, want 0.70", res.Confidence)
	}
	imports := npmEvidenceOfKind(res, EvidenceKindImportPath)
	if len(imports) == 0 {
		t.Fatal("no import_path evidence")
	}
	if imports[0].ImportPath != "acme-lodash" {
		t.Errorf("graph evidence ImportPath = %q, want acme-lodash", imports[0].ImportPath)
	}
	var sourceImport *EvidencePointer
	for i := range imports {
		if imports[i].FilePath == "src/cjs_consumer.js" {
			sourceImport = &imports[i]
		}
	}
	if sourceImport == nil {
		t.Fatalf("expected import evidence in src/cjs_consumer.js, got %+v", imports)
	}
	if sourceImport.Line != 4 {
		t.Errorf("source import Line = %d, want 4", sourceImport.Line)
	}
	symbols := npmEvidenceOfKind(res, EvidenceKindSymbolRef)
	if len(symbols) != 1 {
		t.Fatalf("symbol evidence count = %d, want 1: %+v", len(symbols), symbols)
	}
	if symbols[0].Symbol != "defaultsDeep" || symbols[0].FilePath != "src/cjs_consumer.js" {
		t.Errorf("symbol evidence = %+v, want defaultsDeep in src/cjs_consumer.js", symbols[0])
	}
	if symbols[0].Line != 9 || symbols[0].Column != 10 {
		t.Errorf("symbol position = %d:%d, want 9:10", symbols[0].Line, symbols[0].Column)
	}
}

func TestNpmAnalyze_Reachable_ReceiverDotMethodSelector(t *testing.T) {
	t.Parallel()
	res := npmMustAnalyze(t, &NpmAnalyzer{}, "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"_.defaultsDeep"},
		})
	if res.Status != StatusReachable {
		t.Fatalf("Status = %q, want %q", res.Status, StatusReachable)
	}
	symbols := npmEvidenceOfKind(res, EvidenceKindSymbolRef)
	if len(symbols) != 1 {
		t.Fatalf("symbol evidence count = %d, want 1", len(symbols))
	}
	if symbols[0].Symbol != "_.defaultsDeep" || symbols[0].FilePath != "src/cjs_consumer.js" {
		t.Errorf("symbol evidence = %+v", symbols[0])
	}
}

func TestNpmAnalyze_Reachable_ESMNamedImport_ScopedPackage(t *testing.T) {
	t.Parallel()
	res := npmMustAnalyze(t, &NpmAnalyzer{}, "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"@acme/scoped-lib"},
			VulnerableSymbols: []string{"deepMerge"},
		})
	if res.Status != StatusReachable {
		t.Fatalf("Status = %q, want %q (evidence: %+v)", res.Status, StatusReachable, res.Evidence)
	}
	if res.Confidence != 0.70 {
		t.Errorf("Confidence = %v, want 0.70", res.Confidence)
	}
	symbols := npmEvidenceOfKind(res, EvidenceKindSymbolRef)
	if len(symbols) != 1 {
		t.Fatalf("symbol evidence count = %d, want 1", len(symbols))
	}
	if symbols[0].FilePath != "src/esm_consumer.ts" || symbols[0].Line != 2 {
		t.Errorf("symbol evidence = %+v, want src/esm_consumer.ts line 2", symbols[0])
	}
	if !strings.Contains(symbols[0].Description, "named import binding") {
		t.Errorf("Description = %q, want named-import-binding mention", symbols[0].Description)
	}
}

func TestNpmAnalyze_Reachable_TwoHits_HigherConfidence(t *testing.T) {
	t.Parallel()
	res := npmMustAnalyze(t, &NpmAnalyzer{}, "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash", "@acme/scoped-lib"},
			VulnerableSymbols: []string{"defaultsDeep", "deepMerge"},
		})
	if res.Status != StatusReachable {
		t.Fatalf("Status = %q, want %q", res.Status, StatusReachable)
	}
	if res.Confidence != 0.85 {
		t.Errorf("Confidence = %v, want 0.85 for >=2 symbol hits", res.Confidence)
	}
	if n := len(npmEvidenceOfKind(res, EvidenceKindSymbolRef)); n != 2 {
		t.Errorf("symbol evidence count = %d, want 2", n)
	}
}

func TestNpmAnalyze_Reachable_NoLockfile_DefaultImport(t *testing.T) {
	t.Parallel()
	res := npmMustAnalyze(t, &NpmAnalyzer{}, "testdata/npm_no_lockfile_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"defaultsDeep"},
		})
	// A positive hit is a hit: lockfile absence does not weaken direct
	// source evidence.
	if res.Status != StatusReachable {
		t.Fatalf("Status = %q, want %q", res.Status, StatusReachable)
	}
	if res.Confidence != 0.70 {
		t.Errorf("Confidence = %v, want 0.70", res.Confidence)
	}
	symbols := npmEvidenceOfKind(res, EvidenceKindSymbolRef)
	if len(symbols) != 1 || symbols[0].FilePath != "src/app.js" {
		t.Errorf("symbol evidence = %+v, want one hit in src/app.js", symbols)
	}
}

func TestNpmAnalyze_ImportOnly_SymbolSuppliedButNotHit(t *testing.T) {
	t.Parallel()
	res := npmMustAnalyze(t, &NpmAnalyzer{}, "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"nonexistentFn"},
		})
	if res.Status != StatusImportOnly {
		t.Errorf("Status = %q, want %q", res.Status, StatusImportOnly)
	}
	if res.Confidence != 0.60 {
		t.Errorf("Confidence = %v, want 0.60", res.Confidence)
	}
	if n := len(npmEvidenceOfKind(res, EvidenceKindSymbolRef)); n != 0 {
		t.Errorf("symbol evidence count = %d, want 0", n)
	}
	var found bool
	for _, e := range npmEvidenceOfKind(res, EvidenceKindImportPath) {
		if e.FilePath == "src/cjs_consumer.js" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected source import evidence, got %+v", res.Evidence)
	}
}

func TestNpmAnalyze_ImportOnly_NoSymbolsSupplied(t *testing.T) {
	t.Parallel()
	res := npmMustAnalyze(t, &NpmAnalyzer{}, "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
		})
	if res.Status != StatusImportOnly {
		t.Errorf("Status = %q, want %q", res.Status, StatusImportOnly)
	}
	if res.Confidence != 0.60 {
		t.Errorf("Confidence = %v, want 0.60", res.Confidence)
	}
	if !npmHasDescription(res, "did not publish vulnerable symbol names") {
		t.Errorf("expected no-symbols note, got %+v", res.Evidence)
	}
}

func TestNpmAnalyze_ImportOnly_TransitiveOnly(t *testing.T) {
	t.Parallel()
	res := npmMustAnalyze(t, &NpmAnalyzer{}, "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-deep-transitive"},
			VulnerableSymbols: []string{"anything"},
		})
	// Present in the lockfile (nested under acme-transitive-parent) but
	// never imported by first-party source.
	if res.Status != StatusImportOnly {
		t.Errorf("Status = %q, want %q", res.Status, StatusImportOnly)
	}
	if !npmHasDescription(res, "transitive") {
		t.Errorf("expected transitive-dependency note, got %+v", res.Evidence)
	}
	graph := npmEvidenceOfKind(res, EvidenceKindImportPath)
	if len(graph) == 0 || !strings.Contains(graph[0].Description, "package-lock.json") {
		t.Errorf("expected package-lock.json graph evidence, got %+v", graph)
	}
}

func TestNpmAnalyze_ImportOnly_DevDependency_CommentedRequireIgnored(t *testing.T) {
	t.Parallel()
	res := npmMustAnalyze(t, &NpmAnalyzer{}, "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-dev-tool"},
			VulnerableSymbols: []string{"lint"},
		})
	// devDependency counts as present (stage 1), and the commented-out
	// require in src/cjs_consumer.js must NOT count as a source import.
	if res.Status != StatusImportOnly {
		t.Errorf("Status = %q, want %q", res.Status, StatusImportOnly)
	}
	for _, e := range npmEvidenceOfKind(res, EvidenceKindImportPath) {
		if e.Line != 0 {
			t.Errorf("commented-out require must not yield source evidence: %+v", e)
		}
	}
	if !npmHasDescription(res, "devDependencies") {
		t.Errorf("expected devDependencies graph evidence, got %+v", res.Evidence)
	}
}

func TestNpmAnalyze_ImportOnly_DynamicImport(t *testing.T) {
	t.Parallel()
	res := npmMustAnalyze(t, &NpmAnalyzer{}, "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-transitive-parent"},
			VulnerableSymbols: []string{"parentFn"},
		})
	// Dynamic import() yields import-level evidence but no binding, so the
	// verdict stays import_only even with symbols supplied.
	if res.Status != StatusImportOnly {
		t.Errorf("Status = %q, want %q", res.Status, StatusImportOnly)
	}
	var found bool
	for _, e := range npmEvidenceOfKind(res, EvidenceKindImportPath) {
		if e.FilePath == "src/dynamic_consumer.mjs" {
			found = true
			if !strings.Contains(e.Description, "dynamic import") {
				t.Errorf("Description = %q, want dynamic import mention", e.Description)
			}
		}
	}
	if !found {
		t.Errorf("expected dynamic-import evidence, got %+v", res.Evidence)
	}
}

func TestNpmAnalyze_SkipSourceScan(t *testing.T) {
	t.Parallel()
	res := npmMustAnalyze(t, &NpmAnalyzer{SkipSourceScan: true}, "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"defaultsDeep"},
		})
	if res.Status != StatusImportOnly {
		t.Errorf("Status = %q, want %q", res.Status, StatusImportOnly)
	}
	if res.Confidence != 0.60 {
		t.Errorf("Confidence = %v, want 0.60", res.Confidence)
	}
	if n := len(npmEvidenceOfKind(res, EvidenceKindSymbolRef)); n != 0 {
		t.Errorf("symbol evidence count = %d, want 0 with SkipSourceScan", n)
	}
	for _, e := range npmEvidenceOfKind(res, EvidenceKindImportPath) {
		if e.Line != 0 {
			t.Errorf("stage-1-only run must not carry source positions: %+v", e)
		}
	}
}

func TestNpmAnalyze_CaseInsensitivePackageMatch(t *testing.T) {
	t.Parallel()
	res := npmMustAnalyze(t, &NpmAnalyzer{}, "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"ACME-Lodash"},
			VulnerableSymbols: []string{"defaultsDeep"},
		})
	// Legacy npm packages may carry uppercase; matching is case-insensitive
	// end to end (graph and import specifiers).
	if res.Status != StatusReachable {
		t.Errorf("Status = %q, want %q", res.Status, StatusReachable)
	}
}

func TestNpmAnalyze_MalformedSelectorsSkippedIndividually(t *testing.T) {
	t.Parallel()
	res := npmMustAnalyze(t, &NpmAnalyzer{}, "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"@acme/scoped-lib"},
			VulnerableSymbols: []string{"deepMerge", "not-an-ident!", "a.b.c.d", "1bad", ""},
		})
	if res.Status != StatusReachable {
		t.Errorf("Status = %q, want %q (well-formed selector must still match)", res.Status, StatusReachable)
	}
	if !npmHasDescription(res, "malformed symbol selector") {
		t.Errorf("expected malformed-selector note, got %+v", res.Evidence)
	}
}

func TestNpmAnalyze_AllSelectorsMalformed(t *testing.T) {
	t.Parallel()
	res := npmMustAnalyze(t, &NpmAnalyzer{}, "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"not-an-ident!", "a.b.c.d"},
		})
	if res.Status != StatusImportOnly {
		t.Errorf("Status = %q, want %q", res.Status, StatusImportOnly)
	}
	if !npmHasDescription(res, "no well-formed vulnerable symbol selectors") {
		t.Errorf("expected all-malformed note, got %+v", res.Evidence)
	}
}

func TestNpmAnalyze_UnknownOnEmptyProjectPath(t *testing.T) {
	t.Parallel()
	res := npmMustAnalyze(t, &NpmAnalyzer{}, "   ",
		ReachabilityInput{Ecosystem: "npm", VulnerableModules: []string{"x"}})
	if res.Status != StatusUnknown {
		t.Errorf("Status = %q, want %q", res.Status, StatusUnknown)
	}
	if res.Confidence != 0.0 {
		t.Errorf("Confidence = %v, want 0.0", res.Confidence)
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Kind != EvidenceKindAnalyzerError {
		t.Errorf("Evidence = %+v, want one analyzer_error", res.Evidence)
	}
}

func TestNpmAnalyze_UnknownOnUnsupportedEcosystem(t *testing.T) {
	t.Parallel()
	res := npmMustAnalyze(t, &NpmAnalyzer{}, "testdata/npm_project",
		ReachabilityInput{Ecosystem: "go", VulnerableModules: []string{"x"}})
	if res.Status != StatusUnknown {
		t.Errorf("Status = %q, want %q", res.Status, StatusUnknown)
	}
	if !strings.Contains(res.Evidence[0].Description, `unsupported ecosystem "go"`) {
		t.Errorf("Description = %q, want unsupported-ecosystem mention", res.Evidence[0].Description)
	}
}

func TestNpmAnalyze_UnknownOnEmptyVulnerableModules(t *testing.T) {
	t.Parallel()
	res := npmMustAnalyze(t, &NpmAnalyzer{}, "testdata/npm_project",
		ReachabilityInput{Ecosystem: "npm"})
	if res.Status != StatusUnknown {
		t.Errorf("Status = %q, want %q", res.Status, StatusUnknown)
	}
}

func TestNpmAnalyze_UnknownOnNonNpmProject(t *testing.T) {
	t.Parallel()
	res := npmMustAnalyze(t, &NpmAnalyzer{}, t.TempDir(),
		ReachabilityInput{Ecosystem: "npm", VulnerableModules: []string{"x"}})
	if res.Status != StatusUnknown {
		t.Errorf("Status = %q, want %q", res.Status, StatusUnknown)
	}
	if !strings.Contains(res.Evidence[0].Description, "dependency graph load failed") {
		t.Errorf("Description = %q, want graph-load failure", res.Evidence[0].Description)
	}
}

func TestNpmAnalyze_NilContext(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}
	//nolint:staticcheck // deliberately testing nil-context handling
	res, err := a.Analyze(nil, "testdata/npm_project",
		ReachabilityInput{Ecosystem: "npm", VulnerableModules: []string{"x"}})
	if err == nil {
		t.Error("expected error for nil context")
	}
	if res != nil {
		t.Errorf("expected nil result, got %+v", res)
	}
}

func TestNpmAnalyze_CancelledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := (&NpmAnalyzer{}).Analyze(ctx, "testdata/npm_project",
		ReachabilityInput{Ecosystem: "npm", VulnerableModules: []string{"acme-lodash"}})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if res != nil {
		t.Errorf("expected nil result, got %+v", res)
	}
}

// TestNpmAnalyze_ExcludedDirsAndOversizeFiles builds a temp project because
// node_modules/ and dist/ cannot be carried as repo fixtures. Vulnerable-
// looking code inside node_modules/, dist/, build/, hidden dirs, and
// oversized files must not influence the verdict.
func TestNpmAnalyze_ExcludedDirsAndOversizeFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mustWrite := func(rel, content string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("package.json", `{"dependencies": {"acme-lodash": "^4.17.0"}}`)
	mustWrite("package-lock.json", `{
		"lockfileVersion": 3,
		"packages": {"node_modules/acme-lodash": {"version": "4.17.21"}}
	}`)
	vulnCode := "const _ = require('acme-lodash');\n_.defaultsDeep({}, {});\n"
	mustWrite("node_modules/acme-lodash/index.js", vulnCode)
	mustWrite("dist/bundle.js", vulnCode)
	mustWrite("build/out.js", vulnCode)
	mustWrite(".next/server/page.js", vulnCode)
	// Oversized first-party file: skipped by the size cap.
	mustWrite("src/huge.js", vulnCode+strings.Repeat("// padding padding padding\n", 50000))

	res := npmMustAnalyze(t, &NpmAnalyzer{}, root,
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"defaultsDeep"},
		})
	if res.Status != StatusImportOnly {
		t.Errorf("Status = %q, want %q (excluded/oversized code must not be reachable)",
			res.Status, StatusImportOnly)
	}
	for _, e := range res.Evidence {
		for _, banned := range []string{"node_modules", "dist", ".next", "huge.js"} {
			if strings.Contains(e.FilePath, banned) {
				t.Errorf("evidence leaked from excluded location: %+v", e)
			}
		}
	}
	if !npmHasDescription(res, "no first-party source file imports") {
		t.Errorf("expected transitive note, got %+v", res.Evidence)
	}
}

func TestNpmAnalyze_PnpmLockfileProject(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}

	// Transitive dependency: only visible through pnpm-lock.yaml snapshots.
	res := npmMustAnalyze(t, a, "testdata/npm_pnpm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-deep-transitive"},
		})
	if res.Status != StatusImportOnly {
		t.Errorf("Status = %q, want %q", res.Status, StatusImportOnly)
	}
	if !npmHasDescription(res, "pnpm-lock.yaml") {
		t.Errorf("expected pnpm-lock.yaml evidence, got %+v", res.Evidence)
	}

	// Absent package: full-confidence not_present thanks to the lockfile.
	res = npmMustAnalyze(t, a, "testdata/npm_pnpm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"totally-absent-pkg"},
		})
	if res.Status != StatusNotPresent {
		t.Errorf("Status = %q, want %q", res.Status, StatusNotPresent)
	}
	if res.Confidence != 0.90 {
		t.Errorf("Confidence = %v, want 0.90", res.Confidence)
	}
}

func TestNpmAnalyze_YarnLockfileProject(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}

	res := npmMustAnalyze(t, a, "testdata/npm_yarn_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-deep-transitive"},
		})
	if res.Status != StatusImportOnly {
		t.Errorf("Status = %q, want %q", res.Status, StatusImportOnly)
	}
	if !npmHasDescription(res, "yarn.lock") {
		t.Errorf("expected yarn.lock evidence, got %+v", res.Evidence)
	}

	res = npmMustAnalyze(t, a, "testdata/npm_yarn_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"@acme/scoped-lib"},
		})
	if res.Status != StatusImportOnly {
		t.Errorf("Status = %q, want %q (scoped yarn entry)", res.Status, StatusImportOnly)
	}
}

// ---------------------------------------------------------------------------
// unit tests for the parsing helpers
// ---------------------------------------------------------------------------

func TestParsePackageLockPackages_V1Shape(t *testing.T) {
	t.Parallel()
	g := &npmDependencyGraph{packages: map[string]npmGraphSource{}}
	data := []byte(`{
		"lockfileVersion": 1,
		"dependencies": {
			"acme-a": {"version": "1.0.0", "dependencies": {
				"acme-nested": {"version": "2.0.0"}
			}},
			"@scope/b": {"version": "3.0.0"}
		}
	}`)
	if err := parsePackageLockPackages(data, "package-lock.json", g); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	for _, want := range []string{"acme-a", "acme-nested", "@scope/b"} {
		if _, ok := g.packages[want]; !ok {
			t.Errorf("missing %s in %v", want, g.packages)
		}
	}
}

func TestPnpmPackageNameFromKey(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"/lodash/4.17.21":               "lodash",
		"/@scope/name/1.0.0":            "@scope/name",
		"/lodash@4.17.21":               "lodash",
		"lodash@4.17.21":                "lodash",
		"@scope/name@1.0.0":             "@scope/name",
		"@scope/name@1.0.0(peer@2.0.0)": "@scope/name",
		"/foo@1.0.0(react@18.0.0)":      "foo",
		"":                              "",
		"/":                             "",
		"plainname":                     "plainname",
	}
	for in, want := range cases {
		if got := pnpmPackageNameFromKey(in); got != want {
			t.Errorf("pnpmPackageNameFromKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseYarnLockPackages_BerryDescriptors(t *testing.T) {
	t.Parallel()
	g := &npmDependencyGraph{packages: map[string]npmGraphSource{}}
	data := []byte(`# yarn berry style
__metadata:
  version: 6

"lodash@npm:^4.17.15, lodash@npm:^4.17.19":
  version: 4.17.21

"@babel/code-frame@npm:^7.0.0":
  version: 7.12.13
`)
	if err := parseYarnLockPackages(data, "yarn.lock", g); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if _, ok := g.packages["lodash"]; !ok {
		t.Errorf("lodash missing: %v", g.packages)
	}
	if _, ok := g.packages["@babel/code-frame"]; !ok {
		t.Errorf("@babel/code-frame missing: %v", g.packages)
	}
	if _, ok := g.packages["__metadata"]; ok {
		t.Error("__metadata must be filtered out")
	}
}

func TestNpmPackageFromSpecifier(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"lodash":                "lodash",
		"lodash/fp":             "lodash",
		"@scope/name":           "@scope/name",
		"@scope/name/sub/path":  "@scope/name",
		"./relative":            "",
		"../up":                 "",
		"/abs/path":             "",
		"#internal":             "",
		"node:fs":               "",
		"https://cdn.example/x": "",
		"@":                     "",
		"@scope":                "",
		"":                      "",
	}
	for in, want := range cases {
		if got := npmPackageFromSpecifier(in); got != want {
			t.Errorf("npmPackageFromSpecifier(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseNpmImportClause(t *testing.T) {
	t.Parallel()
	cases := []struct {
		clause    string
		receivers []string
		named     []string
	}{
		{" _ ", []string{"_"}, nil},
		{" * as ns ", []string{"ns"}, nil},
		{" _, { merge as m, get } ", []string{"_"}, []string{"merge", "get"}},
		{" { default as lodash } ", []string{"lodash"}, nil},
		{" { type Foo, bar } ", nil, []string{"bar"}},
		{" { a, b, c } ", nil, []string{"a", "b", "c"}},
		{" d, * as ns ", []string{"d", "ns"}, nil},
	}
	for _, tc := range cases {
		receivers, named := parseNpmImportClause(tc.clause)
		if !reflect.DeepEqual(receivers, tc.receivers) {
			t.Errorf("receivers for %q = %v, want %v", tc.clause, receivers, tc.receivers)
		}
		if !reflect.DeepEqual(named, tc.named) {
			t.Errorf("named for %q = %v, want %v", tc.clause, named, tc.named)
		}
	}
}

func TestParseNpmSymbolSelectors(t *testing.T) {
	t.Parallel()
	valid, malformed := parseNpmSymbolSelectors([]string{
		"defaultsDeep", "_.merge", "auth.api.removeUser", "$.extend",
		"a.b.c.d", "not-an-ident!", "", "  ", "defaultsDeep", // dup skipped
	})
	if len(valid) != 4 {
		t.Fatalf("valid count = %d, want 4: %+v", len(valid), valid)
	}
	if valid[0].full != "defaultsDeep" {
		t.Errorf("valid[0] = %q, want defaultsDeep", valid[0].full)
	}
	if !reflect.DeepEqual(valid[1].parts, []string{"_", "merge"}) {
		t.Errorf("valid[1].parts = %v", valid[1].parts)
	}
	if valid[2].leaf() != "removeUser" {
		t.Errorf("valid[2].leaf() = %q, want removeUser", valid[2].leaf())
	}
	if valid[3].full != "$.extend" {
		t.Errorf("valid[3] = %q, want $.extend", valid[3].full)
	}
	if !reflect.DeepEqual(malformed, []string{"a.b.c.d", "not-an-ident!"}) {
		t.Errorf("malformed = %v", malformed)
	}
}

func TestStripJSComments(t *testing.T) {
	t.Parallel()
	src := "const a = require('x'); // require('gone')\n" +
		"/* require('also-gone') */\n" +
		"const url = 'http://not-a-comment';\n" +
		"const s = \"//still-a-string\";\n"
	out := stripJSComments(src)
	if len(out) != len(src) {
		t.Errorf("length changed: %d != %d (offsets must be preserved)", len(out), len(src))
	}
	if !strings.Contains(out, "require('x')") {
		t.Error("code before comment must survive")
	}
	if strings.Contains(out, "gone") {
		t.Error("comment content must be stripped")
	}
	if !strings.Contains(out, "http://not-a-comment") {
		t.Error("// inside a string literal must survive")
	}
	if !strings.Contains(out, "//still-a-string") {
		t.Error("// inside a double-quoted string must survive")
	}
}

func TestNpmLineIndex(t *testing.T) {
	t.Parallel()
	ix := newNpmLineIndex("ab\ncd\n\nef")
	if line, col := ix.locate(0); line != 1 || col != 1 {
		t.Errorf("locate(0) = %d:%d, want 1:1", line, col)
	}
	if line, col := ix.locate(4); line != 2 || col != 2 {
		t.Errorf("locate(4) = %d:%d, want 2:2", line, col)
	}
	if line, col := ix.locate(7); line != 4 || col != 1 {
		t.Errorf("locate(7) = %d:%d, want 4:1", line, col)
	}
}
