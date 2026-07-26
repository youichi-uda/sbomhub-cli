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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
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
	// Since M44 Phase D, a named import binding alone is NOT a symbol hit
	// (an unused import must stay import_only); the evidence points at the
	// USE site — the deepMerge(a, b) call on line 6 — not the import
	// statement on line 2.
	if symbols[0].FilePath != "src/esm_consumer.ts" || symbols[0].Line != 6 {
		t.Errorf("symbol evidence = %+v, want src/esm_consumer.ts line 6 (use site)", symbols[0])
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
	// Named bindings carry BOTH the original export name (selector matching
	// keys on it) and the local alias (M44 Phase D: use-site detection must
	// search the file for the LOCAL identifier — for `merge as m` an unused
	// `merge` string proves nothing, only uses of `m` do).
	cases := []struct {
		clause    string
		receivers []string
		named     []npmNamedImport
	}{
		{" _ ", []string{"_"}, nil},
		{" * as ns ", []string{"ns"}, nil},
		{" _, { merge as m, get } ", []string{"_"},
			[]npmNamedImport{{orig: "merge", local: "m"}, {orig: "get", local: "get"}}},
		{" { default as lodash } ", []string{"lodash"}, nil},
		{" { type Foo, bar } ", nil, []npmNamedImport{{orig: "bar", local: "bar"}}},
		{" { a, b, c } ", nil,
			[]npmNamedImport{{orig: "a", local: "a"}, {orig: "b", local: "b"}, {orig: "c", local: "c"}}},
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

// ---------------------------------------------------------------------------
// M44 Phase D round 1 regression tests (R2a: findings 1-5), ported from the
// backend suite to the CLI's stdlib-testing convention.
// ---------------------------------------------------------------------------

// npmWriteFile writes one file under root, creating parent directories.
func npmWriteFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestNpmAnalyze_SymlinksNotFollowed guards the size-cap bypass (finding 1):
// d.Info() on a symlink reports the LINK's own lstat size, so before the fix
// a tiny symlink pointing at a huge file (or an unbounded device node like
// /dev/zero) passed the npmMaxFileSizeBytes gate and os.ReadFile read the
// TARGET — an unbounded-read DoS plus a false-positive vector (the target's
// content influenced the verdict). Symlinks (file and directory alike) must
// be skipped; only symlinks with a SOURCE-FILE extension — the ones that
// would have been scan candidates as regular files — are counted in the
// informational note (round-2 finding 4: counting directory links and
// non-source links too overstated the note).
func TestNpmAnalyze_SymlinksNotFollowed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()

	npmWriteFile(t, root, "package.json", `{"dependencies": {"acme-lodash": "^4.17.0"}}`)
	npmWriteFile(t, root, "package-lock.json", `{
		"lockfileVersion": 3,
		"packages": {"node_modules/acme-lodash": {"version": "4.17.21"}}
	}`)

	// Big REGULAR target outside the project: vulnerable-looking code on
	// top, padded past npmMaxFileSizeBytes so a direct in-tree copy would be
	// size-capped — only the symlink's small lstat size lets it through.
	vuln := "const _ = require('acme-lodash');\n_.defaultsDeep({}, {});\n"
	big := vuln + strings.Repeat("// pad\n", npmMaxFileSizeBytes/7+1024)
	npmWriteFile(t, outside, "big_target.js", big)

	if err := os.Symlink(filepath.Join(outside, "big_target.js"),
		filepath.Join(root, "big_link.js")); err != nil {
		t.Skipf("cannot create symlinks on this platform: %v", err)
	}
	wantSymlinks := 1

	// Directory symlink: WalkDir surfaces it as a non-dir entry; it must
	// not be followed (and never was), but its basename has no source
	// extension, so it was never a scan candidate and must NOT be counted.
	npmWriteFile(t, outside, "linked_dir/inner.js", vuln)
	if err := os.Symlink(filepath.Join(outside, "linked_dir"),
		filepath.Join(root, "linked_dir")); err != nil {
		t.Fatal(err)
	}

	// Non-source file symlink (README/asset links, .bin shims and the like):
	// skipped, but not a candidate — must NOT be counted either.
	npmWriteFile(t, outside, "notes.txt", "plain text\n")
	if err := os.Symlink(filepath.Join(outside, "notes.txt"),
		filepath.Join(root, "notes_link.txt")); err != nil {
		t.Fatal(err)
	}

	// Unbounded device node, when the platform has one: before the fix,
	// os.ReadFile on this link never terminated (R1 reproduced the DoS).
	// Its .js name makes it a would-be candidate, so it IS counted.
	if _, err := os.Stat("/dev/zero"); err == nil {
		if err := os.Symlink("/dev/zero", filepath.Join(root, "zero_link.js")); err != nil {
			t.Fatal(err)
		}
		wantSymlinks++
	}

	res := npmMustAnalyze(t, &NpmAnalyzer{}, root,
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"defaultsDeep"},
		})
	if res.Status != StatusImportOnly {
		t.Errorf("Status = %q, want %q (symlinked content must not influence the verdict)",
			res.Status, StatusImportOnly)
	}
	for _, e := range res.Evidence {
		for _, banned := range []string{"big_link", "zero_link", "linked_dir", "notes_link"} {
			if strings.Contains(e.FilePath, banned) {
				t.Errorf("evidence leaked from a symlink: %+v", e)
			}
		}
	}
	if !npmHasDescription(res, fmt.Sprintf("%d symlink(s) with source-file extensions skipped", wantSymlinks)) {
		t.Errorf("expected a %d-symlink note, got %+v", wantSymlinks, res.Evidence)
	}
}

// TestNpmAnalyze_StringLiteralContentIgnored guards finding 2: require()/
// import statements and member-call text inside '…'/"…" string literals and
// template-literal text must produce neither import evidence/bindings nor
// symbol hits (docstrings and log messages were a false-reachable vector —
// the analyzer's error budget is false-negative-only). Code inside
// template-literal ${...} interpolations is real code and must keep
// matching.
func TestNpmAnalyze_StringLiteralContentIgnored(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	npmWriteFile(t, root, "package.json",
		`{"dependencies": {"acme-lodash": "^1.0.0", "acme-str-only": "^1.0.0", "acme-tpl-pkg": "^1.0.0"}}`)
	npmWriteFile(t, root, "src/strings.js",
		"const _ = require('acme-lodash');\n"+
			"\n"+
			"const doc = \"call require('acme-str-only') then _.merge(a, b)\";\n"+
			"const doc2 = 'single: require(\"acme-str-only\") and _.merge(';\n"+
			"const tpl = `template: require('acme-str-only') and _.merge( text`;\n"+
			"\n"+
			"module.exports = { doc, doc2, tpl, _ };\n")
	npmWriteFile(t, root, "src/tpl_code.js",
		"const _ = require('acme-lodash');\n"+
			"export const msg = `sum: ${_.defaultsDeep({}, {})} via ${require('acme-tpl-pkg').x}`;\n")

	a := &NpmAnalyzer{}

	// (a) A package referenced ONLY inside string/template text: stage 2
	// must not see a source import at all.
	res := npmMustAnalyze(t, a, root,
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-str-only"},
			VulnerableSymbols: []string{"merge"},
		})
	if res.Status != StatusImportOnly {
		t.Errorf("Status = %q, want %q", res.Status, StatusImportOnly)
	}
	for _, e := range npmEvidenceOfKind(res, EvidenceKindImportPath) {
		if e.Line != 0 {
			t.Errorf("string-literal require must not yield source import evidence: %+v", e)
		}
	}
	if !npmHasDescription(res, "no first-party source file imports") {
		t.Errorf("expected the transitive/unused note, got %+v", res.Evidence)
	}

	// (b) A really-imported package whose symbol appears only inside
	// string/template text: must stay import_only, not reachable.
	res = npmMustAnalyze(t, a, root,
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"merge", "_.merge"},
		})
	if res.Status != StatusImportOnly {
		t.Errorf("Status = %q, want %q (symbol text inside string literals must not hit)",
			res.Status, StatusImportOnly)
	}
	if n := len(npmEvidenceOfKind(res, EvidenceKindSymbolRef)); n != 0 {
		t.Errorf("symbol evidence count = %d, want 0", n)
	}

	// (c) Code inside a template-literal ${...} interpolation IS code:
	// the member call must be found.
	res = npmMustAnalyze(t, a, root,
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"defaultsDeep"},
		})
	if res.Status != StatusReachable {
		t.Errorf("Status = %q, want %q (member call inside ${...} must stay detectable)",
			res.Status, StatusReachable)
	}
	symbols := npmEvidenceOfKind(res, EvidenceKindSymbolRef)
	if len(symbols) != 1 || symbols[0].FilePath != "src/tpl_code.js" {
		t.Errorf("symbol evidence = %+v, want one hit in src/tpl_code.js", symbols)
	}

	// (d) require() inside a ${...} interpolation is a real import.
	res = npmMustAnalyze(t, a, root,
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-tpl-pkg"},
		})
	if res.Status != StatusImportOnly {
		t.Errorf("Status = %q, want %q", res.Status, StatusImportOnly)
	}
	var tplImport bool
	for _, e := range npmEvidenceOfKind(res, EvidenceKindImportPath) {
		if e.FilePath == "src/tpl_code.js" {
			tplImport = true
		}
	}
	if !tplImport {
		t.Errorf("require inside ${...} must yield import evidence, got %+v", res.Evidence)
	}
}

// TestNpmAnalyze_DollarIdentifierSelectors guards finding 3: "$" is a legal
// JS identifier character but a regex anchor, so before the fix the
// member-call pattern was doubly broken — `$watch` became "end-of-line
// anchor + watch" (never matches) and the leading `\b` DEMANDED a word char
// before a `$` receiver, so `$.ajax(` at statement start never matched while
// `x$.ajax(` (a different identifier) falsely did.
func TestNpmAnalyze_DollarIdentifierSelectors(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	npmWriteFile(t, root, "package.json",
		`{"dependencies": {"acme-jquery": "^1.0.0", "acme-vue": "^1.0.0"}}`)
	npmWriteFile(t, root, "src/jq.js",
		"const $ = require('acme-jquery');\n"+
			"const x$ = { ajax() {} };\n"+
			"$.ajax({ url: '/api' });\n"+
			"x$.ajax({ url: '/decoy' });\n")
	npmWriteFile(t, root, "src/vue.js",
		"const svc = require('acme-vue');\n"+
			"svc.$watch('prop', () => {});\n")

	a := &NpmAnalyzer{}

	// `$` as the receiver: $.ajax( at statement start must match; the
	// x$.ajax( decoy (different identifier) must NOT.
	res := npmMustAnalyze(t, a, root,
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-jquery"},
			VulnerableSymbols: []string{"$.ajax"},
		})
	if res.Status != StatusReachable {
		t.Errorf("Status = %q, want %q", res.Status, StatusReachable)
	}
	symbols := npmEvidenceOfKind(res, EvidenceKindSymbolRef)
	if len(symbols) != 1 {
		t.Fatalf("symbol evidence count = %d, want exactly the $.ajax( call (not the x$.ajax( decoy): %+v",
			len(symbols), symbols)
	}
	if symbols[0].Line != 3 || symbols[0].Column != 1 {
		t.Errorf("symbol position = %d:%d, want 3:1", symbols[0].Line, symbols[0].Column)
	}

	// `$` inside the method name: svc.$watch( must match.
	res = npmMustAnalyze(t, a, root,
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-vue"},
			VulnerableSymbols: []string{"svc.$watch"},
		})
	if res.Status != StatusReachable {
		t.Errorf("Status = %q, want %q", res.Status, StatusReachable)
	}
	symbols = npmEvidenceOfKind(res, EvidenceKindSymbolRef)
	if len(symbols) != 1 || symbols[0].FilePath != "src/vue.js" || symbols[0].Line != 2 {
		t.Errorf("symbol evidence = %+v, want one hit in src/vue.js line 2", symbols)
	}
}

// TestNpmAnalyze_NamedImportRequiresUse guards finding 4: a named import /
// require-destructure binding of a vulnerable symbol is only a symbol
// reference when the LOCAL identifier is actually used outside binding
// declarations — either called (merge(...)) or referenced (arr.map(merge);
// a bare reference hands the function around, so it may execute). An import
// that is never used must stay import_only (false-positive direction
// otherwise) with an explanatory evidence note.
func TestNpmAnalyze_NamedImportRequiresUse(t *testing.T) {
	t.Parallel()
	analyze := func(t *testing.T, source string) *ReachabilityResult {
		t.Helper()
		root := t.TempDir()
		npmWriteFile(t, root, "package.json", `{"dependencies": {"acme-lodash": "^4.17.0"}}`)
		npmWriteFile(t, root, "src/app.js", source)
		return npmMustAnalyze(t, &NpmAnalyzer{}, root,
			ReachabilityInput{
				Ecosystem:         "npm",
				VulnerableModules: []string{"acme-lodash"},
				VulnerableSymbols: []string{"merge"},
			})
	}

	t.Run("unused named import is import_only with note", func(t *testing.T) {
		res := analyze(t, "import { merge } from 'acme-lodash';\nexport const answer = 42;\n")
		if res.Status != StatusImportOnly {
			t.Errorf("Status = %q, want %q", res.Status, StatusImportOnly)
		}
		if n := len(npmEvidenceOfKind(res, EvidenceKindSymbolRef)); n != 0 {
			t.Errorf("symbol evidence count = %d, want 0", n)
		}
		if !npmHasDescription(res, "binding imported but no use found") {
			t.Errorf("expected the unused-binding note, got %+v", res.Evidence)
		}
	})

	t.Run("call is reachable", func(t *testing.T) {
		res := analyze(t, "import { merge } from 'acme-lodash';\nmerge({}, {});\n")
		if res.Status != StatusReachable {
			t.Fatalf("Status = %q, want %q", res.Status, StatusReachable)
		}
		symbols := npmEvidenceOfKind(res, EvidenceKindSymbolRef)
		if len(symbols) != 1 || symbols[0].Line != 2 {
			t.Errorf("symbol evidence = %+v, want one hit on line 2 (use site)", symbols)
		}
		if !strings.Contains(symbols[0].Description, "named import binding") {
			t.Errorf("Description = %q, want named-import-binding mention", symbols[0].Description)
		}
	})

	t.Run("bare reference (callback passing) is reachable", func(t *testing.T) {
		res := analyze(t, "import { merge } from 'acme-lodash';\n"+
			"export const out = [1].map(merge);\n")
		if res.Status != StatusReachable {
			t.Errorf("Status = %q, want %q", res.Status, StatusReachable)
		}
	})

	t.Run("aliased import matched via alias use", func(t *testing.T) {
		res := analyze(t, "import { merge as m } from 'acme-lodash';\nm({}, {});\n")
		if res.Status != StatusReachable {
			t.Errorf("Status = %q, want %q", res.Status, StatusReachable)
		}
	})

	t.Run("aliased import not matched by same-named local fn", func(t *testing.T) {
		// The vulnerable binding's LOCAL name is m; a different local
		// function that happens to be called merge must not count.
		res := analyze(t, "import { merge as m } from 'acme-lodash';\n"+
			"const merge = () => {};\nmerge();\n")
		if res.Status != StatusImportOnly {
			t.Errorf("Status = %q, want %q", res.Status, StatusImportOnly)
		}
	})

	t.Run("unused require destructure is import_only", func(t *testing.T) {
		res := analyze(t, "const { merge } = require('acme-lodash');\nexport const answer = 42;\n")
		if res.Status != StatusImportOnly {
			t.Errorf("Status = %q, want %q", res.Status, StatusImportOnly)
		}
		if !npmHasDescription(res, "binding imported but no use found") {
			t.Errorf("expected the unused-binding note, got %+v", res.Evidence)
		}
	})

	t.Run("object-literal key is not a use", func(t *testing.T) {
		res := analyze(t, "import { merge } from 'acme-lodash';\n"+
			"export const o = { merge: 1 };\n")
		if res.Status != StatusImportOnly {
			t.Errorf("Status = %q, want %q", res.Status, StatusImportOnly)
		}
	})
}

// TestNpmAnalyze_UnicodeIdentifierSelector guards finding 5: the server-side
// filter (isJSIdentifier) and the CLI filter (isJSIdentifierShaped) accept
// Unicode letters in selector parts, so the analyzer must too — before the
// fix the ASCII-only npmIdentRe silently dropped such selectors as
// "malformed" and the verdict degraded to import_only.
func TestNpmAnalyze_UnicodeIdentifierSelector(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	npmWriteFile(t, root, "package.json", `{"dependencies": {"acme-uni": "^1.0.0"}}`)
	npmWriteFile(t, root, "src/uni.js",
		"const café = require('acme-uni');\ncafé.parse('data');\n")

	res := npmMustAnalyze(t, &NpmAnalyzer{}, root,
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-uni"},
			VulnerableSymbols: []string{"café.parse"},
		})
	if res.Status != StatusReachable {
		t.Errorf("Status = %q, want %q", res.Status, StatusReachable)
	}
	if npmHasDescription(res, "malformed") {
		t.Errorf("a Unicode-letter selector must not be skipped as malformed: %+v", res.Evidence)
	}
	symbols := npmEvidenceOfKind(res, EvidenceKindSymbolRef)
	if len(symbols) != 1 || symbols[0].Symbol != "café.parse" || symbols[0].Line != 2 {
		t.Errorf("symbol evidence = %+v, want café.parse on line 2", symbols)
	}
}

func TestParseNpmSymbolSelectors_UnicodeIdentifiers(t *testing.T) {
	t.Parallel()
	valid, malformed := parseNpmSymbolSelectors([]string{
		"café.parse", "変数.メソッド", "1café",
	})
	if len(valid) != 2 {
		t.Fatalf("valid count = %d, want 2 (Unicode-letter selectors must parse): %+v (malformed %v)",
			len(valid), valid, malformed)
	}
	if valid[0].full != "café.parse" {
		t.Errorf("valid[0] = %q, want café.parse", valid[0].full)
	}
	if valid[1].leaf() != "メソッド" {
		t.Errorf("valid[1].leaf() = %q, want メソッド", valid[1].leaf())
	}
	if !reflect.DeepEqual(malformed, []string{"1café"}) {
		t.Errorf("malformed = %v, want [1café] (leading digit still malformed)", malformed)
	}
}

func TestStripJSCode_StringAndTemplateBlanking(t *testing.T) {
	t.Parallel()
	src := "const a = require('x');\n" +
		"const s = \"require('y') and _.merge(\";\n" +
		"const t = `text ${_.merge(a, b)} more ${`inner ${deep} rest`} end`;\n"
	stripped, codeOnly := stripJSCode(src)
	if len(stripped) != len(src) || len(codeOnly) != len(src) {
		t.Fatalf("lengths changed: stripped=%d codeOnly=%d src=%d (offsets must be preserved)",
			len(stripped), len(codeOnly), len(src))
	}
	// stripped keeps string content (import specifiers must stay readable).
	if !strings.Contains(stripped, "require('y')") {
		t.Error("stripped must keep string content")
	}
	// codeOnly blanks string bodies and template text…
	for _, gone := range []string{"require('y')", "text", "more", "inner", "end"} {
		if strings.Contains(codeOnly, gone) {
			t.Errorf("codeOnly must blank %q", gone)
		}
	}
	// …but keeps real code, including inside ${} interpolations (nested).
	for _, kept := range []string{"require(", "_.merge(a, b)", "deep"} {
		if !strings.Contains(codeOnly, kept) {
			t.Errorf("codeOnly must keep %q", kept)
		}
	}
	// Newlines survive so the line index still works.
	if strings.Count(codeOnly, "\n") != strings.Count(src, "\n") {
		t.Error("newlines must be preserved")
	}
}

// ---------------------------------------------------------------------------
// M44 Phase D round 2 regression tests (R3a: npm analyzer findings), kept in
// lockstep with the backend suite.
// ---------------------------------------------------------------------------

// TestNpmAnalyze_MethodDefinitionKeyNotAUse guards round-2 finding 1: an
// object-literal / class-body method DEFINITION key that happens to carry the
// vulnerable symbol's name (`const o = { merge() {…} }`) is not a use of the
// imported binding — before the fix the `merge(` text was read as a call and
// the verdict went false-reachable. The decisive shape is that the ')'
// matching the identifier's '(' is directly followed by '{' (a block never
// follows a call expression without a statement break), so real calls —
// including `foo(merge(1))` and `if (merge(x)) {`, whose extra ')' sits
// between the call's ')' and the '{' — keep matching.
func TestNpmAnalyze_MethodDefinitionKeyNotAUse(t *testing.T) {
	t.Parallel()
	analyze := func(t *testing.T, source string) *ReachabilityResult {
		t.Helper()
		root := t.TempDir()
		npmWriteFile(t, root, "package.json", `{"dependencies": {"acme-lodash": "^4.17.0"}}`)
		npmWriteFile(t, root, "src/app.js", source)
		return npmMustAnalyze(t, &NpmAnalyzer{}, root,
			ReachabilityInput{
				Ecosystem:         "npm",
				VulnerableModules: []string{"acme-lodash"},
				VulnerableSymbols: []string{"merge"},
			})
	}
	wantImportOnly := func(t *testing.T, res *ReachabilityResult) {
		t.Helper()
		if res.Status != StatusImportOnly {
			t.Errorf("Status = %q, want %q", res.Status, StatusImportOnly)
		}
		if n := len(npmEvidenceOfKind(res, EvidenceKindSymbolRef)); n != 0 {
			t.Errorf("symbol evidence count = %d, want 0: %+v",
				n, npmEvidenceOfKind(res, EvidenceKindSymbolRef))
		}
		if !npmHasDescription(res, "binding imported but no use found") {
			t.Errorf("expected the unused-binding note, got %+v", res.Evidence)
		}
	}

	t.Run("object method shorthand key is not a use", func(t *testing.T) {
		wantImportOnly(t, analyze(t,
			"import { merge } from 'acme-lodash';\n"+
				"const o = { merge(a, b) { return a; } };\n"+
				"export default o;\n"))
	})

	t.Run("async and getter shorthand keys are not uses", func(t *testing.T) {
		wantImportOnly(t, analyze(t,
			"import { merge } from 'acme-lodash';\n"+
				"const o = { async merge(a) { return a; } };\n"+
				"const p = { get merge() { return 1; } };\n"+
				"export default [o, p];\n"))
	})

	t.Run("class method key is not a use", func(t *testing.T) {
		wantImportOnly(t, analyze(t,
			"import { merge } from 'acme-lodash';\n"+
				"class C { merge(x) { return x; } }\n"+
				"export default C;\n"))
	})

	t.Run("Allman-style body brace on the next line is still a definition", func(t *testing.T) {
		wantImportOnly(t, analyze(t,
			"import { merge } from 'acme-lodash';\n"+
				"const o = { merge (a, b)\n"+
				"{ return a; } };\n"+
				"export default o;\n"))
	})

	t.Run("sloppy-mode function declaration is not a use", func(t *testing.T) {
		// var + function-declaration redeclaration is valid sloppy-mode JS;
		// the declaration's `merge(` must not read as a call of the binding.
		wantImportOnly(t, analyze(t,
			"var { merge } = require('acme-lodash');\n"+
				"function merge(a) { return a; }\n"))
	})

	t.Run("call in argument position is a use", func(t *testing.T) {
		res := analyze(t,
			"import { merge } from 'acme-lodash';\n"+
				"export const r = JSON.stringify(merge({}, {}));\n")
		if res.Status != StatusReachable {
			t.Errorf("Status = %q, want %q", res.Status, StatusReachable)
		}
	})

	t.Run("call in an if condition is a use", func(t *testing.T) {
		res := analyze(t,
			"import { merge } from 'acme-lodash';\n"+
				"if (merge({})) { console.log('hit'); }\n")
		if res.Status != StatusReachable {
			t.Errorf("Status = %q, want %q", res.Status, StatusReachable)
		}
	})

	t.Run("shorthand property value is still a use", func(t *testing.T) {
		// `{ merge }` REFERENCES the binding (hands the function around) —
		// the definition-key exclusion must not over-reach into it.
		res := analyze(t,
			"import { merge } from 'acme-lodash';\n"+
				"export const o = { merge };\n")
		if res.Status != StatusReachable {
			t.Errorf("Status = %q, want %q", res.Status, StatusReachable)
		}
	})
}

// TestNpmAnalyze_RegexLiteralStringParity guards round-2 finding 2 (R1b
// reproduced it live): stripJSCode did not model regex literals, so a quote
// or backtick INSIDE a regex (`/'/`, "/\\`/") opened a phantom string in
// codeOnly; the parity flip turned later real string text into phantom code
// and `_.merge(` inside a docstring became a false-reachable symbol hit.
// Regex literals are now lexed via a prev-token heuristic and blanked, while
// division expressions stay untouched.
func TestNpmAnalyze_RegexLiteralStringParity(t *testing.T) {
	t.Parallel()
	analyze := func(t *testing.T, source string, symbols []string) *ReachabilityResult {
		t.Helper()
		root := t.TempDir()
		npmWriteFile(t, root, "package.json", `{"dependencies": {"acme-lodash": "^4.17.0"}}`)
		npmWriteFile(t, root, "src/app.js", source)
		return npmMustAnalyze(t, &NpmAnalyzer{}, root,
			ReachabilityInput{
				Ecosystem:         "npm",
				VulnerableModules: []string{"acme-lodash"},
				VulnerableSymbols: symbols,
			})
	}
	wantImportOnly := func(t *testing.T, res *ReachabilityResult) {
		t.Helper()
		if res.Status != StatusImportOnly {
			t.Errorf("Status = %q, want %q", res.Status, StatusImportOnly)
		}
		if n := len(npmEvidenceOfKind(res, EvidenceKindSymbolRef)); n != 0 {
			t.Errorf("symbol evidence count = %d, want 0: %+v",
				n, npmEvidenceOfKind(res, EvidenceKindSymbolRef))
		}
	}

	t.Run("quote in regex must not turn a same-line string into code", func(t *testing.T) {
		// Same line matters: the string lexer resyncs at newlines, so the
		// R1b parity flip is confined to (and reproduced on) one line.
		wantImportOnly(t, analyze(t,
			"const _ = require('acme-lodash');\n"+
				"const esc = /'/; const doc = 'docs: _.merge(a, b) example';\n"+
				"module.exports = { _, esc, doc };\n",
			[]string{"merge", "_.merge"}))
	})

	t.Run("backtick in regex must not open a phantom template", func(t *testing.T) {
		// R1b: the parity flip from /\`/ swallowed the REAL template opener,
		// so the template's multi-line text body became phantom code.
		wantImportOnly(t, analyze(t,
			"const _ = require('acme-lodash');\n"+
				"const re = /\\`/;\n"+
				"const tpl = `multi\n"+
				"line _.merge(a, b) text\n"+
				"end`;\n"+
				"module.exports = { _, re, tpl };\n",
			[]string{"merge", "_.merge"}))
	})

	t.Run("regex as a call argument", func(t *testing.T) {
		wantImportOnly(t, analyze(t,
			"const _ = require('acme-lodash');\n"+
				"const out = 'x'.replace(/'/g, '-'); const doc = 'see _.merge(a, b)';\n"+
				"module.exports = { _, out, doc };\n",
			[]string{"merge", "_.merge"}))
	})

	t.Run("division is not misread as a regex", func(t *testing.T) {
		res := analyze(t,
			"const _ = require('acme-lodash');\n"+
				"const ratio = 10 / 2 / 5;\n"+
				"_.defaultsDeep({}, {});\n",
			[]string{"defaultsDeep"})
		if res.Status != StatusReachable {
			t.Fatalf("Status = %q, want %q (division must not blank following code)",
				res.Status, StatusReachable)
		}
		symbols := npmEvidenceOfKind(res, EvidenceKindSymbolRef)
		if len(symbols) != 1 || symbols[0].Line != 3 {
			t.Errorf("symbol evidence = %+v, want one hit on line 3", symbols)
		}
	})
}

func TestStripJSCode_RegexLiterals(t *testing.T) {
	t.Parallel()
	src := "const esc = /'/; const doc = 'STRTEXT _.merge(a, b)';\n" +
		"const re = /RXBODY[/]\\//gi;\n" +
		"const ratio = a / b / c;\n" +
		"return /'/.test(s) ? 1 : 0;\n"
	stripped, codeOnly := stripJSCode(src)
	if len(stripped) != len(src) || len(codeOnly) != len(src) {
		t.Fatalf("lengths changed: stripped=%d codeOnly=%d src=%d (offsets must be preserved)",
			len(stripped), len(codeOnly), len(src))
	}
	// The quote inside /'/ must not flip string parity: the next line's
	// string stays a string (blanked in codeOnly) and its declaration stays
	// code.
	for _, gone := range []string{"STRTEXT", "_.merge(", "RXBODY", "gi"} {
		if strings.Contains(codeOnly, gone) {
			t.Errorf("codeOnly must blank %q", gone)
		}
	}
	for _, kept := range []string{"const doc =", "a / b / c", ".test(s) ? 1 : 0"} {
		if !strings.Contains(codeOnly, kept) {
			t.Errorf("codeOnly must keep %q", kept)
		}
	}
	// stripped only blanks comments: string text stays readable there.
	if !strings.Contains(stripped, "STRTEXT") {
		t.Error("stripped must keep string content")
	}
	if strings.Count(codeOnly, "\n") != strings.Count(src, "\n") {
		t.Error("newlines must be preserved")
	}
}

// TestNpmAnalyze_ReadFailureDegradesConfidence guards the final-round Medium
// finding: a candidate source file that cannot be read (vanished, permission
// denied, or swapped mid-scan — see readFileInRoot) must never be skipped
// SILENTLY. Before the fix, making the single file that imports the
// vulnerable package unreadable produced a verdict indistinguishable from a
// clean negative (import_only at 0.60 plus the "no first-party source file
// imports" note): an attacker racing the scanner could yank the one file
// proving reachability and forge a clean result. Now the lost candidate is
// counted, surfaced as analyzer_error evidence, and import_only confidence
// drops to the degraded 0.50 tier (same as a failed source scan).
func TestNpmAnalyze_ReadFailureDegradesConfidence(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("0o000 file modes do not deny reads on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits are not enforced")
	}
	root := t.TempDir()
	npmWriteFile(t, root, "package.json", `{"dependencies": {"acme-lodash": "^4.17.0"}}`)
	npmWriteFile(t, root, "package-lock.json", `{
		"lockfileVersion": 3,
		"packages": {"node_modules/acme-lodash": {"version": "4.17.21"}}
	}`)
	// The ONLY file that imports the vulnerable package: would be reachable
	// if readable. Made unreadable to simulate the mid-scan loss.
	npmWriteFile(t, root, "src/only_consumer.js",
		"const _ = require('acme-lodash');\n_.defaultsDeep({}, {});\n")
	if err := os.Chmod(filepath.Join(root, "src", "only_consumer.js"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Join(root, "src", "only_consumer.js"), 0o644)
	})

	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), root,
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"defaultsDeep"},
		})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusImportOnly {
		t.Errorf("Status = %q, want %q (stage-1 graph hit stands)", res.Status, StatusImportOnly)
	}
	if res.Confidence < 0.499 || res.Confidence > 0.501 {
		t.Errorf("Confidence = %v, want 0.50 (a scan that LOST a candidate file must be degraded, not a clean 0.60)", res.Confidence)
	}
	if !npmHasDescription(res, "could not be securely read") {
		t.Errorf("expected a read-failure evidence note, got %+v", res.Evidence)
	}
}

// TestNpmAnalyze_ReadFailureKeepsReachableConfidence: read failures can only
// HIDE evidence, never mint it, so a reachable verdict backed by evidence
// from files that WERE read keeps its confidence — only the incompleteness
// note is added.
func TestNpmAnalyze_ReadFailureKeepsReachableConfidence(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("0o000 file modes do not deny reads on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits are not enforced")
	}
	root := t.TempDir()
	npmWriteFile(t, root, "package.json", `{"dependencies": {"acme-lodash": "^4.17.0"}}`)
	npmWriteFile(t, root, "package-lock.json", `{
		"lockfileVersion": 3,
		"packages": {"node_modules/acme-lodash": {"version": "4.17.21"}}
	}`)
	npmWriteFile(t, root, "src/consumer.js",
		"const _ = require('acme-lodash');\n_.defaultsDeep({}, {});\n")
	npmWriteFile(t, root, "src/lost.js",
		"const _ = require('acme-lodash');\n_.defaultsDeep({}, {});\n")
	if err := os.Chmod(filepath.Join(root, "src", "lost.js"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Join(root, "src", "lost.js"), 0o644)
	})

	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), root,
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"defaultsDeep"},
		})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusReachable {
		t.Errorf("Status = %q, want %q", res.Status, StatusReachable)
	}
	if res.Confidence < 0.699 || res.Confidence > 0.701 {
		t.Errorf("Confidence = %v, want 0.70 (found evidence stands on its own)", res.Confidence)
	}
	if !npmHasDescription(res, "could not be securely read") {
		t.Errorf("the incompleteness must still be recorded, got %+v", res.Evidence)
	}
}

// TestReadFileInRoot_SwapDetected guards the final-round High finding
// (TOCTOU): os.Root does NOT provide O_NOFOLLOW semantics on path components
// — symlinks whose targets stay INSIDE the root are followed (measured on
// go1.26.4; the canary subtest pins that fact so a future Go semantics
// change is noticed). A regular file swapped for an in-root symlink between
// the walker's lstat and the open therefore opens fine under os.Root alone;
// before the fix readFileInRoot returned the TARGET's content, letting an
// attacker smuggle node_modules code into the first-party scan (forging
// reachable evidence) or redirect the one file proving reachability at a
// harmless blob (hiding a real reachable). The fix detects the swap by
// identity: fstat of the opened handle must match the walk-time lstat
// (os.SameFile) and a post-open lstat must still name the same regular file.
func TestReadFileInRoot_SwapDetected(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	npmWriteFile(t, root, "node_modules/payload.js", "THIRD_PARTY")
	npmWriteFile(t, root, "src/a.js", "FIRST_PARTY")
	if err := os.Symlink("probe", filepath.Join(root, "symlink_probe")); err != nil {
		t.Skipf("cannot create symlinks on this platform: %v", err)
	}

	r, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	t.Run("canary: raw os.Root follows in-root symlinks", func(t *testing.T) {
		// Not a bug in os.Root — documented behaviour — but the fact the
		// fix exists for. If this subtest ever fails, os.Root stopped
		// following in-root links and the comments on readFileInRoot /
		// scanNpmSource should be revisited.
		npmWriteFile(t, root, "src/canary_target.js", "CANARY")
		if err := os.Symlink("canary_target.js",
			filepath.Join(root, "src", "canary_link.js")); err != nil {
			t.Fatal(err)
		}
		f, err := r.Open("src/canary_link.js")
		if err != nil {
			t.Fatalf("os.Root no longer follows in-root symlinks (%v): update the TOCTOU comments", err)
		}
		defer f.Close()
		data, err := io.ReadAll(f)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "CANARY" {
			t.Errorf("content = %q, want CANARY", string(data))
		}
	})

	t.Run("swap to in-root symlink rejected", func(t *testing.T) {
		target := filepath.Join(root, "src", "a.js")
		walkInfo, err := os.Lstat(target) // what WalkDir's d.Info() saw
		if err != nil {
			t.Fatal(err)
		}
		if !walkInfo.Mode().IsRegular() {
			t.Fatal("fixture must start as a regular file")
		}
		// The attack: between the walker's lstat and the open, the checked
		// regular file becomes a symlink to skipped third-party code whose
		// target stays inside the root.
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../node_modules/payload.js", target); err != nil {
			t.Fatal(err)
		}

		data, err := readFileInRoot(r, "src/a.js", walkInfo, npmMaxFileSizeBytes)
		if err == nil {
			t.Fatalf("in-root symlink swap must be detected, not followed; read %q", string(data))
		}
	})

	t.Run("swap to out-of-root symlink rejected", func(t *testing.T) {
		outside := t.TempDir()
		npmWriteFile(t, outside, "secret.js", "OUTSIDE")
		npmWriteFile(t, root, "src/b.js", "FIRST_PARTY")
		target := filepath.Join(root, "src", "b.js")
		walkInfo, err := os.Lstat(target)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(outside, "secret.js"), target); err != nil {
			t.Fatal(err)
		}

		data, err := readFileInRoot(r, "src/b.js", walkInfo, npmMaxFileSizeBytes)
		if err == nil {
			t.Fatalf("os.Root must refuse resolution escaping the root; read %q", string(data))
		}
	})

	t.Run("swap to different regular file rejected", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			// Documented residual: on Windows os.SameFile resolves the
			// walk-side file ID lazily from the PATH, so a regular→regular
			// replacement is content-change-equivalent and passes.
			t.Skip("regular-file replacement detection is Unix-only (see readFileInRoot)")
		}
		npmWriteFile(t, root, "src/c.js", "FIRST_PARTY")
		target := filepath.Join(root, "src", "c.js")
		walkInfo, err := os.Lstat(target)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
		npmWriteFile(t, root, "src/c.js", "REPLACEMENT")

		data, err := readFileInRoot(r, "src/c.js", walkInfo, npmMaxFileSizeBytes)
		if err == nil {
			t.Fatalf("identity (dev/inode) mismatch must be detected; read %q", string(data))
		}
	})

	t.Run("file over the limit at open time rejected", func(t *testing.T) {
		// Exercises the fstat size gate: the walker's lstat size check can
		// be stale (file grown after it), so readFileInRoot re-verifies
		// against the handle.
		npmWriteFile(t, root, "src/grown.js", "0123456789")
		walkInfo, err := os.Lstat(filepath.Join(root, "src", "grown.js"))
		if err != nil {
			t.Fatal(err)
		}
		data, err := readFileInRoot(r, "src/grown.js", walkInfo, 4)
		if err == nil {
			t.Fatalf("size must be re-verified on the opened handle; read %q", string(data))
		}
	})

	t.Run("unswapped file still reads", func(t *testing.T) {
		npmWriteFile(t, root, "src/ok.js", "LEGIT")
		walkInfo, err := os.Lstat(filepath.Join(root, "src", "ok.js"))
		if err != nil {
			t.Fatal(err)
		}
		data, err := readFileInRoot(r, "src/ok.js", walkInfo, npmMaxFileSizeBytes)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "LEGIT" {
			t.Errorf("content = %q, want LEGIT", string(data))
		}
	})
}
