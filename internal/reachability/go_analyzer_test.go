package reachability

// Smoke tests for the VENDORED Go reachability analyzer. Ported from the
// backend suite (sbomhub/apps/api/internal/service/reachability/
// go_analyzer_test.go) but rewritten to the CLI's stdlib-testing
// convention (the CLI does not vendor testify).
//
// The fixtures under testdata/ reference example.test/vulnpkg, a fake
// module that does not exist in the public proxy. We therefore drive the
// stage-1 module-graph logic through Analyze (which only reads go.mod when
// no vulnerable symbols are supplied — no packages.Load, no network) and
// exercise the AST symbol walk separately via inspectFileForSelectors
// against a directly-parsed fixture file. This keeps the suite offline-safe.

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyze_NotPresent(t *testing.T) {
	t.Parallel()
	a := &GoAnalyzer{}
	res, err := a.Analyze(context.Background(),
		"testdata/not_present_project",
		ReachabilityInput{
			AdvisoryID:        "GHSA-test-0001",
			Ecosystem:         "go",
			VulnerableModules: []string{"example.test/vulnpkg"},
		})
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if res == nil {
		t.Fatal("Analyze returned nil result")
	}
	if res.Status != StatusNotPresent {
		t.Errorf("Status = %q, want %q", res.Status, StatusNotPresent)
	}
	if res.Confidence != 0.90 {
		t.Errorf("Confidence = %v, want 0.90", res.Confidence)
	}
	if res.Ecosystem != "go" {
		t.Errorf("Ecosystem = %q, want go", res.Ecosystem)
	}
	if res.AnalyzerName != analyzerName {
		t.Errorf("AnalyzerName = %q, want %q", res.AnalyzerName, analyzerName)
	}
}

func TestAnalyze_ImportOnly_NoSymbols(t *testing.T) {
	t.Parallel()
	// With the vulnerable module in go.mod but no vulnerable symbols
	// supplied, Analyze stops at stage 1 (import presence) and never calls
	// packages.Load — so this is offline-safe and yields import_only.
	a := &GoAnalyzer{}
	res, err := a.Analyze(context.Background(),
		"testdata/import_only_project",
		ReachabilityInput{
			AdvisoryID:        "GHSA-test-0002",
			Ecosystem:         "go",
			VulnerableModules: []string{"example.test/vulnpkg"},
		})
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if res.Status != StatusImportOnly {
		t.Errorf("Status = %q, want %q", res.Status, StatusImportOnly)
	}
	if res.Confidence != 0.60 {
		t.Errorf("Confidence = %v, want 0.60", res.Confidence)
	}
	if len(res.Evidence) == 0 {
		t.Fatal("expected at least one evidence entry")
	}
	if res.Evidence[0].Kind != EvidenceKindImportPath {
		t.Errorf("Evidence[0].Kind = %q, want %q", res.Evidence[0].Kind, EvidenceKindImportPath)
	}
	if res.Evidence[0].ImportPath != "example.test/vulnpkg" {
		t.Errorf("Evidence[0].ImportPath = %q, want example.test/vulnpkg", res.Evidence[0].ImportPath)
	}
}

func TestAnalyze_UnknownOnEmptyProjectPath(t *testing.T) {
	t.Parallel()
	a := &GoAnalyzer{}
	res, err := a.Analyze(context.Background(), "  ",
		ReachabilityInput{
			Ecosystem:         "go",
			VulnerableModules: []string{"example.test/vulnpkg"},
		})
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if res.Status != StatusUnknown {
		t.Errorf("Status = %q, want %q", res.Status, StatusUnknown)
	}
	if res.Confidence != 0.0 {
		t.Errorf("Confidence = %v, want 0.0", res.Confidence)
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Kind != EvidenceKindAnalyzerError {
		t.Errorf("expected single analyzer_error evidence, got %#v", res.Evidence)
	}
}

func TestAnalyze_UnknownOnUnsupportedEcosystem(t *testing.T) {
	t.Parallel()
	a := &GoAnalyzer{}
	res, err := a.Analyze(context.Background(), "testdata/not_present_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"lodash"},
		})
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if res.Status != StatusUnknown {
		t.Errorf("Status = %q, want %q", res.Status, StatusUnknown)
	}
}

func TestAnalyze_UnknownOnMissingGoMod(t *testing.T) {
	t.Parallel()
	a := &GoAnalyzer{}
	res, err := a.Analyze(context.Background(),
		"testdata/__no_such_dir__",
		ReachabilityInput{
			Ecosystem:         "go",
			VulnerableModules: []string{"example.test/vulnpkg"},
		})
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if res.Status != StatusUnknown {
		t.Errorf("Status = %q, want %q", res.Status, StatusUnknown)
	}
}

func TestAnalyze_UnknownOnEmptyVulnerableModules(t *testing.T) {
	t.Parallel()
	a := &GoAnalyzer{}
	res, err := a.Analyze(context.Background(),
		"testdata/vulnerable_project",
		ReachabilityInput{Ecosystem: "go"})
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if res.Status != StatusUnknown {
		t.Errorf("Status = %q, want %q", res.Status, StatusUnknown)
	}
}

func TestAnalyze_NilContext(t *testing.T) {
	t.Parallel()
	a := &GoAnalyzer{}
	//nolint:staticcheck // intentionally passing nil to verify defensive check
	_, err := a.Analyze(nil, "testdata/not_present_project",
		ReachabilityInput{Ecosystem: "go", VulnerableModules: []string{"x"}})
	if err == nil {
		t.Fatal("expected error for nil context, got nil")
	}
}

func TestLoadModuleGraph_ReadsRequireBlock(t *testing.T) {
	t.Parallel()
	graph, err := loadModuleGraph("testdata/vulnerable_project")
	if err != nil {
		t.Fatalf("loadModuleGraph error: %v", err)
	}
	if _, ok := graph["example.test/vulnpkg"]; !ok {
		t.Errorf("graph missing example.test/vulnpkg: %#v", graph)
	}
}

// TestLoadModuleGraph_ReadsConfined guards the go.mod twin of the npm
// round-3 High finding (TestNpmDependencyGraph_ManifestReadsConfined):
// stage 1 read go.mod with a bare os.ReadFile — following a symlinked
// go.mod wherever it pointed (including OUT of the project root) with no
// size bound. go.mod is now read through readManifestInRoot, the same
// root-confined, symlink-refusing, size-capped read as the npm stage-1
// files ("go.mod" is a pure basename, so the lstat refusal covers the
// whole path within the root here too). A refused go.mod fails the
// module-graph load, and Analyze downgrades to unknown (loud) rather than
// producing a verdict from bytes the project directory does not actually
// contain.
func TestLoadModuleGraph_ReadsConfined(t *testing.T) {
	t.Parallel()

	input := ReachabilityInput{
		Ecosystem:         "go",
		VulnerableModules: []string{"example.test/vulnpkg"},
	}
	const goModBody = "module example.test/confined\n\nrequire example.test/vulnpkg v1.0.0\n"

	t.Run("out-of-root go.mod symlink refused", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		outside := t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, "go.mod"), []byte(goModBody), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(outside, "go.mod"),
			filepath.Join(root, "go.mod")); err != nil {
			t.Skipf("cannot create symlinks on this platform: %v", err)
		}

		// No VulnerableSymbols → Analyze stops after stage 1 (no
		// packages.Load), per this suite's offline convention.
		res, err := (&GoAnalyzer{}).Analyze(context.Background(), root, input)
		if err != nil {
			t.Fatalf("Analyze returned error: %v", err)
		}
		if res.Status != StatusUnknown {
			t.Errorf("Status = %q, want %q (out-of-root go.mod content must not enter the module graph)",
				res.Status, StatusUnknown)
		}
		if !npmHasDescription(res, "module graph load failed") {
			t.Errorf("expected a loud load failure, got %+v", res.Evidence)
		}
	})

	t.Run("in-root go.mod symlink refused", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "real_go.mod"), []byte(goModBody), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("real_go.mod", filepath.Join(root, "go.mod")); err != nil {
			t.Skipf("cannot create symlinks on this platform: %v", err)
		}

		res, err := (&GoAnalyzer{}).Analyze(context.Background(), root, input)
		if err != nil {
			t.Fatalf("Analyze returned error: %v", err)
		}
		if res.Status != StatusUnknown {
			t.Errorf("Status = %q, want %q (symlinked go.mod is refused even when the target stays in-root)",
				res.Status, StatusUnknown)
		}
		if !npmHasDescription(res, "module graph load failed") {
			t.Errorf("expected a loud load failure, got %+v", res.Evidence)
		}
	})

	t.Run("oversized go.mod refused at the cap", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		// Sparse file over the cap: fast to create. Unlike the npm
		// lockfile case, 64 MiB of NULs would not have parsed as a valid
		// go.mod anyway, so the discriminating assertion is the error
		// text: the read must be refused AT the cap, not performed
		// unboundedly and then rejected by the parser.
		f, err := os.Create(filepath.Join(root, "go.mod"))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(npmMaxManifestSizeBytes + 1); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}

		_, gerr := loadModuleGraph(root)
		if gerr == nil {
			t.Fatal("expected an error for an oversized go.mod")
		}
		if !strings.Contains(gerr.Error(), "-byte cap") {
			t.Errorf("error = %q, want the size-cap refusal, not a parse failure after an unbounded read", gerr)
		}
	})

	// Contract pin, green before and after the confinement change: an
	// absent go.mod must still surface as fs.ErrNotExist through the
	// wrapped error, matching the npm stage-1 absent-file handling.
	t.Run("absent go.mod still reports fs.ErrNotExist", func(t *testing.T) {
		t.Parallel()
		_, gerr := loadModuleGraph(t.TempDir())
		if gerr == nil {
			t.Fatal("expected an error for an absent go.mod")
		}
		if !errors.Is(gerr, fs.ErrNotExist) {
			t.Errorf("error = %v, want errors.Is(err, fs.ErrNotExist) (absent-file detection must survive the read-path change)", gerr)
		}
	})
}

func TestMatchModules(t *testing.T) {
	t.Parallel()
	graph := map[string]struct{}{
		"github.com/foo/bar":   {},
		"example.test/vulnpkg": {},
	}
	hits := matchModules(graph, []string{"example.test/vulnpkg", "missing/mod"})
	if len(hits) != 1 || hits[0] != "example.test/vulnpkg" {
		t.Errorf("matchModules = %#v, want [example.test/vulnpkg]", hits)
	}
}

func TestParseSymbolSelectors(t *testing.T) {
	t.Parallel()
	got, err := parseSymbolSelectors([]string{"yaml.Unmarshal", "sql.DB.Exec"})
	if err != nil {
		t.Fatalf("parseSymbolSelectors error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d selectors, want 2", len(got))
	}
	if got[0].pkg != "yaml" || got[0].leaf != "Unmarshal" {
		t.Errorf("selector[0] = %+v, want pkg=yaml leaf=Unmarshal", got[0])
	}
	if got[1].pkg != "sql" || got[1].leaf != "Exec" {
		t.Errorf("selector[1] = %+v, want pkg=sql leaf=Exec", got[1])
	}
	if _, err := parseSymbolSelectors([]string{"BareFunc"}); err == nil {
		t.Error("expected error for bare (unqualified) symbol, got nil")
	}
}

// TestInspectFile_Reachable exercises the stage-2 AST symbol walk against
// a directly-parsed fixture (no packages.Load), asserting the vulnerable
// symbol reference is found — the "reachable" evidence path.
func TestInspectFile_Reachable(t *testing.T) {
	t.Parallel()
	file, fset := parseFixture(t, "testdata/vulnerable_project/main.go")
	wanted, err := parseSymbolSelectors([]string{"vulnpkg.Unmarshal"})
	if err != nil {
		t.Fatalf("parseSymbolSelectors error: %v", err)
	}
	seen := map[string]struct{}{}
	hits := inspectFileForSelectors(fset, file, "main.go", wanted, seen)
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want exactly 1 for vulnpkg.Unmarshal", len(hits))
	}
	if hits[0].Kind != EvidenceKindSymbolRef {
		t.Errorf("Kind = %q, want %q", hits[0].Kind, EvidenceKindSymbolRef)
	}
	if hits[0].Symbol != "vulnpkg.Unmarshal" {
		t.Errorf("Symbol = %q, want vulnpkg.Unmarshal", hits[0].Symbol)
	}
	if hits[0].Line <= 0 || hits[0].Column <= 0 {
		t.Errorf("expected positive Line/Column, got %d:%d", hits[0].Line, hits[0].Column)
	}
}

// TestInspectFile_ImportOnly asserts a fixture that imports but never
// calls the vulnerable symbol yields no symbol_ref evidence.
func TestInspectFile_ImportOnly(t *testing.T) {
	t.Parallel()
	file, fset := parseFixture(t, "testdata/import_only_project/main.go")
	wanted, err := parseSymbolSelectors([]string{"vulnpkg.Unmarshal"})
	if err != nil {
		t.Fatalf("parseSymbolSelectors error: %v", err)
	}
	seen := map[string]struct{}{}
	hits := inspectFileForSelectors(fset, file, "main.go", wanted, seen)
	if len(hits) != 0 {
		t.Errorf("expected no hits for import-only fixture, got %#v", hits)
	}
}

func parseFixture(t *testing.T, path string) (*ast.File, *token.FileSet) {
	t.Helper()
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("abs(%q): %v", path, err)
	}
	fs := token.NewFileSet()
	parsed, err := parser.ParseFile(fs, abs, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %q: %v", abs, err)
	}
	return parsed, fs
}
