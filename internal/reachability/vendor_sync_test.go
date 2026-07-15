package reachability

// Divergence guard for the VENDORED analyzer sources (M43 Wave 4, F468,
// issue #170).
//
// types.go, go_analyzer.go and npm_analyzer.go in this package are faithful
// copies of the backend module's sbomhub/apps/api/internal/service/reachability/. The
// sync contract (see the header docstring in types.go) is: apart from the
// header comment block, the file bodies are byte-identical. This test
// enforces that contract so an edit applied to only one copy fails loudly
// on the next local `go test ./...` instead of silently drifting.
//
// Scope notes:
//
//   - Only the files listed in vendoredFiles (types.go, go_analyzer.go,
//     npm_analyzer.go) are compared. The _test.go files and testdata/
//     fixtures are intentionally divergent (the CLI uses stdlib testing,
//     the backend uses its own suite) and are NOT covered.
//   - "Header" is defined as: everything before the `package ` clause, plus
//     any contiguous run of blank / line-comment (`//`) lines immediately
//     after the package clause. That is exactly where the two copies are
//     allowed to differ today (types.go carries its vendoring docstring
//     above `package`, go_analyzer.go carries it right below `package`).
//     Everything from the first code line after the package clause down to
//     EOF must match byte for byte — a single-line body edit fails.
//   - This guard can only run where the sibling backend repo is checked
//     out (the sbom-all workspace layout). The CLI's CI checks out
//     sbomhub-cli alone, so the test skips there; it is a local-dev-only
//     divergence guard.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// vendoredFiles lists the files under the sync contract. Keep in sync with
// the vendoring note in types.go if more analyzer files are ever copied.
var vendoredFiles = []string{"types.go", "go_analyzer.go", "npm_analyzer.go"}

// stripVendorHeader returns the comparable body of a vendored source file:
// the `package ` clause line plus everything from the first non-blank,
// non-`//`-comment line after the package clause to EOF. Leading header
// comments (before `package`) and the contiguous comment/blank block
// immediately following the package clause are dropped — those regions
// intentionally differ between the backend original and the CLI copy.
//
// Limitations (documented, acceptable for a divergence guard): `/* ... */`
// block comments in the header region are not recognised (neither copy
// uses them today), and a comment sitting directly between `package` and
// the first code line is treated as header on both sides.
func stripVendorHeader(src string) (string, error) {
	lines := strings.Split(src, "\n")

	pkgIdx := -1
	for i, l := range lines {
		if strings.HasPrefix(l, "package ") {
			pkgIdx = i
			break
		}
	}
	if pkgIdx == -1 {
		return "", fmt.Errorf("no `package ` clause found")
	}

	// Skip the post-package header block: contiguous blank or //-comment
	// lines. The first remaining line is the start of the body proper.
	body := pkgIdx + 1
	for body < len(lines) {
		trimmed := strings.TrimSpace(lines[body])
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			body++
			continue
		}
		break
	}
	if body >= len(lines) {
		return "", fmt.Errorf("no body found after the package clause")
	}

	return lines[pkgIdx] + "\n" + strings.Join(lines[body:], "\n"), nil
}

// firstDiffLine reports the 1-based line number (within the normalised
// bodies) and the differing line pair of the first mismatch, for the
// failure message. Returns 0 if the bodies are equal.
func firstDiffLine(a, b string) (int, string, string) {
	al := strings.Split(a, "\n")
	bl := strings.Split(b, "\n")
	n := len(al)
	if len(bl) < n {
		n = len(bl)
	}
	for i := 0; i < n; i++ {
		if al[i] != bl[i] {
			return i + 1, al[i], bl[i]
		}
	}
	if len(al) != len(bl) {
		la, lb := "<EOF>", "<EOF>"
		if n < len(al) {
			la = al[n]
		}
		if n < len(bl) {
			lb = bl[n]
		}
		return n + 1, la, lb
	}
	return 0, "", ""
}

// TestVendoredAnalyzerInSyncWithBackend fails if the vendored analyzer
// sources in this package have drifted from the backend originals in
// sbomhub/apps/api/internal/service/reachability/ (header comments
// excluded, see stripVendorHeader).
func TestVendoredAnalyzerInSyncWithBackend(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed; cannot locate the vendored sources")
	}
	cliDir := filepath.Dir(thisFile)
	backendDir := filepath.Clean(filepath.Join(
		cliDir, "..", "..", "..",
		"sbomhub", "apps", "api", "internal", "service", "reachability"))

	if _, err := os.Stat(backendDir); err != nil {
		t.Skipf("sibling backend repo not found at %s (%v) — this is a "+
			"local-dev-only divergence guard: it needs the sbom-all "+
			"workspace layout with the sbomhub repo checked out next to "+
			"sbomhub-cli. CLI CI checks out sbomhub-cli alone, so skipping "+
			"there is expected.", backendDir, err)
	}

	for _, name := range vendoredFiles {
		t.Run(name, func(t *testing.T) {
			cliPath := filepath.Join(cliDir, name)
			backendPath := filepath.Join(backendDir, name)

			cliSrc, err := os.ReadFile(cliPath)
			if err != nil {
				t.Fatalf("read CLI copy %s: %v", cliPath, err)
			}
			backendSrc, err := os.ReadFile(backendPath)
			if err != nil {
				t.Fatalf("read backend original %s: %v", backendPath, err)
			}

			cliBody, err := stripVendorHeader(string(cliSrc))
			if err != nil {
				t.Fatalf("normalise CLI copy %s: %v", cliPath, err)
			}
			backendBody, err := stripVendorHeader(string(backendSrc))
			if err != nil {
				t.Fatalf("normalise backend original %s: %v", backendPath, err)
			}

			if cliBody != backendBody {
				line, cl, bl := firstDiffLine(cliBody, backendBody)
				t.Errorf("vendored %s has drifted from the backend original "+
					"(first difference at normalised-body line %d):\n"+
					"  CLI     (%s):\n    %q\n"+
					"  backend (%s):\n    %q\n\n"+
					"Recovery: the two copies must stay byte-identical apart "+
					"from their header comment blocks. Apply the SAME diff to "+
					"BOTH copies in a single commit (edit the backend file and "+
					"mirror the exact change into the CLI copy, or vice versa); "+
					"do not let either side evolve alone.",
					name, line, cliPath, cl, backendPath, bl)
			}
		})
	}
}

// --- SHA-256 pin check (C4a) -------------------------------------------
//
// Unlike TestVendoredAnalyzerInSyncWithBackend, the pin check needs no
// sibling repo: it recomputes the normalised-body SHA-256 of the vendored
// files in THIS package and compares against vendored.sha256. It therefore
// also runs in the CLI's solo CI, giving tamper-evidence against "edited a
// vendored file body without updating the pin". See vendored.sha256's header
// for exactly what the pin does and does NOT prove about cross-repo equality.

// vendoredBodyHash returns the hex SHA-256 of a vendored source file's
// normalised body (stripVendorHeader), matching how vendored.sha256 is
// generated.
func vendoredBodyHash(src string) (string, error) {
	body, err := stripVendorHeader(src)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:]), nil
}

// parsePinFile parses vendored.sha256 into filename -> expected hex hash.
// Blank lines and '#'-prefixed comment lines are ignored.
func parsePinFile(raw string) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) != 2 {
			return nil, fmt.Errorf("malformed pin line %q: want '<sha256>  <filename>'", line)
		}
		out[fields[1]] = fields[0]
	}
	return out, nil
}

// TestVendoredAnalyzerMatchesPin fails if any vendored source file's
// normalised-body SHA-256 has drifted from the pinned value in
// vendored.sha256 — i.e. someone edited a vendored file without updating the
// pin (or vice versa).
func TestVendoredAnalyzerMatchesPin(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed; cannot locate the vendored sources")
	}
	dir := filepath.Dir(thisFile)

	pinRaw, err := os.ReadFile(filepath.Join(dir, "vendored.sha256"))
	if err != nil {
		t.Fatalf("read pin file: %v", err)
	}
	pinned, err := parsePinFile(string(pinRaw))
	if err != nil {
		t.Fatalf("parse pin file: %v", err)
	}

	for _, name := range vendoredFiles {
		want, present := pinned[name]
		if !present {
			t.Errorf("vendored.sha256 has no pin entry for %s", name)
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		got, err := vendoredBodyHash(string(src))
		if err != nil {
			t.Errorf("hash %s: %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("vendored %s normalised-body SHA-256 has drifted from the "+
				"pin in vendored.sha256:\n  pinned: %s\n  actual: %s\n\n"+
				"If you intentionally changed the analyzer: apply the SAME diff "+
				"to BOTH repo copies, then update the '%s' line in vendored.sha256 "+
				"in BOTH repos to the actual hash above. If you did NOT mean to "+
				"change it, revert your edit.", name, want, got, name)
		}
	}

	// A pin entry with no matching vendored file means the two lists drifted.
	for name := range pinned {
		found := false
		for _, v := range vendoredFiles {
			if v == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("vendored.sha256 pins unknown file %q not in vendoredFiles", name)
		}
	}
}
