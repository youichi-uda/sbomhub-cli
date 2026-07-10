package api

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestGoModuleFromPurl(t *testing.T) {
	cases := []struct {
		name       string
		purl       string
		wantModule string
		wantOK     bool
	}{
		{"simple", "pkg:golang/example.test/vulnpkg@v1.0.0", "example.test/vulnpkg", true},
		{"major-version-suffix", "pkg:golang/github.com/jackc/pgx/v5@v5.5.0", "github.com/jackc/pgx/v5", true},
		{"qualifiers", "pkg:golang/github.com/foo/bar@v1.2.3?type=module", "github.com/foo/bar", true},
		{"subpath", "pkg:golang/github.com/foo/bar@v1.2.3#pkg/sub", "github.com/foo/bar", true},
		{"no-version", "pkg:golang/github.com/foo/bar", "github.com/foo/bar", true},
		{"bare-golang-prefix", "golang/github.com/foo/bar@v1", "github.com/foo/bar", true},
		{"non-golang-type", "pkg:npm/lodash@4.17.21", "", false},
		{"empty", "", "", false},
		{"garbage", "not-a-purl", "", false},
		// M43 Phase D R9: rows mirrored from the server-side derivation
		// table (apps/api/internal/handler/reachability_targets_test.go
		// TestGoModuleFromPurl) — the two implementations must stay in
		// lockstep or scoped vuln_funcs delivery silently degrades.
		{"stdlib", "pkg:golang/stdlib@go1.22.4", "stdlib", true},
		{"percent-encoded", "pkg:golang/github.com%2Fa%2Fb@v1.0.0", "github.com/a/b", true},
		{"whitespace", "  pkg:golang/github.com/a/b@v1  ", "github.com/a/b", true},
		{"type-case", "pkg:GOLANG/github.com/foo/bar@v1", "github.com/foo/bar", true},
		{"bare-type-case", "Golang/x", "x", true},
		{"path-case-preserved", "pkg:golang/github.com/Foo/Bar", "github.com/Foo/Bar", true},
		{"scheme-exact", "PKG:golang/github.com/a/b", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := goModuleFromPurl(tc.purl)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (module=%q)", ok, tc.wantOK, got)
			}
			if got != tc.wantModule {
				t.Errorf("module = %q, want %q", got, tc.wantModule)
			}
		})
	}
}

// TestNpmPackageFromPurl pins the CLI-side purl → npm package name
// derivation (M44 Wave 4 / F472). LOCKSTEP: this table is a replica of the
// server-side TestNpmPackageFromPurl
// (sbomhub apps/api/internal/handler/reachability_targets_test.go, M44
// Wave 3 / F471) — the server scopes each target row's vuln_funcs to the
// package its derivation yields, and the CLI matches the same purl against
// the local dependency graph, so the two implementations must stay in
// lockstep or scoped vuln_funcs delivery silently degrades.
func TestNpmPackageFromPurl(t *testing.T) {
	cases := []struct {
		purl string
		want string
		ok   bool
	}{
		{"pkg:npm/lodash@4.17.21", "lodash", true},
		// Scoped packages in every producer variant: fully encoded,
		// Syft-style (only the "@" encoded), and literal "@".
		{"pkg:npm/%40scope%2Fname@1.0.0", "@scope/name", true},
		{"pkg:npm/%40scope/name@1.0.0", "@scope/name", true},
		{"pkg:npm/@scope/name@1.0.0", "@scope/name", true},
		{"pkg:npm/@scope/name", "@scope/name", true},
		// Version absent / qualifiers / subpath cut points.
		{"pkg:npm/lodash", "lodash", true},
		{"pkg:npm/lodash?arch=amd64", "lodash", true},
		{"pkg:npm/lodash#sub/dir", "lodash", true},
		// Scheme-less producer tolerance (mirrors goModuleFromPurl).
		{"npm/lodash@1.0.0", "lodash", true},
		// The purl type is case-insensitive; the name keeps its case.
		{"pkg:NPM/lodash@4.17.21", "lodash", true},
		{"pkg:npm/jQuery@1.7.2", "jQuery", true},
		// Surrounding whitespace tolerated.
		{"  pkg:npm/lodash@4.17.21  ", "lodash", true},
		// The "pkg:" scheme stays exact-case (EcosystemFromPurl rejects
		// "PKG:" too, so such a row never reaches the scoped path).
		{"PKG:npm/lodash@4.17.21", "", false},
		// Not derivable: non-npm / malformed / empty — the caller skips
		// the target (no package coordinate).
		{"pkg:golang/github.com/a/b@v1.0.0", "", false},
		{"pkg:npm/", "", false},
		{"pkg:npm/@1.0.0", "", false},
		{"lodash@4.17.21", "", false},
		{"", "", false},
		{"   ", "", false},
	}
	for _, tc := range cases {
		got, ok := npmPackageFromPurl(tc.purl)
		if got != tc.want || ok != tc.ok {
			t.Errorf("npmPackageFromPurl(%q) = (%q, %v), want (%q, %v)", tc.purl, got, ok, tc.want, tc.ok)
		}
	}
}

// TestReachabilityTarget_VulnFuncsDecode pins the frozen M43 contract
// (issue #168): the targets response field is named exactly "vuln_funcs"
// and its entries decode verbatim into VulnFuncs.
func TestReachabilityTarget_VulnFuncsDecode(t *testing.T) {
	body := `{"targets":[{
		"cve_id":"CVE-2024-0001",
		"component_id":"aaaaaaaa-0000-0000-0000-000000000001",
		"purl":"pkg:golang/example.test/vulnpkg@v1.0.0",
		"component_name":"vulnpkg",
		"component_version":"v1.0.0",
		"ecosystem":"go",
		"vuln_funcs":["vulnpkg.Parse","vulnpkg.Decoder.Decode"]
	}]}`
	var out struct {
		Targets []ReachabilityTarget `json:"targets"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Targets) != 1 {
		t.Fatalf("targets len = %d, want 1", len(out.Targets))
	}
	got := out.Targets[0].VulnFuncs
	want := []string{"vulnpkg.Parse", "vulnpkg.Decoder.Decode"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("VulnFuncs = %#v, want %#v (frozen-contract field vuln_funcs)", got, want)
	}
}

// TestReachabilityTarget_VulnFuncsMissing_GracefulNil asserts the graceful
// degrade against pre-M43 servers: a target row without the vuln_funcs
// field (or with an explicit null) decodes to a nil slice, which the
// command then forwards as nil VulnerableSymbols → import_only granularity.
func TestReachabilityTarget_VulnFuncsMissing_GracefulNil(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			"field-absent-old-server",
			`{"targets":[{"cve_id":"CVE-2024-0001","component_id":"c1","purl":"pkg:golang/example.test/vulnpkg@v1.0.0","ecosystem":"go"}]}`,
		},
		{
			"explicit-null",
			`{"targets":[{"cve_id":"CVE-2024-0001","component_id":"c1","purl":"pkg:golang/example.test/vulnpkg@v1.0.0","ecosystem":"go","vuln_funcs":null}]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out struct {
				Targets []ReachabilityTarget `json:"targets"`
			}
			if err := json.Unmarshal([]byte(tc.body), &out); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(out.Targets) != 1 {
				t.Fatalf("targets len = %d, want 1", len(out.Targets))
			}
			if out.Targets[0].VulnFuncs != nil {
				t.Errorf("VulnFuncs = %#v, want nil (graceful degrade)", out.Targets[0].VulnFuncs)
			}
			// The rest of the row must still decode as before.
			if out.Targets[0].CVEID != "CVE-2024-0001" || out.Targets[0].ComponentID != "c1" {
				t.Errorf("row decode regressed: %+v", out.Targets[0])
			}
		})
	}
}

// TestReachabilityTarget_ModulePath pins the ecosystem dispatch (M44 Wave 4
// / F472): "go" — and "", the pre-ecosystem default every M32-era row and
// purl-less row carries — derive via goModuleFromPurl; "npm" derives via
// npmPackageFromPurl; any other ecosystem yields ("", false) because no
// analyzer consumes it yet.
func TestReachabilityTarget_ModulePath(t *testing.T) {
	cases := []struct {
		name       string
		tgt        ReachabilityTarget
		wantModule string
		wantOK     bool
	}{
		// Go rows (pre-M44 behavior, unchanged).
		{"go-purl-no-ecosystem", ReachabilityTarget{Purl: "pkg:golang/example.test/vulnpkg@v1.0.0"}, "example.test/vulnpkg", true},
		{"go-purl-go-ecosystem", ReachabilityTarget{Purl: "pkg:golang/example.test/vulnpkg@v1.0.0", Ecosystem: "go"}, "example.test/vulnpkg", true},
		{"empty-purl", ReachabilityTarget{Purl: "", ComponentName: "foo"}, "", false},
		// An npm purl WITHOUT the npm ecosystem token stays underivable —
		// exactly the M32 behavior (ecosystem "" defaults to the Go arm).
		{"npm-purl-no-ecosystem", ReachabilityTarget{Purl: "pkg:npm/lodash@4.17.21"}, "", false},

		// npm rows (M44 Wave 4 / F472).
		{"npm-plain", ReachabilityTarget{Purl: "pkg:npm/lodash@4.17.21", Ecosystem: "npm"}, "lodash", true},
		{"npm-scoped-fully-encoded", ReachabilityTarget{Purl: "pkg:npm/%40scope%2Fname@1.0.0", Ecosystem: "npm"}, "@scope/name", true},
		{"npm-scoped-syft-encoding", ReachabilityTarget{Purl: "pkg:npm/%40scope/name@1.0.0", Ecosystem: "npm"}, "@scope/name", true},
		{"npm-scoped-literal-at", ReachabilityTarget{Purl: "pkg:npm/@scope/name@1.0.0", Ecosystem: "npm"}, "@scope/name", true},
		{"npm-ecosystem-case-fold", ReachabilityTarget{Purl: "pkg:npm/lodash@4.17.21", Ecosystem: "NPM"}, "lodash", true},
		{"npm-empty-purl", ReachabilityTarget{Purl: "", Ecosystem: "npm"}, "", false},
		// Cross-wired rows (a conforming server never produces them).
		{"npm-ecosystem-go-purl", ReachabilityTarget{Purl: "pkg:golang/example.test/vulnpkg@v1.0.0", Ecosystem: "npm"}, "", false},
		{"go-ecosystem-npm-purl", ReachabilityTarget{Purl: "pkg:npm/lodash@4.17.21", Ecosystem: "go"}, "", false},

		// Unsupported ecosystems: no analyzer, no coordinate.
		{"maven", ReachabilityTarget{Purl: "pkg:maven/org.acme/thing@1.0.0", Ecosystem: "maven"}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := tc.tgt.ModulePath()
			if m != tc.wantModule || ok != tc.wantOK {
				t.Errorf("ModulePath() = (%q, %v), want (%q, %v)", m, ok, tc.wantModule, tc.wantOK)
			}
		})
	}
}
