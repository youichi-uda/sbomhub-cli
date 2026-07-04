package api

import "testing"

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

func TestReachabilityTarget_ModulePath(t *testing.T) {
	// A pkg:golang purl yields the module path.
	tgt := ReachabilityTarget{Purl: "pkg:golang/example.test/vulnpkg@v1.0.0"}
	m, ok := tgt.ModulePath()
	if m != "example.test/vulnpkg" || !ok {
		t.Errorf("ModulePath = (%q, %v), want (example.test/vulnpkg, true)", m, ok)
	}

	// Empty purl → no module (caller skips the target).
	tgt = ReachabilityTarget{Purl: "", ComponentName: "foo"}
	if m, ok := tgt.ModulePath(); ok || m != "" {
		t.Errorf("ModulePath = (%q, %v), want (\"\", false) for empty purl", m, ok)
	}

	// Non-golang purl → no module.
	tgt = ReachabilityTarget{Purl: "pkg:npm/lodash@4.17.21"}
	if m, ok := tgt.ModulePath(); ok || m != "" {
		t.Errorf("ModulePath = (%q, %v), want (\"\", false) for non-go purl", m, ok)
	}
}
