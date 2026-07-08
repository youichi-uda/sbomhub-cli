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
