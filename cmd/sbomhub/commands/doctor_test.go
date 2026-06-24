package commands

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeDoctorConfig writes a config.yaml into dir for the doctor tests.
// Empty fields are omitted so we can exercise the "missing api_key" path.
func writeDoctorConfig(t *testing.T, dir, apiURL, apiKey string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	var b strings.Builder
	if apiURL != "" {
		b.WriteString("api_url: " + apiURL + "\n")
	}
	if apiKey != "" {
		b.WriteString("api_key: " + apiKey + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// findResult returns the first result with the given name, or nil.
func findResult(rs []doctorResult, name string) *doctorResult {
	for i := range rs {
		if rs[i].name == name {
			return &rs[i]
		}
	}
	return nil
}

// newTestHTTPClient returns an http.Client with a short timeout so cases that
// hit an unreachable address don't slow the suite to a crawl.
func newTestHTTPClient() *http.Client {
	return &http.Client{Timeout: 2 * time.Second}
}

// resetCredentialGlobals snapshots the package-level apiURL / apiKey vars and
// restores them after the test. The cobra flag layer writes into those vars
// at runtime, so per-test mutations (--api-key path in TestDoctor_FlagOnly...)
// would otherwise leak across the suite.
func resetCredentialGlobals(t *testing.T) {
	t.Helper()
	prevKey, prevURL := apiKey, apiURL
	t.Cleanup(func() {
		apiKey = prevKey
		apiURL = prevURL
	})
}

// clearCredentialEnv makes the credential env vars deterministically empty
// for the duration of the test. Without this, a developer running tests with
// SBOMHUB_API_KEY exported in their shell would silently change test
// behaviour now that resolveCredentials honours env vars.
func clearCredentialEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SBOMHUB_API_KEY", "")
	t.Setenv("SBOMHUB_API_URL", "")
}

func TestDoctor_NoConfig(t *testing.T) {
	dir := t.TempDir()
	resetCredentialGlobals(t)
	clearCredentialEnv(t)

	// Point the URL at a local stub so the api-reachability probe does not
	// hit the real SaaS endpoint over the network when no credentials are
	// configured. api_key is intentionally left unset to exercise the
	// "missing credential" path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	t.Setenv("SBOMHUB_API_URL", srv.URL)

	results := doctorChecks(dir, newTestHTTPClient(), false, false)

	cf := findResult(results, "config-file")
	if cf == nil {
		t.Fatalf("expected config-file result, got none: %+v", results)
	}
	if cf.status == doctorFail {
		t.Errorf("expected config-file non-FAIL (missing file should be informational), got %+v", cf)
	}
	if !strings.Contains(cf.message, "設定ファイル無し") {
		t.Errorf("expected config-file message to indicate missing file, got: %s", cf.message)
	}

	ak := findResult(results, "api-key")
	if ak == nil || ak.status != doctorFail {
		t.Errorf("expected api-key FAIL when no credentials supplied, got %+v", ak)
	}
	if ak != nil && !strings.Contains(ak.message, "SBOMHUB_API_KEY") {
		t.Errorf("expected api-key FAIL message to mention env / flag fallback, got: %s", ak.message)
	}

	if av := findResult(results, "auth-verify"); av != nil {
		t.Errorf("auth-verify should be skipped when api_key empty, got %+v", av)
	}
}

func TestDoctor_ConfigPresentNoAPIKey(t *testing.T) {
	dir := t.TempDir()
	resetCredentialGlobals(t)
	clearCredentialEnv(t)

	// Stand up a server that answers /health so reachability is OK, and would
	// have answered /cli/projects too — but doctorChecks must skip the auth
	// probe entirely when api_key is empty.
	var authProbeCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/health":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/v1/cli/projects":
			authProbeCount++
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	writeDoctorConfig(t, dir, srv.URL, "")
	results := doctorChecks(dir, newTestHTTPClient(), false, false)

	apiKey := findResult(results, "api-key")
	if apiKey == nil || apiKey.status != doctorFail {
		t.Errorf("expected api-key FAIL, got %+v", apiKey)
	}
	if reach := findResult(results, "api-reachability"); reach == nil || reach.status != doctorOK {
		t.Errorf("expected api-reachability OK, got %+v", reach)
	}
	if auth := findResult(results, "auth-verify"); auth != nil {
		t.Errorf("auth-verify should be skipped when api_key empty, got %+v", auth)
	}
	if authProbeCount != 0 {
		t.Errorf("server should not have received auth probe, got %d hits", authProbeCount)
	}
}

func TestDoctor_FullyOK(t *testing.T) {
	dir := t.TempDir()
	resetCredentialGlobals(t)
	clearCredentialEnv(t)
	const validKey = "sbh_abcd1234validtoken"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/health":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","mode":"production"}`))
		case "/api/v1/cli/projects":
			if r.Header.Get("Authorization") != "Bearer "+validKey {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"projects":[],"total":0}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	writeDoctorConfig(t, dir, srv.URL, validKey)
	results := doctorChecks(dir, newTestHTTPClient(), false, false)

	for _, r := range results {
		// Scanner detection depends on the host environment; ignore it here.
		if r.name == "scanners" {
			continue
		}
		if r.status == doctorFail {
			t.Errorf("unexpected FAIL on %s: %s", r.name, r.message)
		}
	}
	for _, name := range []string{"config-file", "api-key", "api-url", "api-reachability", "auth-verify"} {
		got := findResult(results, name)
		if got == nil {
			t.Errorf("expected result %q in output", name)
			continue
		}
		if got.status != doctorOK {
			t.Errorf("expected %q OK, got %v: %s", name, got.status, got.message)
		}
	}
	// Source attribution: api_key and api_url both came from the config file.
	if ak := findResult(results, "api-key"); ak != nil && !strings.Contains(ak.message, "source: config") {
		t.Errorf("expected api-key source=config, got: %s", ak.message)
	}
	if au := findResult(results, "api-url"); au != nil && !strings.Contains(au.message, "source: config") {
		t.Errorf("expected api-url source=config, got: %s", au.message)
	}

	// Also verify runDoctorWith returns nil and prints all lines.
	var buf bytes.Buffer
	if err := runDoctorWith(&buf, dir, newTestHTTPClient(), false, false, false); err != nil {
		t.Errorf("runDoctorWith returned error: %v\noutput:\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "[OK]") {
		t.Errorf("expected at least one [OK] in output, got:\n%s", buf.String())
	}
}

func TestDoctor_AuthFails(t *testing.T) {
	dir := t.TempDir()
	resetCredentialGlobals(t)
	clearCredentialEnv(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/health":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/v1/cli/projects":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid api key"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	writeDoctorConfig(t, dir, srv.URL, "sbh_revokedtoken")
	results := doctorChecks(dir, newTestHTTPClient(), false, false)

	if reach := findResult(results, "api-reachability"); reach == nil || reach.status != doctorOK {
		t.Errorf("expected reachability OK, got %+v", reach)
	}
	auth := findResult(results, "auth-verify")
	if auth == nil || auth.status != doctorFail {
		t.Errorf("expected auth-verify FAIL, got %+v", auth)
	}

	// runDoctorWith must return an error so main exits 1.
	var buf bytes.Buffer
	if err := runDoctorWith(&buf, dir, newTestHTTPClient(), false, false, false); err == nil {
		t.Errorf("runDoctorWith returned nil despite FAIL; output:\n%s", buf.String())
	}
}

func TestDoctor_APIUnreachable(t *testing.T) {
	dir := t.TempDir()
	resetCredentialGlobals(t)
	clearCredentialEnv(t)

	// Spin up a server and close it immediately so the URL is well-formed but
	// no socket is listening. Use 127.0.0.1 so the OS returns ECONNREFUSED
	// (fast) rather than letting us wait on a routing timeout.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := srv.URL
	srv.Close()

	writeDoctorConfig(t, dir, deadURL, "sbh_validkey")
	results := doctorChecks(dir, newTestHTTPClient(), false, false)

	reach := findResult(results, "api-reachability")
	if reach == nil || reach.status != doctorFail {
		t.Errorf("expected api-reachability FAIL, got %+v", reach)
	}
	// auth-verify also tries the same dead URL — must FAIL, not panic.
	auth := findResult(results, "auth-verify")
	if auth == nil || auth.status != doctorFail {
		t.Errorf("expected auth-verify FAIL, got %+v", auth)
	}
}

// TestDoctor_EnvOnlyNoConfigFile covers the CI shape: no `sbomhub login` has
// ever run, only SBOMHUB_API_URL / SBOMHUB_API_KEY are set. Before R10 the
// doctor short-circuited on the missing config file and reported [FAIL],
// which made `SBOMHUB_API_KEY=... sbomhub doctor` unusable as a CI gate.
func TestDoctor_EnvOnlyNoConfigFile(t *testing.T) {
	dir := t.TempDir()
	resetCredentialGlobals(t)
	const envKey = "sbh_envonlytoken1234"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/health":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/v1/cli/projects":
			if r.Header.Get("Authorization") != "Bearer "+envKey {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"projects":[],"total":0}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("SBOMHUB_API_KEY", envKey)
	t.Setenv("SBOMHUB_API_URL", srv.URL)

	results := doctorChecks(dir, newTestHTTPClient(), false, false)

	cf := findResult(results, "config-file")
	if cf == nil || cf.status == doctorFail {
		t.Errorf("expected config-file non-FAIL with INFO-style message, got %+v", cf)
	}
	if cf != nil && !strings.Contains(cf.message, "設定ファイル無し") {
		t.Errorf("expected message about missing file, got: %s", cf.message)
	}

	ak := findResult(results, "api-key")
	if ak == nil || ak.status != doctorOK {
		t.Errorf("expected api-key OK from env, got %+v", ak)
	} else if !strings.Contains(ak.message, "source: env") {
		t.Errorf("expected api-key source=env, got: %s", ak.message)
	}

	au := findResult(results, "api-url")
	if au == nil || au.status != doctorOK {
		t.Errorf("expected api-url OK from env, got %+v", au)
	} else if !strings.Contains(au.message, "source: env") {
		t.Errorf("expected api-url source=env, got: %s", au.message)
	}

	if av := findResult(results, "auth-verify"); av == nil || av.status != doctorOK {
		t.Errorf("expected auth-verify OK against the env-supplied URL, got %+v", av)
	}

	// runDoctorWith must succeed (no FAIL → no error).
	var buf bytes.Buffer
	if err := runDoctorWith(&buf, dir, newTestHTTPClient(), false, false, false); err != nil {
		t.Errorf("runDoctorWith returned error for env-only setup: %v\noutput:\n%s", err, buf.String())
	}
}

// TestDoctor_FlagOnlyNoConfigFile covers the ad-hoc shape: no config file, no
// env, the operator invoked `sbomhub doctor --api-url=... --api-key=...`. The
// flag-set globals are mutated directly here; resetCredentialGlobals restores
// them for the next test.
func TestDoctor_FlagOnlyNoConfigFile(t *testing.T) {
	dir := t.TempDir()
	resetCredentialGlobals(t)
	clearCredentialEnv(t)
	const flagKey = "sbh_flagonlytoken1234"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/health":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/v1/cli/projects":
			if r.Header.Get("Authorization") != "Bearer "+flagKey {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"projects":[],"total":0}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	apiKey = flagKey
	apiURL = srv.URL

	results := doctorChecks(dir, newTestHTTPClient(), true, true)

	cf := findResult(results, "config-file")
	if cf == nil || cf.status == doctorFail {
		t.Errorf("expected config-file non-FAIL, got %+v", cf)
	}

	ak := findResult(results, "api-key")
	if ak == nil || ak.status != doctorOK {
		t.Errorf("expected api-key OK from flag, got %+v", ak)
	} else if !strings.Contains(ak.message, "source: flag") {
		t.Errorf("expected api-key source=flag, got: %s", ak.message)
	}

	au := findResult(results, "api-url")
	if au == nil || au.status != doctorOK {
		t.Errorf("expected api-url OK from flag, got %+v", au)
	} else if !strings.Contains(au.message, "source: flag") {
		t.Errorf("expected api-url source=flag, got: %s", au.message)
	}

	if av := findResult(results, "auth-verify"); av == nil || av.status != doctorOK {
		t.Errorf("expected auth-verify OK against flag-supplied URL, got %+v", av)
	}

	var buf bytes.Buffer
	if err := runDoctorWith(&buf, dir, newTestHTTPClient(), false, true, true); err != nil {
		t.Errorf("runDoctorWith returned error for flag-only setup: %v\noutput:\n%s", err, buf.String())
	}
}
