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

func TestDoctor_NoConfig(t *testing.T) {
	dir := t.TempDir()
	results := doctorChecks(dir, newTestHTTPClient())

	if len(results) != 1 {
		t.Fatalf("expected 1 result when config missing, got %d: %+v", len(results), results)
	}
	r := results[0]
	if r.status != doctorFail {
		t.Errorf("expected FAIL, got %v: %s", r.status, r.message)
	}
	if !strings.Contains(r.message, "sbomhub login") {
		t.Errorf("expected hint mentioning 'sbomhub login', got: %s", r.message)
	}
}

func TestDoctor_ConfigPresentNoAPIKey(t *testing.T) {
	dir := t.TempDir()

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
	results := doctorChecks(dir, newTestHTTPClient())

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
	results := doctorChecks(dir, newTestHTTPClient())

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

	// Also verify runDoctorWith returns nil and prints all lines.
	var buf bytes.Buffer
	if err := runDoctorWith(&buf, dir, newTestHTTPClient(), false); err != nil {
		t.Errorf("runDoctorWith returned error: %v\noutput:\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "[OK]") {
		t.Errorf("expected at least one [OK] in output, got:\n%s", buf.String())
	}
}

func TestDoctor_AuthFails(t *testing.T) {
	dir := t.TempDir()

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
	results := doctorChecks(dir, newTestHTTPClient())

	if reach := findResult(results, "api-reachability"); reach == nil || reach.status != doctorOK {
		t.Errorf("expected reachability OK, got %+v", reach)
	}
	auth := findResult(results, "auth-verify")
	if auth == nil || auth.status != doctorFail {
		t.Errorf("expected auth-verify FAIL, got %+v", auth)
	}

	// runDoctorWith must return an error so main exits 1.
	var buf bytes.Buffer
	if err := runDoctorWith(&buf, dir, newTestHTTPClient(), false); err == nil {
		t.Errorf("runDoctorWith returned nil despite FAIL; output:\n%s", buf.String())
	}
}

func TestDoctor_APIUnreachable(t *testing.T) {
	dir := t.TempDir()

	// Spin up a server and close it immediately so the URL is well-formed but
	// no socket is listening. Use 127.0.0.1 so the OS returns ECONNREFUSED
	// (fast) rather than letting us wait on a routing timeout.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := srv.URL
	srv.Close()

	writeDoctorConfig(t, dir, deadURL, "sbh_validkey")
	results := doctorChecks(dir, newTestHTTPClient())

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
