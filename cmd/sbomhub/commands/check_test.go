package commands

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunCheck_HonorsAPIURLFromEnv verifies the Codex R9 fix for the
// `sbomhub check` path. Self-host users expect
//
//	SBOMHUB_API_URL=http://localhost:8080 SBOMHUB_API_KEY=sbh_xxx \
//	    sbomhub check ./sbom.json
//
// to hit localhost. Before the fix runCheck called config.Load + a manual
// --api-key override, silently routing /api/v1/cli/check to the built-in
// https://api.sbomhub.app default.
//
// We exercise the SBOM-file branch (not the directory-scan branch) so the
// test doesn't depend on syft/trivy/cdxgen being installed.
func TestRunCheck_HonorsAPIURLFromEnv(t *testing.T) {
	withCleanCredentialEnv(t)

	var (
		hit         bool
		gotAuth     string
		gotPath     string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		// Minimal CheckResult payload — runCheck only inspects Total /
		// per-severity counters for the rendered summary, all of which are
		// zero in this fixture.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total":       0,
			"by_severity": map[string]int{},
		})
	}))
	defer server.Close()

	// Minimal CycloneDX SBOM so parseSBOMToComponents has something to
	// chew on (zero-component case is acceptable: CheckVulnerabilities
	// posts an empty Components slice, server returns the canned response
	// above).
	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	t.Setenv("SBOMHUB_API_URL", server.URL)
	t.Setenv("SBOMHUB_API_KEY", "sbh_env_check")

	if err := runCheck(checkCmd, []string{sbomPath}); err != nil {
		t.Fatalf("runCheck() error = %v; expected env-only credentials to satisfy the command", err)
	}

	if !hit {
		t.Fatal("server never received request — runCheck did not route to SBOMHUB_API_URL")
	}
	if gotAuth != "Bearer sbh_env_check" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer sbh_env_check")
	}
	if gotPath != "/api/v1/cli/check" {
		t.Errorf("request path = %q, want %q", gotPath, "/api/v1/cli/check")
	}
}

// TestRunCheck_MissingCredentialsErrorMentionsAllSources verifies the
// error message lists every viable credential source when none is set, so
// the operator isn't blindsided by a single "run sbomhub login" hint when
// they're in an ephemeral CI shell where flag/env are the right answer.
func TestRunCheck_MissingCredentialsErrorMentionsAllSources(t *testing.T) {
	withCleanCredentialEnv(t)

	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	err := runCheck(checkCmd, []string{sbomPath})
	if err == nil {
		t.Fatal("runCheck() returned nil; expected credentials error")
	}
	msg := err.Error()
	for _, want := range []string{"API Key", "SBOMHUB_API_KEY", "--api-key", "sbomhub login"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error = %q, want substring %q", msg, want)
		}
	}
}
