package commands

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/youichi-uda/sbomhub-cli/internal/api"
	"github.com/youichi-uda/sbomhub-cli/internal/config"
)

// withCleanCredentialEnv snapshots and restores the credential package
// globals + relevant env vars so tests don't leak into each other (and
// don't inherit stale values from the developer's shell).
func withCleanCredentialEnv(t *testing.T) {
	t.Helper()
	saveURL, saveKey := apiURL, apiKey
	t.Cleanup(func() { apiURL, apiKey = saveURL, saveKey })
	apiURL = ""
	apiKey = ""
	t.Setenv("SBOMHUB_API_URL", "")
	t.Setenv("SBOMHUB_API_KEY", "")
	// Point credential lookups at an empty fake HOME so we don't accidentally
	// read the developer's real ~/.sbomhub/config.yaml.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", "")
}

// TestLoadConfigAndClient_HonorsAPIURLFromEnv verifies the Codex R9 fix:
// `sbomhub projects ...` must respect SBOMHUB_API_URL even when no
// ~/.sbomhub/config.yaml exists. Before the fix, loadConfigAndClient
// called config.Load (which errored on the missing file) and the env URL
// was silently ignored — projects commands always hit the built-in
// https://api.sbomhub.app default, breaking self-host installs.
func TestLoadConfigAndClient_HonorsAPIURLFromEnv(t *testing.T) {
	withCleanCredentialEnv(t)
	t.Setenv("SBOMHUB_API_URL", "https://env.example.com")
	t.Setenv("SBOMHUB_API_KEY", "sbh_env_key")

	client, err := loadConfigAndClient()
	if err != nil {
		t.Fatalf("loadConfigAndClient() error = %v, want nil (env-only path must succeed)", err)
	}
	if client == nil {
		t.Fatal("client is nil")
	}

	// We cannot read the unexported baseURL field directly, so verify via
	// an actual round-trip: any request the client makes must land on our
	// server, NOT https://api.sbomhub.app.
	var hit bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		if got := r.Header.Get("Authorization"); got != "Bearer sbh_env_key" {
			t.Errorf("Authorization header = %q, want %q (env API key not propagated)", got, "Bearer sbh_env_key")
		}
		_ = json.NewEncoder(w).Encode(api.ProjectsListResponse{Projects: []api.Project{}, Total: 0})
	}))
	defer server.Close()

	// Re-resolve with the server URL so we can actually verify the URL
	// path (the previous resolve happened before we knew server.URL).
	t.Setenv("SBOMHUB_API_URL", server.URL)
	client, err = loadConfigAndClient()
	if err != nil {
		t.Fatalf("loadConfigAndClient() error = %v on second resolve", err)
	}

	if _, err := client.ListProjects(); err != nil {
		t.Fatalf("ListProjects() error = %v; expected the env-configured server to be reached", err)
	}
	if !hit {
		t.Error("server never received request — loadConfigAndClient did not route to SBOMHUB_API_URL")
	}
}

// TestLoadConfigAndClient_FlagBeatsEnv verifies CLI flag > env precedence:
// --api-url overrides SBOMHUB_API_URL, matching the documented contract in
// resolveCredentials and the behaviour of scan.go.
func TestLoadConfigAndClient_FlagBeatsEnv(t *testing.T) {
	withCleanCredentialEnv(t)
	t.Setenv("SBOMHUB_API_URL", "https://env.example.com")
	t.Setenv("SBOMHUB_API_KEY", "sbh_env_key")

	var hit bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		if got := r.Header.Get("Authorization"); got != "Bearer sbh_flag_key" {
			t.Errorf("Authorization header = %q, want %q (CLI flag key not propagated)", got, "Bearer sbh_flag_key")
		}
		_ = json.NewEncoder(w).Encode(api.ProjectsListResponse{Projects: []api.Project{}, Total: 0})
	}))
	defer server.Close()

	// Flags must win over env.
	apiURL = server.URL
	apiKey = "sbh_flag_key"

	client, err := loadConfigAndClient()
	if err != nil {
		t.Fatalf("loadConfigAndClient() error = %v", err)
	}
	if _, err := client.ListProjects(); err != nil {
		t.Fatalf("ListProjects() error = %v", err)
	}
	if !hit {
		t.Error("server never received request — CLI --api-url did not override env")
	}
}

// TestLoadConfigAndClient_NoCredentialsErrors verifies the error path: when
// neither flag nor env nor config supplies an API key, the function returns
// a helpful error that mentions all three credential sources (so the
// operator knows what to set).
func TestLoadConfigAndClient_NoCredentialsErrors(t *testing.T) {
	withCleanCredentialEnv(t)

	_, err := loadConfigAndClient()
	if err == nil {
		t.Fatal("loadConfigAndClient() returned nil error with no credentials")
	}
	msg := err.Error()
	if !strings.Contains(msg, "API Key") {
		t.Errorf("error = %q, want substring %q", msg, "API Key")
	}
	// The hint should reference env / flag / login so the operator has
	// every viable knob in one place.
	for _, want := range []string{"SBOMHUB_API_KEY", "--api-key", "sbomhub login"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error = %q, want substring %q (operator must see all credential sources)", msg, want)
		}
	}
}

// TestLoadConfigAndClient_ConfigFileFallback verifies the file→env precedence:
// when no env vars or flags are set, the config file value is honoured (so
// `sbomhub login` users keep working).
func TestLoadConfigAndClient_ConfigFileFallback(t *testing.T) {
	withCleanCredentialEnv(t)

	// Re-seed HOME and write a config there so getConfigDir finds it.
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", "")
	if err := config.Save(&config.Config{
		APIURL: "https://file.example.com",
		APIKey: "sbh_file_key",
	}, homeDir+"/.sbomhub"); err != nil {
		t.Fatalf("config.Save() error = %v", err)
	}

	var hit bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		_ = json.NewEncoder(w).Encode(api.ProjectsListResponse{Projects: []api.Project{}, Total: 0})
	}))
	defer server.Close()

	// Env overrides the file URL to point at our fake server, but the key
	// comes from the file — this asserts both (env-wins-over-file URL) and
	// (file-fills-the-blank for the unset key) in one assertion.
	t.Setenv("SBOMHUB_API_URL", server.URL)

	client, err := loadConfigAndClient()
	if err != nil {
		t.Fatalf("loadConfigAndClient() error = %v", err)
	}
	if _, err := client.ListProjects(); err != nil {
		t.Fatalf("ListProjects() error = %v", err)
	}
	if !hit {
		t.Error("server never received request — env URL did not override file URL")
	}
}
