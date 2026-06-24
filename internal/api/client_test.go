package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	client := NewClient("https://api.example.com", "test-api-key")

	if client.baseURL != "https://api.example.com" {
		t.Errorf("baseURL = %q, want %q", client.baseURL, "https://api.example.com")
	}

	if client.apiKey != "test-api-key" {
		t.Errorf("apiKey = %q, want %q", client.apiKey, "test-api-key")
	}

	if client.httpClient == nil {
		t.Error("httpClient is nil")
	}
}

// TestUploadSBOM exercises the new two-step upload contract introduced by
// Trust Rescue 9.3.1 (#9):
//   1. POST /api/v1/cli/projects with the project name → project ID (the
//      `/cli/projects` endpoint still has get-or-create semantics and is
//      kept for one release of overlap; it is NOT under the deprecation
//      banner that /cli/upload carries).
//   2. POST /api/v1/projects/{id}/sbom with the raw SBOM JSON body, gated
//      by the unified MultiAuth Bearer auth on the server side.
func TestUploadSBOM(t *testing.T) {
	const projectID = "00000000-0000-0000-0000-000000000abc"
	const sbomID = "00000000-0000-0000-0000-000000000def"

	var (
		createProjectHits int
		uploadHits        int
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-key" {
			t.Errorf("Authorization = %q, want Bearer test-key", auth)
		}

		switch {
		case r.Method == "POST" && r.URL.Path == "/api/v1/cli/projects":
			createProjectHits++
			resp := CreateProjectResponse{
				Project: &Project{ID: projectID, Name: "my-project"},
				Created: true,
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(resp)

		case r.Method == "POST" && r.URL.Path == "/api/v1/projects/"+projectID+"/sbom":
			uploadHits++

			// Verify the body is RAW JSON (not multipart) — this is the
			// load-bearing change of the contract.
			ct := r.Header.Get("Content-Type")
			if ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json (raw body, not multipart)", ct)
			}
			body, _ := io.ReadAll(r.Body)
			var probe map[string]interface{}
			if err := json.Unmarshal(body, &probe); err != nil {
				t.Errorf("server received non-JSON body: %v (got %q)", err, string(body))
			}
			if probe["bomFormat"] != "CycloneDX" {
				t.Errorf("server lost SBOM body: got %v", probe)
			}

			// Mirror the actual server response shape: the canonical
			// endpoint returns the saved Sbom model (id, project_id,
			// format, version, created_at) — NOT the legacy CLI shape.
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":         sbomID,
				"project_id": projectID,
				"format":     "cyclonedx",
				"version":    "1.4",
				"created_at": "2026-06-24T00:00:00Z",
			})

		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	sbomData := []byte(`{"bomFormat": "CycloneDX", "specVersion": "1.4"}`)
	result, err := client.UploadSBOM("my-project", sbomData, "cyclonedx")

	if err != nil {
		t.Fatalf("UploadSBOM() error = %v", err)
	}

	if createProjectHits != 1 {
		t.Errorf("POST /cli/projects called %d times, want 1", createProjectHits)
	}
	if uploadHits != 1 {
		t.Errorf("POST /projects/{id}/sbom called %d times, want 1", uploadHits)
	}
	if result.ProjectID != projectID {
		t.Errorf("ProjectID = %q, want %q", result.ProjectID, projectID)
	}
	if result.SBOMID != sbomID {
		t.Errorf("SBOMID = %q, want %q", result.SBOMID, sbomID)
	}
	if result.Format != "cyclonedx" {
		t.Errorf("Format = %q, want cyclonedx", result.Format)
	}
	if !result.ProjectCreated {
		t.Error("ProjectCreated should be true when /cli/projects returned created=true")
	}
}

// TestUploadSBOMError verifies the upload step's error path. The canonical
// endpoint should fail loudly on 401 with the server's error body surfaced
// so the operator can debug auth / tenant misconfiguration.
func TestUploadSBOMError(t *testing.T) {
	const projectID = "00000000-0000-0000-0000-000000000abc"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/cli/projects":
			resp := CreateProjectResponse{
				Project: &Project{ID: projectID, Name: "my-project"},
				Created: false,
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		case r.URL.Path == "/api/v1/projects/"+projectID+"/sbom":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error": "invalid api key"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "bad-key")

	_, err := client.UploadSBOM("my-project", []byte(`{}`), "cyclonedx")

	if err == nil {
		t.Error("UploadSBOM() expected error for 401 response from canonical endpoint")
	}
}

func TestCheckVulnerabilities(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Method = %q, want POST", r.Method)
		}

		if r.URL.Path != "/api/v1/cli/check" {
			t.Errorf("Path = %q, want /api/v1/cli/check", r.URL.Path)
		}

		result := CheckResult{
			Total:    10,
			Critical: 2,
			High:     3,
			Medium:   3,
			Low:      2,
		}
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")

	sbomData := []byte(`{"bomFormat": "CycloneDX"}`)
	result, err := client.CheckVulnerabilities(sbomData)

	if err != nil {
		t.Fatalf("CheckVulnerabilities() error = %v", err)
	}

	if result.Total != 10 {
		t.Errorf("Total = %d, want 10", result.Total)
	}

	if result.Critical != 2 {
		t.Errorf("Critical = %d, want 2", result.Critical)
	}
}

func TestListProjects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("Method = %q, want GET", r.Method)
		}

		if r.URL.Path != "/api/v1/cli/projects" {
			t.Errorf("Path = %q, want /api/v1/cli/projects", r.URL.Path)
		}

		projects := []Project{
			{ID: "1", Name: "Project A", Description: "First project"},
			{ID: "2", Name: "Project B", Description: "Second project"},
		}
		_ = json.NewEncoder(w).Encode(projects)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")

	projects, err := client.ListProjects()

	if err != nil {
		t.Fatalf("ListProjects() error = %v", err)
	}

	if len(projects) != 2 {
		t.Errorf("len(projects) = %d, want 2", len(projects))
	}

	if projects[0].Name != "Project A" {
		t.Errorf("projects[0].Name = %q, want Project A", projects[0].Name)
	}
}

func TestListProjectsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error": "internal server error"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")

	_, err := client.ListProjects()

	if err == nil {
		t.Error("ListProjects() expected error for 500 response")
	}
}

// TestGetScanStatus exercises the polling contract used by
// `sbomhub scan --fail-on` (Trust Rescue P1 #12). The CLI calls
// GET /api/v1/projects/{project_id}/sboms/{sbom_id}/scan-status with the
// Bearer API key and decodes the status + per-severity counts.
func TestGetScanStatus(t *testing.T) {
	const projectID = "00000000-0000-0000-0000-000000000abc"
	const sbomID = "00000000-0000-0000-0000-000000000def"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("Method = %q, want GET", r.Method)
		}
		wantPath := "/api/v1/projects/" + projectID + "/sboms/" + sbomID + "/scan-status"
		if r.URL.Path != wantPath {
			t.Errorf("Path = %q, want %q", r.URL.Path, wantPath)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-key" {
			t.Errorf("Authorization = %q, want Bearer test-key", auth)
		}

		// Server emits the canonical scan-status shape; KEV is the
		// orthogonal bucket introduced by Codex R1 fix.
		_, _ = w.Write([]byte(`{
			"status":     "completed",
			"sbom_id":    "` + sbomID + `",
			"project_id": "` + projectID + `",
			"vulnerabilities": {
				"critical": 2,
				"high":     3,
				"medium":   5,
				"low":      7,
				"unknown":  1,
				"kev":      4,
				"total":    18
			}
		}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	got, err := client.GetScanStatus(projectID, sbomID)
	if err != nil {
		t.Fatalf("GetScanStatus() error = %v", err)
	}
	if got.Status != "completed" {
		t.Errorf("Status = %q, want completed", got.Status)
	}
	if got.Vulnerabilities.Critical != 2 || got.Vulnerabilities.High != 3 {
		t.Errorf("Vulnerabilities = %+v, want critical=2 high=3", got.Vulnerabilities)
	}
	if got.Vulnerabilities.Total != 18 {
		t.Errorf("Total = %d, want 18", got.Vulnerabilities.Total)
	}
	// Codex R1 fix regression guard: the CLI must decode the new `kev`
	// bucket so `--fail-on kev` can read it from scan-status. Before the
	// fix this field did not exist on the struct and silently dropped.
	if got.Vulnerabilities.KEV != 4 {
		t.Errorf("KEV = %d, want 4 (server response must round-trip into VulnerabilitySummary.KEV)", got.Vulnerabilities.KEV)
	}
	// Codex R2 fix regression guard: the `unknown` bucket must round-trip
	// too. Before the fix the scan-status response decoded fine into
	// VulnerabilitySummary.Unknown but scan.go's downstream aggregation
	// dropped it, so a scan whose only findings were `unknown` rendered
	// as "なし ✅" — silently hiding the data-quality finding.
	if got.Vulnerabilities.Unknown != 1 {
		t.Errorf("Unknown = %d, want 1 (server response must round-trip into VulnerabilitySummary.Unknown)", got.Vulnerabilities.Unknown)
	}
}

// TestGetScanStatusError exercises the transient-error path. The CLI
// poll loop logs and retries on errors here, so the only contract we
// need from the client is "return a non-nil error".
func TestGetScanStatusError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error": "boom"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	if _, err := client.GetScanStatus("p", "s"); err == nil {
		t.Error("GetScanStatus() expected error for 500 response")
	}
}

func TestUploadResultJSON(t *testing.T) {
	jsonData := `{
		"project_id": "abc",
		"sbom_id": "def",
		"url": "https://example.com",
		"vulnerability_count": 3,
		"critical": 1,
		"high": 1,
		"medium": 1,
		"low": 0
	}`

	var result UploadResult
	if err := json.Unmarshal([]byte(jsonData), &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if result.ProjectID != "abc" {
		t.Errorf("ProjectID = %q, want abc", result.ProjectID)
	}

	if result.VulnerabilityCount != 3 {
		t.Errorf("VulnerabilityCount = %d, want 3", result.VulnerabilityCount)
	}
}
