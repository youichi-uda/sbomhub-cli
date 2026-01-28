package api

import (
	"encoding/json"
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

func TestUploadSBOM(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != "POST" {
			t.Errorf("Method = %q, want POST", r.Method)
		}

		if r.URL.Path != "/api/v1/cli/upload" {
			t.Errorf("Path = %q, want /api/v1/cli/upload", r.URL.Path)
		}

		// Verify auth header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-key" {
			t.Errorf("Authorization = %q, want Bearer test-key", auth)
		}

		// Send response
		result := UploadResult{
			ProjectID:          "proj-123",
			SBOMID:             "sbom-456",
			URL:                "https://sbomhub.app/projects/proj-123",
			VulnerabilityCount: 5,
			Critical:           1,
			High:               2,
			Medium:             1,
			Low:                1,
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")

	sbomData := []byte(`{"bomFormat": "CycloneDX", "specVersion": "1.4"}`)
	result, err := client.UploadSBOM("my-project", sbomData, "cyclonedx")

	if err != nil {
		t.Fatalf("UploadSBOM() error = %v", err)
	}

	if result.ProjectID != "proj-123" {
		t.Errorf("ProjectID = %q, want proj-123", result.ProjectID)
	}

	if result.VulnerabilityCount != 5 {
		t.Errorf("VulnerabilityCount = %d, want 5", result.VulnerabilityCount)
	}

	if result.Critical != 1 {
		t.Errorf("Critical = %d, want 1", result.Critical)
	}
}

func TestUploadSBOMError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "invalid api key"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "bad-key")

	_, err := client.UploadSBOM("my-project", []byte(`{}`), "cyclonedx")

	if err == nil {
		t.Error("UploadSBOM() expected error for 401 response")
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
		json.NewEncoder(w).Encode(result)
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

		if r.URL.Path != "/api/v1/projects" {
			t.Errorf("Path = %q, want /api/v1/projects", r.URL.Path)
		}

		projects := []Project{
			{ID: "1", Name: "Project A", Description: "First project"},
			{ID: "2", Name: "Project B", Description: "Second project"},
		}
		json.NewEncoder(w).Encode(projects)
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
		w.Write([]byte(`{"error": "internal server error"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")

	_, err := client.ListProjects()

	if err == nil {
		t.Error("ListProjects() expected error for 500 response")
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
