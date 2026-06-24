package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	// allowAsID=true here because the test simulates an explicit --project
	// supply; the value is a name, so the UUID short-circuit does not
	// fire and we still take the get-or-create path. allowAsID toggles
	// "may treat as ID if it happens to be a UUID", not "is an ID".
	result, err := client.UploadSBOM("my-project", true, sbomData, "cyclonedx")

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

// TestUploadSBOM_ProjectRefIsUUID verifies the Codex R6 finding 1 fix:
// when `--project` is EXPLICITLY given a canonical UUID (allowAsID=true),
// UploadSBOM must treat it as the existing project's ID and skip
// CreateProject entirely. Before the fix the UUID was passed to
// CreateProject as a NAME, which then created a brand-new project whose
// name happened to be the UUID string — attaching the SBOM to the wrong
// project.
//
// Codex R12 fix (P2) layered on top: the short-circuit is now ALSO gated
// on allowAsID=true. See TestUploadSBOM_UUIDImplicitTreatedAsName for the
// inverse — UUID-shaped but implicit-from-dir-basename must NOT trip the
// short-circuit, or a /tmp/<uuid>/ checkout silently attaches to a random
// project.
func TestUploadSBOM_ProjectRefIsUUID(t *testing.T) {
	const projectID = "12345678-1234-1234-1234-1234567890ab"
	const sbomID = "00000000-0000-0000-0000-000000000def"

	var (
		createProjectHits int
		uploadHits        int
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/api/v1/cli/projects":
			createProjectHits++
			// We do NOT expect this branch to be reached when the
			// caller passes a UUID with allowAsID=true. Still respond
			// so a regression produces a useful diff rather than a hang.
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(CreateProjectResponse{
				Project: &Project{ID: "wrong-id", Name: projectID},
				Created: true,
			})

		case r.Method == "POST" && r.URL.Path == "/api/v1/projects/"+projectID+"/sbom":
			uploadHits++
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
	// allowAsID=true → the caller (scan.go) saw an explicit --project
	// flag, so a UUID-format value is honored as a project ID.
	result, err := client.UploadSBOM(projectID, true, sbomData, "cyclonedx")
	if err != nil {
		t.Fatalf("UploadSBOM() error = %v", err)
	}

	if createProjectHits != 0 {
		t.Errorf("CreateProject called %d times for UUID --project; want 0 (Codex R6 finding 1 regression)", createProjectHits)
	}
	if uploadHits != 1 {
		t.Errorf("POST /projects/{id}/sbom called %d times, want 1", uploadHits)
	}
	if result.ProjectID != projectID {
		t.Errorf("ProjectID = %q, want %q (UUID must round-trip as the upload target)", result.ProjectID, projectID)
	}
	if result.ProjectCreated {
		t.Error("ProjectCreated should be false when --project was an existing UUID (no create happened)")
	}
}

// TestUploadSBOM_UUIDImplicitTreatedAsName verifies the Codex R12 P2 fix:
// when allowAsID=false the UUID short-circuit must NOT fire even for a
// projectRef that matches the canonical UUID format. The motivating bug
// is that scan.go falls back to the working-directory basename when
// --project is not supplied, and a CI checkout under /tmp/<uuid>/ would
// otherwise have its basename misread as "user gave me this project ID
// on purpose" — silently attaching the SBOM to whichever random project
// happened to share that ID in the tenant.
//
// The contract this test pins down:
//   - CreateProject IS called with the UUID-shaped string as the NAME
//     (server-side get-or-create then mints a fresh project, or returns
//     the one already named that way).
//   - The SBOM uploads to whatever project ID CreateProject returned,
//     NOT to the literal UUID value the caller passed in.
//
// A regression where allowAsID=false reverts to UUID-format-driven
// short-circuit reopens the P2 misattribution incident.
func TestUploadSBOM_UUIDImplicitTreatedAsName(t *testing.T) {
	// projectRef is UUID-shaped (would have tripped pre-R12 short-circuit)
	// but we hand it in with allowAsID=false, mimicking the dir-basename
	// fallback in scan.go.
	const dirBasenameUUID = "01234567-0123-0123-0123-0123456789ab"
	// The server resolves the name to an entirely different project ID,
	// so a regression that still treats the input as an ID would POST
	// the SBOM to /projects/<dirBasenameUUID>/sbom and the test would
	// see uploadToCreatedID == 0 + uploadToInputUUID == 1.
	const createdProjectID = "99999999-9999-9999-9999-999999999999"
	const sbomID = "00000000-0000-0000-0000-000000000def"

	var (
		createProjectHits int
		uploadToCreatedID int
		uploadToInputUUID int
		seenCreateName    string
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/api/v1/cli/projects":
			createProjectHits++
			// Capture the NAME the client sent so the test can assert
			// the dir-basename UUID was passed verbatim (not parsed as
			// an ID and stripped).
			body, _ := io.ReadAll(r.Body)
			var req CreateProjectRequest
			_ = json.Unmarshal(body, &req)
			seenCreateName = req.Name

			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(CreateProjectResponse{
				Project: &Project{ID: createdProjectID, Name: dirBasenameUUID},
				Created: true,
			})

		case r.Method == "POST" && r.URL.Path == "/api/v1/projects/"+createdProjectID+"/sbom":
			uploadToCreatedID++
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":         sbomID,
				"project_id": createdProjectID,
				"format":     "cyclonedx",
				"version":    "1.4",
				"created_at": "2026-06-24T00:00:00Z",
			})

		case r.Method == "POST" && r.URL.Path == "/api/v1/projects/"+dirBasenameUUID+"/sbom":
			// Regression path: the client treated the input UUID as an
			// ID directly. Count + respond so the test produces a clear
			// diff rather than a network error.
			uploadToInputUUID++
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":         sbomID,
				"project_id": dirBasenameUUID,
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
	// allowAsID=false: caller is the dir-basename fallback path in
	// scan.go and has NOT been told to treat this value as a UUID.
	result, err := client.UploadSBOM(dirBasenameUUID, false, sbomData, "cyclonedx")
	if err != nil {
		t.Fatalf("UploadSBOM() error = %v", err)
	}

	if createProjectHits != 1 {
		t.Errorf("CreateProject called %d times for implicit UUID-shaped name; want 1 (Codex R12 P2 regression — UUID short-circuit firing without explicit --project)", createProjectHits)
	}
	if seenCreateName != dirBasenameUUID {
		t.Errorf("CreateProject received name %q, want %q (the dir-basename UUID must be passed verbatim as a name)", seenCreateName, dirBasenameUUID)
	}
	if uploadToInputUUID != 0 {
		t.Errorf("upload hit /projects/%s/sbom %d times (R12 P2 regression: implicit UUID was treated as an ID and the SBOM would have attached to a stranger's project)", dirBasenameUUID, uploadToInputUUID)
	}
	if uploadToCreatedID != 1 {
		t.Errorf("upload hit /projects/%s/sbom %d times, want 1 (SBOM must attach to the project the server actually created/found)", createdProjectID, uploadToCreatedID)
	}
	if result.ProjectID != createdProjectID {
		t.Errorf("ProjectID = %q, want %q (must be the server-issued ID, not the dir-basename UUID)", result.ProjectID, createdProjectID)
	}
	if !result.ProjectCreated {
		t.Error("ProjectCreated should be true (CreateProject returned Created: true)")
	}
}

// TestLooksLikeUUID covers the strict UUID detector used by UploadSBOM to
// disambiguate name vs ID in `--project`. The negative cases are the
// load-bearing ones — anything that returns true here will skip
// CreateProject and be sent as `/api/v1/projects/{value}/sbom`.
func TestLooksLikeUUID(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"canonical lowercase", "12345678-1234-1234-1234-1234567890ab", true},
		{"canonical uppercase", "12345678-1234-1234-1234-1234567890AB", true},
		{"mixed case", "12345678-ABcd-1234-EfAb-1234567890ab", true},
		{"empty string", "", false},
		{"plain name", "my-app", false},
		{"hyphenated name", "my-cool-project", false},
		{"too short", "12345678-1234-1234-1234-1234567890a", false},
		{"too long", "12345678-1234-1234-1234-1234567890abc", false},
		{"wrong hyphen positions", "1234567-81234-1234-1234-1234567890ab1", false},
		{"non-hex char", "12345678-1234-1234-1234-1234567890ag", false},
		{"all hyphens swapped to underscores", "12345678_1234_1234_1234_1234567890ab", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikeUUID(tc.in); got != tc.want {
				t.Errorf("looksLikeUUID(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
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

	// allowAsID=true is irrelevant here ("my-project" is not a UUID), but
	// match the realistic explicit-flag case.
	_, err := client.UploadSBOM("my-project", true, []byte(`{}`), "cyclonedx")

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
	got, err := client.GetScanStatus(context.Background(), projectID, sbomID)
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
//
// Codex R7: the error must also be a typed *APIError so the polling
// loop can inspect StatusCode and classify it (5xx → transient, retry
// within --wait-timeout). Without the typed wrapper the loop has no
// way to distinguish 5xx from network errors from 4xx.
func TestGetScanStatusError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error": "boom"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	_, err := client.GetScanStatus(context.Background(), "p", "s")
	if err == nil {
		t.Fatal("GetScanStatus() expected error for 500 response")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is not *APIError: %T %v (R7: non-2xx must surface as typed APIError for classification)", err, err)
	}
	if apiErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("APIError.StatusCode = %d, want %d", apiErr.StatusCode, http.StatusInternalServerError)
	}
}

// TestGetScanStatus_PermanentClientError verifies the Codex R7 fix:
// 4xx responses from scan-status are returned as a typed *APIError so
// the polling loop in scan.go can recognise the permanent failure and
// fast-fail (exit-3) instead of silently retrying for --wait-timeout
// and then reporting it as a misleading exit-2 "scan timed out".
//
// We cover the common permanent cases:
//   - 401 Unauthorized: API key is wrong / missing
//   - 403 Forbidden:    key valid but no access to this project / sbom
//   - 404 Not Found:    older server without scan-status endpoint, or
//                       the sbom ID was wrong (race against deletion)
//   - 400 Bad Request:  malformed path / sbom ID; same class of "this
//                       will never succeed, stop retrying"
func TestGetScanStatus_PermanentClientError(t *testing.T) {
	cases := []struct {
		name string
		code int
	}{
		{"401 unauthorized", http.StatusUnauthorized},
		{"403 forbidden", http.StatusForbidden},
		{"404 not found", http.StatusNotFound},
		{"400 bad request", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(`{"error":"permanent"}`))
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-key")
			_, err := client.GetScanStatus(context.Background(), "p", "s")
			if err == nil {
				t.Fatal("expected error")
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("error is not *APIError: %T %v", err, err)
			}
			if apiErr.StatusCode != tc.code {
				t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, tc.code)
			}
			// URL must round-trip so the operator-facing message in
			// runScan can include the failing endpoint.
			if apiErr.URL == "" {
				t.Error("APIError.URL is empty; want the failing scan-status URL for diagnostics")
			}
			// The body must round-trip too so the server's error
			// message (e.g. "invalid api key") is preserved end-to-end.
			if !strings.Contains(apiErr.Message, "permanent") {
				t.Errorf("APIError.Message = %q, want substring %q (server body lost)", apiErr.Message, "permanent")
			}
		})
	}
}

// TestGetScanStatusContextCancel verifies the Codex R4 finding 2 fix:
// GetScanStatus must honor caller-supplied context cancellation by
// aborting an in-flight HTTP request. The fix wires the ctx through
// http.NewRequestWithContext so that --wait-timeout (modeled as
// context.WithTimeout in scan.go) actually short-circuits a hung server.
//
// Before the fix the only timeout in effect was Client.httpClient default
// 60s, so a 100ms --wait-timeout would still hang for ~60s.
func TestGetScanStatusContextCancel(t *testing.T) {
	// Server intentionally hangs forever (until the test's HTTP request
	// is cancelled). We hold the handler open via the request's own
	// context so we don't leak goroutines after the test exits.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := client.GetScanStatus(ctx, "p", "s")
	elapsed := time.Since(start)

	if err == nil {
		t.Error("GetScanStatus() expected error when ctx cancels mid-request")
	}
	// 60s default httpClient.Timeout would put us in the 5-60s range
	// without the fix. Allow generous slack, but reject anything that
	// suggests the ctx was ignored.
	if elapsed > 2*time.Second {
		t.Errorf("GetScanStatus took %s with a 100ms ctx — request not bound via http.NewRequestWithContext (Codex R4 finding 2 regression)", elapsed)
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
