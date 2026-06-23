package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is the SBOMHub API client
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewClient creates a new API client
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// UploadResult represents the result of an SBOM upload
type UploadResult struct {
	Success        bool   `json:"success"`
	ProjectID      string `json:"project_id"`
	ProjectName    string `json:"project_name"`
	ProjectCreated bool   `json:"project_created"`
	SBOMID         string `json:"sbom_id"`
	Format         string `json:"format"`
	ComponentCount int    `json:"component_count"`
	URL            string `json:"url"`
	// Vulnerability counts (legacy, for backwards compatibility)
	VulnerabilityCount int `json:"vulnerability_count"`
	Critical           int `json:"critical"`
	High               int `json:"high"`
	Medium             int `json:"medium"`
	Low                int `json:"low"`
	// KEV (Known Exploited Vulnerabilities) count
	KEVCount int `json:"kev_count"`
}

// sbomUploadResponse mirrors the JSON returned by the canonical SBOM upload
// endpoint (POST /api/v1/projects/:id/sbom). That endpoint returns the saved
// `Sbom` model (apps/api/internal/model/sbom.go), NOT the legacy CLI-shaped
// UploadResponse — so we map it here and let UploadSBOM reassemble the
// surface UploadResult that the CLI commands already consume.
type sbomUploadResponse struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Format    string `json:"format"`
	Version   string `json:"version"`
	CreatedAt string `json:"created_at"`
}

// UploadSBOM uploads an SBOM to SBOMHub.
//
// Wire contract (Trust Rescue 9.3.1 / #9, BREAKING):
//   - Step 1: resolve `projectName` to a tenant-scoped project ID by calling
//     POST /api/v1/cli/projects, which has get-or-create semantics
//     (CLIService.GetOrCreateProject on the server side).
//   - Step 2: POST the raw SBOM bytes to /api/v1/projects/{id}/sbom — the
//     canonical endpoint protected by MultiAuth that the web UI also uses.
//     Content-Type is `application/json` because both CycloneDX-JSON and
//     SPDX-JSON parse as JSON and the server auto-detects which by the
//     body's `bomFormat` / `spdxVersion` field.
//
// The legacy multipart POST /api/v1/cli/upload still exists with a Sunset of
// 2026-09-24, but new requests MUST go through the canonical endpoint so the
// product has one source of truth on auth + tenant scoping.
func (c *Client) UploadSBOM(projectName string, sbomData []byte, format string) (*UploadResult, error) {
	// Step 1: get-or-create the project so we have a stable :id to POST to.
	project, projectCreated, err := c.CreateProject(projectName, "")
	if err != nil {
		return nil, fmt.Errorf("プロジェクト解決エラー: %w", err)
	}
	if project == nil || project.ID == "" {
		return nil, fmt.Errorf("APIがプロジェクトIDを返しませんでした")
	}

	// Step 2: POST raw body to the canonical SBOM upload endpoint.
	url := fmt.Sprintf("%s/api/v1/projects/%s/sbom", c.baseURL, project.ID)
	req, err := http.NewRequest("POST", url, bytes.NewReader(sbomData))
	if err != nil {
		return nil, err
	}

	// Send raw JSON; the server reads body via io.ReadAll and detects
	// CycloneDX vs SPDX from content, so the exact JSON media type is
	// informational rather than dispatch-driving.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("APIエラー (%d): %s", resp.StatusCode, string(body))
	}

	var sbomResp sbomUploadResponse
	if err := json.Unmarshal(body, &sbomResp); err != nil {
		return nil, fmt.Errorf("レスポンス解析エラー: %w", err)
	}

	// The canonical endpoint does not return component or vulnerability
	// counts (vulnerability scans run asynchronously in the background after
	// upload). Counts displayed by the CLI come from local counting of the
	// SBOM file (scan.go computes them before upload), so leaving them at
	// zero here is the honest representation of what the server told us.
	result := &UploadResult{
		Success:        true,
		ProjectID:      sbomResp.ProjectID,
		ProjectName:    project.Name,
		ProjectCreated: projectCreated,
		SBOMID:         sbomResp.ID,
		Format:         sbomResp.Format,
	}

	// Best-effort: pick up the web URL on the same host as the API. If the
	// API and web host are split, the operator is expected to set this via
	// configuration in a follow-up.
	if result.URL == "" && result.ProjectID != "" {
		result.URL = fmt.Sprintf("%s/projects/%s", c.baseURL, result.ProjectID)
	}

	// `format` is accepted for backwards compatibility with callers that pass
	// e.g. "cyclonedx", but the server now owns format detection.
	_ = format

	return result, nil
}

// CheckResult represents the result of a vulnerability check
type CheckResult struct {
	TotalComponents int                 `json:"total_components"`
	Total           int                 `json:"total_vulnerabilities"`
	Critical        int                 `json:"critical"`
	High            int                 `json:"high"`
	Medium          int                 `json:"medium"`
	Low             int                 `json:"low"`
	Unknown         int                 `json:"unknown"`
	BySeverity      map[string]int      `json:"by_severity"`
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
}

// VulnerabilityItem represents a single vulnerability
type VulnerabilityItem struct {
	Package    string   `json:"package"`
	Version    string   `json:"version"`
	ID         string   `json:"id"`
	Severity   string   `json:"severity"`
	Summary    string   `json:"summary"`
	FixedIn    string   `json:"fixed_in"`
	Aliases    []string `json:"aliases"`
	References []string `json:"references"`
}

// ComponentInput represents a component for vulnerability check
type ComponentInput struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Purl      string `json:"purl,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

// CheckVulnerabilitiesRequest represents the request body
type CheckVulnerabilitiesRequest struct {
	Components []ComponentInput `json:"components"`
}

// CheckVulnerabilities checks components for vulnerabilities without uploading
func (c *Client) CheckVulnerabilities(sbomData []byte) (*CheckResult, error) {
	// Parse SBOM to extract components
	components, err := parseSBOMToComponents(sbomData)
	if err != nil {
		return nil, fmt.Errorf("SBOM解析エラー: %w", err)
	}

	reqBody := CheckVulnerabilitiesRequest{
		Components: components,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("リクエストのシリアライズに失敗: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/cli/check", c.baseURL)

	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("APIエラー (%d): %s", resp.StatusCode, string(body))
	}

	var result CheckResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("レスポンス解析エラー: %w", err)
	}

	// Populate severity counts from BySeverity map
	if result.BySeverity != nil {
		result.Critical = result.BySeverity["CRITICAL"]
		result.High = result.BySeverity["HIGH"]
		result.Medium = result.BySeverity["MEDIUM"]
		result.Low = result.BySeverity["LOW"]
		result.Unknown = result.BySeverity["UNKNOWN"]
	}

	return &result, nil
}

// parseSBOMToComponents extracts components from SBOM data
func parseSBOMToComponents(sbomData []byte) ([]ComponentInput, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(sbomData, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	var components []ComponentInput

	// CycloneDX
	if rawComponents, ok := raw["components"].([]interface{}); ok {
		for _, c := range rawComponents {
			comp, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			input := ComponentInput{
				Name:    getString(comp, "name"),
				Version: getString(comp, "version"),
				Purl:    getString(comp, "purl"),
			}
			if input.Name != "" && input.Version != "" {
				components = append(components, input)
			}
		}
		return components, nil
	}

	// SPDX
	if rawPackages, ok := raw["packages"].([]interface{}); ok {
		for _, p := range rawPackages {
			pkg, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			input := ComponentInput{
				Name:    getString(pkg, "name"),
				Version: getString(pkg, "versionInfo"),
			}
			// Try to get PURL from externalRefs
			if refs, ok := pkg["externalRefs"].([]interface{}); ok {
				for _, ref := range refs {
					if refMap, ok := ref.(map[string]interface{}); ok {
						if getString(refMap, "referenceType") == "purl" {
							input.Purl = getString(refMap, "referenceLocator")
							break
						}
					}
				}
			}
			if input.Name != "" && input.Version != "" {
				components = append(components, input)
			}
		}
		return components, nil
	}

	return components, nil
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// Project represents a project
type Project struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

// ProjectsListResponse represents the response for listing projects
type ProjectsListResponse struct {
	Projects []Project `json:"projects"`
	Total    int       `json:"total"`
}

// ListProjects retrieves all projects
func (c *Client) ListProjects() ([]Project, error) {
	url := fmt.Sprintf("%s/api/v1/cli/projects", c.baseURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("APIエラー (%d): %s", resp.StatusCode, string(body))
	}

	var listResp ProjectsListResponse
	if err := json.Unmarshal(body, &listResp); err != nil {
		// Try parsing as array for backwards compatibility
		var projects []Project
		if err2 := json.Unmarshal(body, &projects); err2 != nil {
			return nil, fmt.Errorf("レスポンス解析エラー: %w", err)
		}
		return projects, nil
	}

	return listResp.Projects, nil
}

// GetProject retrieves a project by ID
func (c *Client) GetProject(id string) (*Project, error) {
	url := fmt.Sprintf("%s/api/v1/cli/projects/%s", c.baseURL, id)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("APIエラー (%d): %s", resp.StatusCode, string(body))
	}

	var project Project
	if err := json.Unmarshal(body, &project); err != nil {
		return nil, fmt.Errorf("レスポンス解析エラー: %w", err)
	}

	return &project, nil
}

// CreateProjectRequest represents the request for creating a project
type CreateProjectRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// CreateProjectResponse represents the response for creating a project
type CreateProjectResponse struct {
	Project *Project `json:"project"`
	Created bool     `json:"created"`
}

// CreateProject creates a new project or returns existing one
func (c *Client) CreateProject(name, description string) (*Project, bool, error) {
	url := fmt.Sprintf("%s/api/v1/cli/projects", c.baseURL)

	reqBody := CreateProjectRequest{
		Name:        name,
		Description: description,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, false, fmt.Errorf("リクエストのシリアライズに失敗: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonData))
	if err != nil {
		return nil, false, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, false, fmt.Errorf("APIエラー (%d): %s", resp.StatusCode, string(body))
	}

	var createResp CreateProjectResponse
	if err := json.Unmarshal(body, &createResp); err != nil {
		return nil, false, fmt.Errorf("レスポンス解析エラー: %w", err)
	}

	return createResp.Project, createResp.Created, nil
}
