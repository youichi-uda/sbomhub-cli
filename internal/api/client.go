package api

import (
	"bytes"
	"context"
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

// APIError represents a non-2xx HTTP response from the SBOMHub API.
//
// Codex R7 fix: returning a typed error (instead of a wrapped
// fmt.Errorf "APIエラー (%d): %s") lets callers — specifically the
// scan-status polling loop in cmd/sbomhub/commands/scan.go — use
// errors.As to inspect the status code and decide whether to retry
// (transient: network flap, 5xx, ctx cancellation) or fast-fail
// (permanent: 401/403 bad auth, 404 endpoint missing on older server).
//
// Before this change, every non-2xx response was treated as transient
// by waitForScanCompletion's `continue` branch, so a permanent 401
// would silently retry for the full --wait-timeout (default 5 min) and
// then report the failure as a "scan timed out" exit-2 — misleading
// the operator into thinking the scan was slow when the real failure
// mode was a misconfigured API key.
//
// Currently only emitted by GetScanStatus; other client methods still
// return wrapped sentinel errors. They can adopt APIError incrementally
// as their callers gain a need to classify failures.
type APIError struct {
	StatusCode int
	Message    string
	URL        string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("APIエラー (%d) %s: %s", e.StatusCode, e.URL, e.Message)
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

// looksLikeUUID reports whether s matches the canonical 8-4-4-4-12 hex
// UUID format (RFC 4122 string form, case-insensitive). It is intentionally
// strict: anything else — including names that happen to contain hyphens —
// is treated as a project NAME by UploadSBOM, preserving the get-or-create
// semantics for the legacy `--project my-app` form.
//
// Codex R12 fix (P2): looksLikeUUID is only consulted when the caller
// passes allowAsID=true to UploadSBOM. That gate exists because the CLI's
// scan command falls back to the working-directory basename when --project
// is not explicitly given, and a checkout path like /tmp/<uuid>/ would
// otherwise be silently routed to a random project ID — UploadSBOM cannot
// distinguish "user gave me this UUID on purpose" from "I synthesized this
// from a directory name" without the explicit bit. Keeping looksLikeUUID
// unexported keeps that gate co-located with the only legitimate use.
//
// We do strict format matching rather than pulling in github.com/google/uuid
// to keep the CLI's dependency surface minimal (the project's go.mod has
// cobra + yaml only).
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
				return false
			}
		}
	}
	return true
}

// UploadSBOM uploads an SBOM to SBOMHub.
//
// Wire contract (Trust Rescue 9.3.1 / #9, BREAKING):
//   - Step 1: resolve `projectRef` to a tenant-scoped project ID. The flag
//     `sbomhub scan --project` accepts EITHER a project name OR a project
//     UUID per its help text. If the caller passes `allowAsID=true` AND
//     `projectRef` parses as a canonical UUID (8-4-4-4-12 hex per RFC 4122)
//     we treat it as the project ID directly and skip the get-or-create
//     call. Otherwise we POST to /api/v1/cli/projects, which has
//     get-or-create semantics on the server side
//     (CLIService.GetOrCreateProject).
//   - Step 2: POST the raw SBOM bytes to /api/v1/projects/{id}/sbom — the
//     canonical endpoint protected by MultiAuth that the web UI also uses.
//     Content-Type is `application/json` because both CycloneDX-JSON and
//     SPDX-JSON parse as JSON and the server auto-detects which by the
//     body's `bomFormat` / `spdxVersion` field.
//
// Codex R6 fix (Finding 1): before that change, passing a UUID via
// `--project <uuid>` was silently routed through CreateProject, which would
// create a new project whose NAME was the literal UUID string (because no
// existing project had that name). SBOMs then attached to the wrong (newly
// created) project. The UUID short-circuit gives the operator the
// behaviour the help text already promised.
//
// Codex R12 fix (P2): R6 keyed the short-circuit purely on UUID format,
// which made it fire even when the CLI had synthesized projectRef from the
// working-directory basename (the no-flag fallback in cmd/sbomhub/commands/
// scan.go). A checkout under /tmp/<uuid>/ would then attach to whatever
// random project happened to share that ID — silently rebinding the SBOM
// to an unrelated tenant resource. The `allowAsID` parameter scopes the
// ID short-circuit to the case where the caller can vouch that projectRef
// came from an explicit user-supplied value (i.e. the `--project` flag
// was changed on the command line). When `allowAsID=false` we ALWAYS go
// through CreateProject get-or-create, so a UUID-shaped directory name
// becomes a benignly-named project rather than a misattribution incident.
//
// The legacy multipart POST /api/v1/cli/upload still exists with a Sunset of
// 2026-09-24, but new requests MUST go through the canonical endpoint so the
// product has one source of truth on auth + tenant scoping.
func (c *Client) UploadSBOM(projectRef string, allowAsID bool, sbomData []byte, format string) (*UploadResult, error) {
	// Step 1: resolve projectRef to a project ID.
	//
	// If projectRef is an explicitly-supplied canonical UUID
	// (allowAsID=true AND format matches), treat it as the ID directly —
	// no CreateProject round-trip, and crucially no risk of accidentally
	// creating a new project whose NAME is the UUID string. If the UUID
	// is invalid (no such project in this tenant) the canonical upload
	// endpoint will return 4xx and surface that to the operator.
	//
	// Otherwise — including the case of a UUID-shaped value that came
	// from the CLI's implicit dir-basename fallback (allowAsID=false) —
	// fall through to the get-or-create call as before.
	var (
		projectID      string
		projectName    string
		projectCreated bool
	)
	if allowAsID && looksLikeUUID(projectRef) {
		projectID = projectRef
		// We don't have the project's display name without an extra
		// GET; leave it empty — UploadResult.ProjectName is only used
		// for cosmetic output and the CLI prints the user-supplied
		// projectRef itself in the "アップロード中" line.
		projectName = ""
		projectCreated = false
	} else {
		project, created, err := c.CreateProject(projectRef, "")
		if err != nil {
			return nil, fmt.Errorf("プロジェクト解決エラー: %w", err)
		}
		if project == nil || project.ID == "" {
			return nil, fmt.Errorf("APIがプロジェクトIDを返しませんでした")
		}
		projectID = project.ID
		projectName = project.Name
		projectCreated = created
	}

	// Step 2: POST raw body to the canonical SBOM upload endpoint.
	url := fmt.Sprintf("%s/api/v1/projects/%s/sbom", c.baseURL, projectID)
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
		ProjectName:    projectName,
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

// VulnerabilitySummary aggregates vulnerability counts by severity for a
// single SBOM. It mirrors the API-side `VulnerabilitySummaryCount` type
// in apps/api/internal/handler/sbom.go — keep them in sync.
//
// `KEV` is orthogonal to CVSS severity (a KEV-listed CVE also counts in
// its CRITICAL/HIGH/etc. bucket) and is the authoritative source for
// `sbomhub scan --fail-on kev`. Older servers that do not emit this field
// will leave it at zero, in which case `--fail-on kev` is effectively a
// no-op against that server — operators who need the threshold should run
// against an api built from the same Trust Rescue R1 commit or later.
type VulnerabilitySummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	KEV      int `json:"kev"`
	Total    int `json:"total"`
}

// ScanStatusResponse is the body of
// GET /api/v1/projects/{project_id}/sboms/{sbom_id}/scan-status.
//
// Status values:
//
//   - "running":   background NVD/JVN scan in progress; counts are partial
//   - "completed": scan finished without errors; counts are authoritative
//   - "failed":    scan errored; Error has details; counts may be partial
//   - "unknown":   no tracker entry (server restart, very old sbom, …);
//                  callers should keep polling until --wait-timeout
//
// `sbomhub scan --fail-on <severity>` only enforces thresholds once
// Status == "completed".
type ScanStatusResponse struct {
	Status          string               `json:"status"`
	SbomID          string               `json:"sbom_id"`
	ProjectID       string               `json:"project_id"`
	Error           string               `json:"error,omitempty"`
	Vulnerabilities VulnerabilitySummary `json:"vulnerabilities"`
}

// GetScanStatus polls the per-SBOM scan-status endpoint. Returns the
// current state of the asynchronous NVD/JVN scan kicked off by
// POST /api/v1/projects/:id/sbom plus the current per-severity counts.
//
// Trust Rescue P1 #12: this is the contract that lets the CLI block a CI
// job on --fail-on <severity>.
//
// Codex R4 fix: the caller-supplied ctx is bound to the HTTP request via
// http.NewRequestWithContext so that --wait-timeout (modeled as
// context.WithTimeout in scan.go's waitForScanCompletion) actually aborts
// an in-flight request. Without the context binding the only timeout in
// effect was the Client.httpClient default 60s, so --wait-timeout=10s
// still hung for up to 60s on a slow server — violating the documented
// timeout contract.
//
// Codex R7 fix: non-2xx HTTP responses are returned as *APIError (instead
// of a stringly-wrapped fmt.Errorf) so the polling loop can classify
// 4xx as permanent (fast-fail with exit 3) vs 5xx / network as transient
// (retry within --wait-timeout). See APIError doc for the full rationale.
func (c *Client) GetScanStatus(ctx context.Context, projectID, sbomID string) (*ScanStatusResponse, error) {
	url := fmt.Sprintf("%s/api/v1/projects/%s/sboms/%s/scan-status", c.baseURL, projectID, sbomID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Message:    string(body),
			URL:        url,
		}
	}

	var out ScanStatusResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("レスポンス解析エラー: %w", err)
	}
	return &out, nil
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
