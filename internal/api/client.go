package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
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
	ProjectID          string `json:"project_id"`
	SBOMID             string `json:"sbom_id"`
	URL                string `json:"url"`
	VulnerabilityCount int    `json:"vulnerability_count"`
	Critical           int    `json:"critical"`
	High               int    `json:"high"`
	Medium             int    `json:"medium"`
	Low                int    `json:"low"`
}

// UploadSBOM uploads an SBOM to SBOMHub
func (c *Client) UploadSBOM(projectName string, sbomData []byte, format string) (*UploadResult, error) {
	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add project name
	if err := writer.WriteField("project_name", projectName); err != nil {
		return nil, err
	}

	// Add format
	if err := writer.WriteField("format", format); err != nil {
		return nil, err
	}

	// Add SBOM file
	part, err := writer.CreateFormFile("sbom", "sbom.json")
	if err != nil {
		return nil, err
	}
	if _, err := part.Write(sbomData); err != nil {
		return nil, err
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	// Create request
	url := fmt.Sprintf("%s/api/v1/cli/upload", c.baseURL)
	req, err := http.NewRequest("POST", url, &buf)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("APIエラー (%d): %s", resp.StatusCode, string(body))
	}

	var result UploadResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("レスポンス解析エラー: %w", err)
	}

	return &result, nil
}

// CheckResult represents the result of a vulnerability check
type CheckResult struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// CheckVulnerabilities checks an SBOM for vulnerabilities without uploading
func (c *Client) CheckVulnerabilities(sbomData []byte) (*CheckResult, error) {
	url := fmt.Sprintf("%s/api/v1/cli/check", c.baseURL)

	req, err := http.NewRequest("POST", url, bytes.NewReader(sbomData))
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

	return &result, nil
}

// Project represents a project
type Project struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ListProjects retrieves all projects
func (c *Client) ListProjects() ([]Project, error) {
	url := fmt.Sprintf("%s/api/v1/projects", c.baseURL)

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

	var projects []Project
	if err := json.Unmarshal(body, &projects); err != nil {
		return nil, fmt.Errorf("レスポンス解析エラー: %w", err)
	}

	return projects, nil
}
