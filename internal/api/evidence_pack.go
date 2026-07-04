package api

// Evidence Pack API client (M31 Wave C — F407, sbomhub-cli issue #7).
//
// Thin HTTP wrapper over the canonical build endpoint:
//
//	POST /api/v1/projects/:id/evidence-pack/build
//	Body: {"format":"zip"|"markdown",
//	       "include_vex_approved":true,
//	       "include_cra_approved":true,
//	       "include_meti_assessment":true}
//
// The response is format-dependent:
//   - format=zip      → application/zip, binary body, Content-Disposition
//     attachment; filename="evidence-pack-<project>-<ts>.zip"
//   - format=markdown → text/markdown, the existing Markdown bundle
//     (backwards-compatible with the browser-only path).
//
// In both cases the body is read verbatim into EvidencePackResult.Data so
// the CLI can write it to disk untouched. Response metadata (the server
// filename + VEX / CRA counts) is surfaced from headers when present but
// is never required — an older server that omits them leaves the count
// fields at -1 and the filename empty, and the CLI falls back to a
// locally-synthesised name.
//
// Error handling mirrors the M2 *CRAError pattern: a non-2xx response is
// returned as a typed *EvidencePackError so the `sbomhub evidence-pack`
// command can classify 400/403/404 as permanent (exit 3) and 429/5xx as
// transient (exit 4) rather than silently writing an error page to disk.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
)

// Evidence pack format allow-list. Mirrors the server-side accepted
// values (handler/evidence_pack.go). `markdown` preserves the existing
// browser path; `zip` is the M31 machine-readable bundle.
const (
	EvidencePackFormatZip      = "zip"
	EvidencePackFormatMarkdown = "markdown"
)

// BuildEvidencePackRequest is the JSON body for the build endpoint. The
// three include_* toggles default to true at the command layer so the
// pack bundles every approved artefact unless the operator opts out.
type BuildEvidencePackRequest struct {
	Format                string `json:"format"`
	IncludeVEXApproved    bool   `json:"include_vex_approved"`
	IncludeCRAApproved    bool   `json:"include_cra_approved"`
	IncludeMETIAssessment bool   `json:"include_meti_assessment"`
}

// EvidencePackResult holds the built pack bytes plus the metadata the CLI
// surfaces in its confirmation output.
//
// Data is the raw response body — zip binary or markdown text — written to
// disk verbatim by the caller. VEXCount / CRACount are -1 when the server
// did not emit the X-Evidence-Pack-*-Count headers (older server), so a
// caller can distinguish "zero approved drafts" (0) from "server did not
// tell us" (-1) and avoid printing a misleading count.
type EvidencePackResult struct {
	Format      string // effective format ("zip" | "markdown")
	Data        []byte // raw response body (binary zip or markdown text)
	Filename    string // server-supplied name from Content-Disposition (may be empty)
	ContentType string // response Content-Type
	VEXCount    int    // X-Evidence-Pack-VEX-Count, or -1 when absent
	CRACount    int    // X-Evidence-Pack-CRA-Count, or -1 when absent
}

// evidencePackOptions carries the include toggles resolved from the
// functional options. All default to true.
type evidencePackOptions struct {
	includeVEX  bool
	includeCRA  bool
	includeMETI bool
}

// EvidencePackOption configures which approved artefacts the server should
// bundle into the pack.
type EvidencePackOption func(*evidencePackOptions)

// WithVEXApproved toggles inclusion of approved VEX drafts (CycloneDX VEX).
func WithVEXApproved(include bool) EvidencePackOption {
	return func(o *evidencePackOptions) { o.includeVEX = include }
}

// WithCRAApproved toggles inclusion of approved CRA reports.
func WithCRAApproved(include bool) EvidencePackOption {
	return func(o *evidencePackOptions) { o.includeCRA = include }
}

// WithMETIAssessment toggles inclusion of the METI self-assessment rows.
func WithMETIAssessment(include bool) EvidencePackOption {
	return func(o *evidencePackOptions) { o.includeMETI = include }
}

// EvidencePackError is a typed non-2xx response from the build endpoint.
// Callers classify with IsPermanent / IsTransient so the exit-code
// mapping stays in one place (identical rationale to *CRAError).
type EvidencePackError struct {
	StatusCode int
	URL        string
	Method     string
	Message    string // top-level "error" field, when the body was JSON
	Raw        string // original body, preserved for debug logging
}

func (e *EvidencePackError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("evidence-pack API %s %s -> %d: %s", e.Method, e.URL, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("evidence-pack API %s %s -> %d: %s", e.Method, e.URL, e.StatusCode, e.Raw)
}

// IsPermanent reports whether the failure is a permanent 4xx the operator
// must fix before retrying (400 unsupported format, 403 write permission,
// 404 project not found). 429 is intentionally transient (matches the
// scan-polling and CRA classification).
func (e *EvidencePackError) IsPermanent() bool {
	if e == nil {
		return false
	}
	if e.StatusCode == http.StatusTooManyRequests {
		return false
	}
	return e.StatusCode >= 400 && e.StatusCode < 500
}

// IsTransient reports whether the failure is retryable — 429 (rate limit)
// and 5xx (server error / upstream blip).
func (e *EvidencePackError) IsTransient() bool {
	if e == nil {
		return false
	}
	if e.StatusCode == http.StatusTooManyRequests {
		return true
	}
	return e.StatusCode >= 500 && e.StatusCode < 600
}

// decodeEvidencePackError builds an EvidencePackError from a non-2xx body.
// Tolerates non-JSON bodies (gateway HTML pages) — Raw always carries the
// original text.
func decodeEvidencePackError(method, url string, status int, body []byte) *EvidencePackError {
	ee := &EvidencePackError{
		StatusCode: status,
		URL:        url,
		Method:     method,
		Raw:        string(body),
	}
	var parsed struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil {
		ee.Message = parsed.Error
	}
	return ee
}

// BuildEvidencePack requests a compliance evidence pack for the project and
// returns the raw bytes plus response metadata. `format` is sent verbatim
// (the caller validates the zip|markdown allow-list); an unsupported value
// surfaces honestly as a 400 *EvidencePackError rather than being masked
// client-side.
func (c *Client) BuildEvidencePack(ctx context.Context, projectID, format string, opts ...EvidencePackOption) (*EvidencePackResult, error) {
	// Default: bundle every approved artefact unless the caller opts out.
	o := evidencePackOptions{includeVEX: true, includeCRA: true, includeMETI: true}
	for _, fn := range opts {
		fn(&o)
	}

	reqBody := BuildEvidencePackRequest{
		Format:                format,
		IncludeVEXApproved:    o.includeVEX,
		IncludeCRAApproved:    o.includeCRA,
		IncludeMETIAssessment: o.includeMETI,
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("evidence-pack リクエストのシリアライズに失敗: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/v1/projects/%s/evidence-pack/build", c.baseURL, projectID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("evidence-pack リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("evidence-pack レスポンス読み込みエラー: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, decodeEvidencePackError(http.MethodPost, endpoint, resp.StatusCode, respBody)
	}

	result := &EvidencePackResult{
		Format:      format,
		Data:        respBody,
		ContentType: resp.Header.Get("Content-Type"),
		Filename:    filenameFromContentDisposition(resp.Header.Get("Content-Disposition")),
		VEXCount:    headerCountOrNeg(resp.Header.Get("X-Evidence-Pack-VEX-Count")),
		CRACount:    headerCountOrNeg(resp.Header.Get("X-Evidence-Pack-CRA-Count")),
	}
	// Prefer the server-declared format if it echoes one — keeps the CLI
	// honest if a future server normalises the requested value.
	if f := strings.TrimSpace(resp.Header.Get("X-Evidence-Pack-Format")); f != "" {
		result.Format = f
	}
	return result, nil
}

// filenameFromContentDisposition extracts the filename param from a
// Content-Disposition header (e.g. `attachment; filename="pack.zip"`).
// Returns "" when the header is absent or unparseable. The result is
// passed through filepath.Base by the caller before use so a hostile
// `../` value cannot escape the target directory.
func filenameFromContentDisposition(header string) string {
	if strings.TrimSpace(header) == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(header)
	if err != nil {
		return ""
	}
	name := strings.TrimSpace(params["filename"])
	if name == "" {
		return ""
	}
	// Defence in depth: never let the server dictate a path, only a name.
	return filepath.Base(name)
}

// headerCountOrNeg parses a non-negative integer count header, returning
// -1 when the header is absent or malformed so the caller can tell "server
// said zero" from "server did not say".
func headerCountOrNeg(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return -1
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return -1
	}
	return n
}
