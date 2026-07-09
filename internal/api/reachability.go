package api

// Reachability API client — wraps the M32 client-side reachability upload
// endpoint plus the vulnerability read-back the CLI needs to know which
// (component, cve) pairs to analyze:
//
//	GET    /api/v1/projects/:id/vulnerabilities   (read-back — reused shape)
//	POST   /api/v1/projects/:id/reachability      (upload verdicts)
//
// PRIVACY: `sbomhub reachability` runs the analyzer against the user's
// local source tree CLIENT-SIDE. The backend never receives the source —
// only the per-(component, cve) verdicts uploaded here. This client
// therefore uploads a compact result set (status + confidence + evidence
// pointers), not code.
//
// The upload result struct's JSON tags mirror the frozen server contract
// (reachability_results columns, migration 034): component_id, cve_id,
// ecosystem, status, confidence, analyzer_version, analyzed_at, evidence.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ----------------------------------------------------------------------------
// Upload — POST /api/v1/projects/:id/reachability
// ----------------------------------------------------------------------------

// ReachabilityUploadResult is one verdict row in the upload body. The JSON
// tag set MUST match the frozen server contract exactly — the server keys
// upserts by (tenant, project, component_id, cve_id) and CHECK-constrains
// status ∈ {not_present, import_only, reachable, unknown}.
//
// Evidence is the analyzer's evidence array serialised verbatim
// (json.RawMessage) so this package stays decoupled from
// internal/reachability — the command marshals reachability.EvidencePointer
// into it. omitempty keeps the field absent (rather than `null`) when the
// analyzer produced no evidence.
type ReachabilityUploadResult struct {
	ComponentID     string          `json:"component_id"`
	CVEID           string          `json:"cve_id"`
	Ecosystem       string          `json:"ecosystem"`
	Status          string          `json:"status"`
	Confidence      float64         `json:"confidence"`
	AnalyzerVersion string          `json:"analyzer_version"`
	AnalyzedAt      time.Time       `json:"analyzed_at"`
	Evidence        json.RawMessage `json:"evidence,omitempty"`
}

// reachabilityUploadRequest is the POST body envelope: {"results":[...]}.
type reachabilityUploadRequest struct {
	Results []ReachabilityUploadResult `json:"results"`
}

// ReachabilityError is the typed error surfaced when the reachability
// endpoints return a non-2xx response. It carries the parsed JSON `error`
// field (when present) plus the raw body for debugging. The upload path
// treats every non-201 as a hard failure — no partial-success claim.
type ReachabilityError struct {
	StatusCode int
	URL        string
	Method     string
	Message    string // top-level "error" field, when the body parsed as JSON
	Raw        string // original body
}

func (e *ReachabilityError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("reachability API %s %s -> %d: %s", e.Method, e.URL, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("reachability API %s %s -> %d: %s", e.Method, e.URL, e.StatusCode, e.Raw)
}

// IsPermanent reports whether the failure is a permanent 4xx the operator
// must fix (400 bad body, 403 read-only key, 404 missing project) rather
// than retry. 429 is treated as transient.
func (e *ReachabilityError) IsPermanent() bool {
	if e == nil {
		return false
	}
	if e.StatusCode == http.StatusTooManyRequests {
		return false
	}
	return e.StatusCode >= 400 && e.StatusCode < 500
}

func decodeReachabilityError(method, url string, status int, body []byte) *ReachabilityError {
	re := &ReachabilityError{
		StatusCode: status,
		URL:        url,
		Method:     method,
		Raw:        string(body),
	}
	var parsed struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil {
		re.Message = parsed.Error
	}
	return re
}

// UploadReachability POSTs the client-side reachability verdicts to the
// backend. The body is {"results":[...]}. On success the server returns
// 201 Created; any other status is surfaced as a *ReachabilityError with
// the server's body preserved (400 invalid payload, 403 read-only API
// key, 404 unknown project, 5xx server error). No partial-success is
// claimed — a non-201 means nothing was persisted from the CLI's point of
// view.
func (c *Client) UploadReachability(ctx context.Context, projectID string, results []ReachabilityUploadResult) error {
	endpoint := fmt.Sprintf("%s/api/v1/projects/%s/reachability", c.baseURL, projectID)

	if results == nil {
		results = []ReachabilityUploadResult{}
	}
	body, err := json.Marshal(reachabilityUploadRequest{Results: results})
	if err != nil {
		return fmt.Errorf("reachability リクエストのシリアライズに失敗: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("reachability リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return decodeReachabilityError(http.MethodPost, endpoint, resp.StatusCode, respBody)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Targets — GET /api/v1/projects/:id/reachability/targets
// ----------------------------------------------------------------------------

// ReachabilityTarget is one (cve, affected-component) pair the reachability
// command analyzes. It is decoded from the Wave E server endpoint
// GET /api/v1/projects/:id/reachability/targets, which joins
// component_vulnerabilities so every row carries a real component_id + purl
// (no CLI-side stopgap needed). One row per (cve_id, component_id); the same
// purl may appear under several component_ids (multiple SBOMs), each of
// which gets its own uploaded verdict.
//
// Purl is "" when the component has no package URL; the command skips such a
// target (no module coordinate can be derived) and reports it. Ecosystem is
// the server-derived token (pkg:golang→"go", pkg:npm→"npm", …); it is
// forwarded verbatim onto the uploaded verdict.
//
// VulnFuncs (M43, issue #168) is the server-normalized vulnerable symbol
// list for this (cve, component) pair — one "Pkg.Func" or
// "Pkg.Type.Method" entry per element. The CLI forwards it verbatim into
// the analyzer's VulnerableSymbols input (the server owns normalization;
// no client-side re-sanitizing beyond dropping blank entries). Old
// servers omit the field entirely → nil → the analyzer runs stage 1 only
// (import_only granularity), preserving the pre-M43 behavior (graceful
// degrade).
type ReachabilityTarget struct {
	CVEID            string   `json:"cve_id"`
	ComponentID      string   `json:"component_id"`
	Purl             string   `json:"purl"`
	ComponentName    string   `json:"component_name"`
	ComponentVersion string   `json:"component_version"`
	Ecosystem        string   `json:"ecosystem"`
	VulnFuncs        []string `json:"vuln_funcs"`
}

// GetReachabilityTargets returns the (cve, component) pairs the project's
// SBOMs expose for reachability analysis. ecosystem, when non-empty, is
// forwarded as ?ecosystem= so the server filters by derived ecosystem
// (pass "go" — the analyzer is Go-only this milestone). Returns an empty
// slice (not nil) when there are none. 404 (unknown project) / 403
// (read-only key) surface as *ReachabilityError.
func (c *Client) GetReachabilityTargets(ctx context.Context, projectID, ecosystem string) ([]ReachabilityTarget, error) {
	endpoint := fmt.Sprintf("%s/api/v1/projects/%s/reachability/targets", c.baseURL, projectID)
	if e := strings.TrimSpace(ecosystem); e != "" {
		endpoint += "?ecosystem=" + url.QueryEscape(e)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("reachability targets リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, decodeReachabilityError(http.MethodGet, endpoint, resp.StatusCode, respBody)
	}

	var out struct {
		Targets []ReachabilityTarget `json:"targets"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("reachability targets レスポンス解析エラー: %w", err)
	}
	if out.Targets == nil {
		return []ReachabilityTarget{}, nil
	}
	return out.Targets, nil
}

// ModulePath returns the Go module coordinate for this target's affected
// component, derived from its purl (pkg:golang/<module>@<version> →
// <module>), plus ok=true on success. Returns ("", false) when the target
// has no purl or a non-golang purl — the caller skips such a target since
// no module can be matched against the local go.mod.
func (t ReachabilityTarget) ModulePath() (module string, ok bool) {
	return goModuleFromPurl(t.Purl)
}

// goModuleFromPurl extracts the Go module path from a Package URL of the
// form pkg:golang/<namespace>/<name>@<version>?<qualifiers>#<subpath>.
//
// For Go, the module path is the namespace + name joined with "/", e.g.
//
//	pkg:golang/github.com/jackc/pgx/v5@v5.5.0  -> github.com/jackc/pgx/v5
//	pkg:golang/example.test/vulnpkg@v1.0.0     -> example.test/vulnpkg
//
// Returns ("", false) for empty input or a non-golang purl type — the
// caller then falls back to the component name.
func goModuleFromPurl(purl string) (string, bool) {
	s := strings.TrimSpace(purl)
	if s == "" {
		return "", false
	}
	// The purl type is case-insensitive per the purl spec; the server-side
	// derivation (sbomhub apps/api/internal/handler/reachability.go
	// goModuleFromPurl, M43 Phase D R9) matches it with EqualFold — the
	// two implementations MUST stay in lockstep or scoped vuln_funcs
	// delivery and CLI module derivation diverge. The "pkg:" scheme stays
	// exact-case (mirroring the server), the module path body keeps its
	// case, and a bare "golang/..." form (producers omitting the scheme)
	// is still tolerated.
	rest := strings.TrimPrefix(s, "pkg:")
	i := strings.IndexByte(rest, '/')
	if i < 0 || !strings.EqualFold(rest[:i], "golang") {
		return "", false
	}
	s = rest[i+1:]
	// Strip version (@), qualifiers (?) and subpath (#) — the module path
	// is everything before the first of these.
	if i := strings.IndexAny(s, "@?#"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return "", false
	}
	// purl path segments are percent-encoded; decode conservatively.
	if decoded, err := url.PathUnescape(s); err == nil {
		s = decoded
	}
	return s, true
}
