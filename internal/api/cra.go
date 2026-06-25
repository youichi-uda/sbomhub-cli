package api

// CRA report API client — wraps the M2 Wave M2-4 CRA report endpoints
// (sbomhub/apps/api/internal/handler/cra_reports.go — truth source):
//
//	POST   /api/v1/projects/:id/cra-reports/run
//	GET    /api/v1/projects/:id/cra-reports
//	GET    /api/v1/projects/:id/cra-reports/:report_id
//	PUT    /api/v1/projects/:id/cra-reports/:report_id/decision
//	POST   /api/v1/projects/:id/cra-reports/:report_id/reanalyse
//
// The CLI's `sbomhub cra` subcommand uses these to draft, list, view,
// and decide on CRA (Cyber Resilience Act) compliance reports drafted
// from an existing VEX triage decision (PRODUCT_REBOOT_PLAN §7.2 / §13
// M2 — "approved な vex_drafts から取得").
//
// All five helpers share the existing api.Client (Bearer auth, base
// URL, default 60s timeout). Non-2xx responses fall through to the
// shared parsing helper decodeCRAError which mirrors the M1 triage
// pattern: typed CRAError + IsAIDisabled / IsPermanent / IsTransient
// helpers so the CLI loop can classify failures and surface the right
// exit code without sprinkling status-code checks across the command
// layer.
//
// M1 fix patterns carried over to CRA (regression coverage in
// cra_test.go):
//   - F21 exit code classification (3 permanent, 4 transient)
//   - F22 strict AI-disabled detection (503 + known reason markers)
//   - F23 2xx response contract validation (no report → ProtocolError)
//   - F26 paginated ListReports via limit+offset loop (server cap 500)
//   - F28 X-Total-Count header captured into the list result

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ----------------------------------------------------------------------------
// Wire DTOs (mirror sbomhub/apps/api/internal/handler/cra_reports.go)
// ----------------------------------------------------------------------------

// CRARunReportRequest is the body of POST /cra-reports/run.
//
// VulnerabilityID + CVEID + ReportType + Lang are required by the
// server. SourceVEXDraftID pins the draft to a specific approved VEX
// decision; when empty, the runner picks the most recent approved
// draft for (project, cve) — failing 409 when none exists (operator
// must run `sbomhub triage` first).
//
// The "regulatory pass-through" fields (ProductName, VendorName,
// ReporterName, etc.) are forwarded verbatim because the LLM is
// forbidden from hallucinating compliance identifiers — see
// service/cra/runner.go buildTemplateData. The CLI lets the operator
// supply them via flags (M2 MVP) or a YAML file (deferred to M3).
type CRARunReportRequest struct {
	VulnerabilityID  string `json:"vulnerability_id"`
	CVEID            string `json:"cve_id"`
	SourceVEXDraftID string `json:"source_vex_draft_id,omitempty"`
	ReportType       string `json:"report_type"`
	Lang             string `json:"lang"`

	ProductName    string `json:"product_name,omitempty"`
	ProductVersion string `json:"product_version,omitempty"`
	VendorName     string `json:"vendor_name,omitempty"`
	ReporterName   string `json:"reporter_name,omitempty"`
	ReporterRole   string `json:"reporter_role,omitempty"`
	ContactEmail   string `json:"contact_email,omitempty"`
	ContactPhone   string `json:"contact_phone,omitempty"`
	AwarenessTime  string `json:"awareness_time,omitempty"`
	ReportID       string `json:"report_id,omitempty"`
}

// CRAReport mirrors repository.CRAReport. JSON tags match the server-
// side struct verbatim so the CLI decodes the handler response without
// a parallel DTO (M1 #F28 carried over — wire-shape drift between
// repository and handler caused silent UI breakage).
//
// Pointer fields use the same `nil ≡ absent / non-nil ≡ present`
// contract as the server-side row. Timestamps are surfaced as strings
// because the M2 CLI only displays them; downstream consumers that
// need time.Time can parse from CreatedAt / UpdatedAt themselves.
type CRAReport struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`

	ProjectID       string `json:"project_id"`
	VulnerabilityID string `json:"vulnerability_id"`

	CVEID string `json:"cve_id"`

	// Report milestone: 'early_warning' | 'detailed_notification' | 'final_report'.
	ReportType string `json:"report_type"`

	// Language: 'ja' | 'en'.
	Lang string `json:"lang"`

	// Publication lifecycle: 'draft' | 'approved' | 'submitted' | 'archived'.
	State string `json:"state"`

	// Rendered report body. Required by the DB (NOT NULL).
	DraftText string `json:"draft_text"`

	// LLM provenance.
	Provider     string `json:"provider,omitempty"`
	Model        string `json:"model,omitempty"`
	PromptHash   string `json:"prompt_hash,omitempty"`
	ResponseHash string `json:"response_hash,omitempty"`

	// JSONB array of {kind, ref} citations. Server enforces NOT NULL +
	// CHECK length > 0; we surface the raw bytes so callers that want
	// to render evidence can json.Unmarshal further.
	Evidence json.RawMessage `json:"evidence,omitempty"`

	SourceVEXDraftID *string `json:"source_vex_draft_id,omitempty"`
	LLMCallID        *string `json:"llm_call_id,omitempty"`

	// Decision lifecycle (independent of State).
	Decision     string  `json:"decision"`
	DecisionBy   *string `json:"decision_by,omitempty"`
	DecisionAt   *string `json:"decision_at,omitempty"`
	DecisionNote string  `json:"decision_note,omitempty"`

	CreatedBy *string `json:"created_by,omitempty"`

	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// CRARunReportResult is the wire shape returned by POST /cra-reports/run
// and POST /cra-reports/:id/reanalyse.
//
// AIDisabled is true when the runner skipped the LLM call because no
// BYOK provider is configured. The server still persists a synthetic
// `ai_disabled` evidence row + audit trail; the CLI uses this flag to
// surface the "APIキー未設定" hint without inventing a counter-only
// fallback (mirrors M1 #F4 / triage AIDisabled pattern).
type CRARunReportResult struct {
	Report     *CRAReport `json:"report"`
	LLMCallID  string     `json:"llm_call_id,omitempty"`
	AIDisabled bool       `json:"ai_disabled,omitempty"`

	// Error is an optional top-level error string. A well-behaved
	// server NEVER emits this on a 2xx response — when present it is
	// the F23 protocol-violation signal: the handler returned HTTP 200
	// but logically failed. The CLI promotes this to a transient
	// *CRAError in RunReport / ReanalyseReport so the exit-code path
	// can flag the failure.
	Error string `json:"error,omitempty"`
}

// CRAReportListFilter narrows ListReports. Empty fields are not sent
// to the server (zero-valued query params have no effect server-side
// anyway, but skipping them keeps the URL clean for diffability).
type CRAReportListFilter struct {
	CVEID      string
	ReportType string // early_warning | detailed_notification | final_report
	Lang       string // ja | en
	State      string // draft | approved | submitted | archived
	Decision   string // pending | approved | edited | rejected
	Limit      int
	Offset     int
}

// craReportListResponse mirrors handler.craReportListResponse.
type craReportListResponse struct {
	Reports []CRAReport `json:"reports"`
}

// CRADecisionRequest is the body of PUT /cra-reports/:id/decision.
//
// Decision must be one of "approved" | "edited" | "rejected" — the
// server 400s other values. EditedDraftText is a pointer because the
// server uses the nil/non-nil distinction to tell "do not change"
// apart from "set to empty"; for "approved" / "rejected" it is ignored.
type CRADecisionRequest struct {
	Decision        string  `json:"decision"`
	DecisionNote    string  `json:"decision_note,omitempty"`
	EditedDraftText *string `json:"edited_draft_text,omitempty"`
}

// ----------------------------------------------------------------------------
// Error decoding
// ----------------------------------------------------------------------------

// CRAError is the typed error returned by the CRA helpers when the
// server emits a non-2xx response. It carries the parsed JSON body
// (`error` + optional `reason`) so the CLI can branch on:
//
//   - 503 + AI-disabled reason → llm.DisabledError → under_investigation fallback
//   - 409                       → no approved VEX draft (operator must triage first)
//   - other 4xx                 → permanent user / config error
//   - 5xx (non-503)             → transient server error
//
// Callers test category with the helpers IsAIDisabled / IsPermanent /
// IsTransient so the classification stays in one place — identical
// rationale to the M1 *TriageError pattern.
type CRAError struct {
	StatusCode int
	URL        string
	Method     string
	Message    string // top-level "error" field
	Reason     string // "reason" field (only populated for 503 DisabledError)
	Raw        string // original body, preserved for debug logging

	// ProtocolError flags a synthesised CRAError raised for a 2xx
	// response that violated the success contract — server returned
	// HTTP 200/201 but the body had no report (and was not flagged
	// ai_disabled), or carried an explicit "error" field. Callers
	// inspect this via IsTransient (always true when set) so the CLI
	// loop surfaces such bugs through the exit-4 transient path
	// instead of silently bucketing the call as a success
	// (mirrors M1 #F23).
	ProtocolError bool
}

func (e *CRAError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("cra API %s %s -> %d: %s (%s)", e.Method, e.URL, e.StatusCode, e.Message, e.Reason)
	}
	if e.Message != "" {
		return fmt.Sprintf("cra API %s %s -> %d: %s", e.Method, e.URL, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("cra API %s %s -> %d: %s", e.Method, e.URL, e.StatusCode, e.Raw)
}

// craAIDisabledReasonMarkers are the substrings (case-insensitive) we
// recognise as the BYOK-not-configured signal on a 503 response.
//
// M1 #F22 carry-over: only 503s with a recognised reason text classify
// as AI-disabled. Anything else on 503 is treated as a real outage and
// classifies as transient (see IsTransient). Without this strict check,
// a gateway 503 page would silently be mis-classified as "BYOK off" and
// the CLI would exit 0 with zero persisted reports.
var craAIDisabledReasonMarkers = []string{
	"ai features are disabled",
	"byok key not configured",
	"byok not configured",
}

// IsAIDisabled reports whether the server signalled the BYOK-not-
// configured fallback path. The canonical M2-4 server may also signal
// AI-disabled on a 2xx via CRARunReportResult.AIDisabled; the CLI
// inspects that field directly on the 2xx path and consults this
// helper only on the error path (legacy 503 compat).
func (e *CRAError) IsAIDisabled() bool {
	if e == nil || e.StatusCode != http.StatusServiceUnavailable {
		return false
	}
	hay := strings.ToLower(e.Message + " " + e.Reason + " " + e.Raw)
	for _, m := range craAIDisabledReasonMarkers {
		if strings.Contains(hay, m) {
			return true
		}
	}
	return false
}

// IsPermanent reports whether the error is a permanent 4xx that the
// caller cannot retry without fixing config (auth / input validation /
// missing report / no approved VEX draft). 429 is intentionally
// transient (matches scan polling loop classification).
//
// 503 is never permanent — it is either AI-disabled (handled by
// IsAIDisabled) or a transient outage (handled by IsTransient).
//
// 409 (no approved VEX draft for this (project, cve)) is treated as
// permanent because the operator's correct response is "go run
// sbomhub triage on this CVE first", NOT "retry tomorrow".
func (e *CRAError) IsPermanent() bool {
	if e == nil {
		return false
	}
	if e.StatusCode == http.StatusTooManyRequests {
		return false
	}
	if e.StatusCode == http.StatusServiceUnavailable {
		return false
	}
	return e.StatusCode >= 400 && e.StatusCode < 500
}

// IsTransient reports whether the error is a transient failure the
// operator can resolve by retrying — 429 (rate limit) and 5xx (server
// error / upstream blip). The bucket is symmetric with IsPermanent so
// the CLI loop can categorise each failure into exactly one of:
// AI-disabled (caller-handled), permanent, transient, or unclassified.
//
// ProtocolError joins the transient bucket because the operator's
// correct response is the same (retry, possibly after a server
// redeploy) — mirrors M1 #F23.
func (e *CRAError) IsTransient() bool {
	if e == nil {
		return false
	}
	if e.ProtocolError {
		return true
	}
	if e.StatusCode == http.StatusTooManyRequests {
		return true
	}
	if e.StatusCode == http.StatusServiceUnavailable {
		// AI-disabled wins via IsAIDisabled() and the caller short-
		// circuit; everything else on 503 is a real outage that the
		// operator can resolve by retrying.
		return !e.IsAIDisabled()
	}
	return e.StatusCode >= 500 && e.StatusCode < 600
}

// decodeCRAError builds a CRAError from a non-2xx response body.
// Tolerates non-JSON bodies (intermediate gateways sometimes send
// HTML 502 pages) — Raw always carries the original text.
func decodeCRAError(method, url string, status int, body []byte) *CRAError {
	te := &CRAError{
		StatusCode: status,
		URL:        url,
		Method:     method,
		Raw:        string(body),
	}
	var parsed struct {
		Error  string `json:"error"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil {
		te.Message = parsed.Error
		te.Reason = parsed.Reason
	}
	return te
}

// ----------------------------------------------------------------------------
// RunReport — POST /api/v1/projects/:id/cra-reports/run
// ----------------------------------------------------------------------------

// RunReport executes one CRA report drafting cycle for (project, cve)
// on the server and returns the persisted report + AIDisabled flag.
//
// 409 from cra.ErrNoApprovedVEXDraft is returned as a *CRAError where
// IsPermanent() == true — the CLI surfaces this with an actionable
// "run sbomhub triage first" hint via mapCRARunReportError above the
// CLI layer.
func (c *Client) RunReport(ctx context.Context, projectID string, req CRARunReportRequest) (*CRARunReportResult, error) {
	endpoint := fmt.Sprintf("%s/api/v1/projects/%s/cra-reports/run", c.baseURL, projectID)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("cra-report リクエストのシリアライズに失敗: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("cra-report リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, decodeCRAError(http.MethodPost, endpoint, resp.StatusCode, respBody)
	}

	return decodeRunReportResult(http.MethodPost, endpoint, resp.StatusCode, respBody)
}

// ----------------------------------------------------------------------------
// ListReports — GET /api/v1/projects/:id/cra-reports
// ----------------------------------------------------------------------------

// craReportsListPageSize is the per-page request size the CLI uses
// when paging /cra-reports. M1 #F26 carry-over: the server caps
// ?limit= at MaxCRAReportsListLimit (500) and returns 400 on out-of-
// band values, so the CLI requests pages at the maximum allowed size
// to minimise round-trips while staying within the server's clamp.
//
// ※要確認: keep this in sync with sbomhub/apps/api/internal/handler/
// cra_reports.go MaxCRAReportsListLimit (500). If the server raises
// the cap, the CLI can be updated independently, but a value above
// the server's cap will start returning 400 on the first request.
const craReportsListPageSize = 500

// craReportsListMaxPages is a defensive ceiling on the number of pages
// the CLI is willing to fetch before erroring out. Tuned to match
// MaxCRAReportsListOffset (10000) / craReportsListPageSize (500) so
// the loop cannot iterate past the server's offset clamp.
//
// ※要確認: server caps offset at 10000 (cra_reports.go
// MaxCRAReportsListOffset), so the effective cap is 20 pages — but
// we set a slightly higher ceiling (25) so the loop reports a more
// helpful error than the server's 400 if a future server raises the
// offset cap without coordinating with the CLI.
const craReportsListMaxPages = 25

// ListReports returns the project's CRA reports (paginated). Returns
// the joined slice + the server's X-Total-Count (M1 #F28 carried over)
// + an error.
//
// Filter.Limit / Filter.Offset are IGNORED — the CLI always pages
// through the full set. Callers that want a hard cap should slice the
// result. This keeps the paging contract centralised here rather than
// duplicated at every call site.
//
// M1 #F26 carry-over: pages through using craReportsListPageSize per
// request and stops when either:
//   - a page returns fewer rows than the requested page size (canonical
//     "no more rows" signal), or
//   - craReportsListMaxPages is reached (defensive ceiling).
func (c *Client) ListReports(ctx context.Context, projectID string, filter CRAReportListFilter) ([]CRAReport, int, error) {
	all := make([]CRAReport, 0, craReportsListPageSize)
	offset := 0
	total := 0
	for page := 0; page < craReportsListMaxPages; page++ {
		batch, pageTotal, err := c.listReportsPage(ctx, projectID, filter, craReportsListPageSize, offset)
		if err != nil {
			return nil, 0, err
		}
		all = append(all, batch...)
		// X-Total-Count is stable across pages (it counts the matching
		// filtered set, not the current page) — preserve the first
		// page's value but accept later pages updating it if the
		// server changes its mind mid-walk.
		if pageTotal > 0 {
			total = pageTotal
		}
		if len(batch) < craReportsListPageSize {
			return all, total, nil
		}
		offset += len(batch)
	}
	return all, total, fmt.Errorf("cra-reports ページング上限 (%d ページ × %d 件) 到達: サーバーがページング終端を返していない可能性があります",
		craReportsListMaxPages, craReportsListPageSize)
}

// listReportsPage fetches a single (limit, offset) page from the
// server. Extracted from ListReports so the paging loop stays readable
// and so tests can drive the per-page decode independently.
func (c *Client) listReportsPage(ctx context.Context, projectID string, filter CRAReportListFilter, limit, offset int) ([]CRAReport, int, error) {
	endpoint := fmt.Sprintf("%s/api/v1/projects/%s/cra-reports", c.baseURL, projectID)

	q := url.Values{}
	if filter.CVEID != "" {
		q.Set("cve_id", filter.CVEID)
	}
	if filter.ReportType != "" {
		q.Set("report_type", filter.ReportType)
	}
	if filter.Lang != "" {
		q.Set("lang", filter.Lang)
	}
	if filter.State != "" {
		q.Set("state", filter.State)
	}
	if filter.Decision != "" {
		q.Set("decision", filter.Decision)
	}
	q.Set("limit", strconv.Itoa(limit))
	if offset > 0 {
		q.Set("offset", strconv.Itoa(offset))
	}
	endpoint = endpoint + "?" + q.Encode()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, 0, fmt.Errorf("cra-reports リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, 0, decodeCRAError(http.MethodGet, endpoint, resp.StatusCode, respBody)
	}

	var out craReportListResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, 0, fmt.Errorf("cra-reports レスポンス解析エラー: %w", err)
	}
	if out.Reports == nil {
		out.Reports = []CRAReport{}
	}

	// M1 #F28 carry-over: X-Total-Count is the source of truth for
	// the matching filtered count. Falls back to 0 (caller treats 0
	// as "no count available") when the header is missing or
	// unparseable so a legacy server cannot break the page loop.
	total := 0
	if v := resp.Header.Get("X-Total-Count"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			total = n
		}
	}

	return out.Reports, total, nil
}

// ----------------------------------------------------------------------------
// GetReport — GET /api/v1/projects/:id/cra-reports/:report_id
// ----------------------------------------------------------------------------

// GetReport fetches one CRA report scoped to (tenant, project, report).
// The server returns 404 with a generic body for both "report does not
// exist" and "report belongs to another project of this tenant" (M1
// F8/F9 / handler.loadReportScoped); from the CLI's perspective both
// land as IsPermanent → exit 3.
func (c *Client) GetReport(ctx context.Context, projectID, reportID string) (*CRAReport, error) {
	endpoint := fmt.Sprintf("%s/api/v1/projects/%s/cra-reports/%s", c.baseURL, projectID, reportID)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("cra-report 取得エラー: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, decodeCRAError(http.MethodGet, endpoint, resp.StatusCode, respBody)
	}

	var out CRAReport
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("cra-report レスポンス解析エラー: %w", err)
	}
	return &out, nil
}

// ----------------------------------------------------------------------------
// DecideReport — PUT /api/v1/projects/:id/cra-reports/:report_id/decision
// ----------------------------------------------------------------------------

// DecideReport applies a human approve / edit / reject decision to a
// CRA report row. The server mirrors the decision into the audit log
// (`cra_report_decided` action) — neither concern surfaces in this
// client API.
func (c *Client) DecideReport(ctx context.Context, projectID, reportID string, dec CRADecisionRequest) (*CRAReport, error) {
	endpoint := fmt.Sprintf("%s/api/v1/projects/%s/cra-reports/%s/decision", c.baseURL, projectID, reportID)

	body, err := json.Marshal(dec)
	if err != nil {
		return nil, fmt.Errorf("cra-decision リクエストのシリアライズに失敗: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("cra-decision リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, decodeCRAError(http.MethodPut, endpoint, resp.StatusCode, respBody)
	}

	var out CRAReport
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("cra-decision レスポンス解析エラー: %w", err)
	}
	return &out, nil
}

// ----------------------------------------------------------------------------
// ReanalyseReport — POST /api/v1/projects/:id/cra-reports/:report_id/reanalyse
// ----------------------------------------------------------------------------

// ReanalyseReport runs a fresh CRA report drafting cycle for an
// existing report — useful when the AI evidence has improved or the
// operator wants to compare a re-run against the original. The server
// inserts a NEW cra_reports row (the original is preserved) so
// reviewers can diff AI verdicts over time.
//
// The override body MAY override report_type / lang / source vex
// draft id / regulatory pass-through fields; if omitted, the server
// re-uses the values from the source report.
func (c *Client) ReanalyseReport(ctx context.Context, projectID, reportID string, override CRARunReportRequest) (*CRARunReportResult, error) {
	endpoint := fmt.Sprintf("%s/api/v1/projects/%s/cra-reports/%s/reanalyse", c.baseURL, projectID, reportID)

	body, err := json.Marshal(override)
	if err != nil {
		return nil, fmt.Errorf("cra-reanalyse リクエストのシリアライズに失敗: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("cra-reanalyse リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, decodeCRAError(http.MethodPost, endpoint, resp.StatusCode, respBody)
	}

	return decodeRunReportResult(http.MethodPost, endpoint, resp.StatusCode, respBody)
}

// ----------------------------------------------------------------------------
// Shared helpers
// ----------------------------------------------------------------------------

// decodeRunReportResult parses a 2xx response body for RunReport /
// ReanalyseReport and validates the success contract (M1 #F23 carried
// over): a 2xx response MUST carry (a) Error == "" AND (b) a non-nil
// Report. Either violation is surfaced as a ProtocolError so the CLI
// can route it through IsTransient → exit code 4 rather than silently
// treating the call as a success with a nil report.
func decodeRunReportResult(method, endpoint string, status int, body []byte) (*CRARunReportResult, error) {
	var out CRARunReportResult
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("cra-report レスポンス解析エラー: %w", err)
	}

	if out.Error != "" {
		return nil, &CRAError{
			StatusCode:    status,
			URL:           endpoint,
			Method:        method,
			Message:       out.Error,
			Raw:           string(body),
			ProtocolError: true,
		}
	}
	if out.Report == nil {
		var msg string
		if out.AIDisabled {
			msg = "cra-report success response carried ai_disabled=true but no report persisted (server bug — contract violation)"
		} else {
			msg = "cra-report success response missing report (server protocol error — F23 contract violation)"
		}
		return nil, &CRAError{
			StatusCode:    status,
			URL:           endpoint,
			Method:        method,
			Message:       msg,
			Raw:           string(body),
			ProtocolError: true,
		}
	}
	return &out, nil
}
