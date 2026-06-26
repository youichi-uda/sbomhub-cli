package api

// METI self-assessment API client — wraps the M3 Wave M3-4 endpoints
// (sbomhub/apps/api/internal/handler/meti.go — truth source):
//
//	GET    /api/v1/projects/:id/meti/assessment
//	POST   /api/v1/projects/:id/meti/assessment/refresh
//	PUT    /api/v1/projects/:id/meti/assessment/:criterion_id/override
//	DELETE /api/v1/projects/:id/meti/assessment/:criterion_id/override
//	GET    /api/v1/projects/:id/meti/improvement-actions
//
// The CLI's `sbomhub meti` subcommand uses these to list / refresh /
// override the project's 27-item METI 手引 ver 2.0 self-assessment
// (3 phases × ~9 criteria — env_setup / sbom_creation / sbom_operation)
// drawn from PRODUCT_REBOOT_PLAN.md §13 M3.
//
// All four helpers share the existing api.Client (Bearer auth, base
// URL, default 60s timeout). Non-2xx responses fall through to
// decodeMetiError which mirrors the M2 CRA error pattern: typed
// MetiError + IsPermanent / IsTransient helpers so the CLI loop can
// classify failures and surface the right exit code without sprinkling
// status-code checks across the command layer.
//
// M1 / M2 fix patterns carried over to METI (regression coverage in
// meti_test.go):
//   - F21 exit code classification (3 permanent, 4 transient)
//   - F22 strict error detection (no oracle for status-code surface)
//   - F23 2xx response contract validation (no assessments → ProtocolError)
//   - F26 paginated GetAssessment via limit+offset loop (server cap 500)
//   - F28 X-Total-Count header captured into the list result
//
// Note: the M3 METI catalog ships with 27 criterion entries (3 phases
// × ~9 items), so in practice ListByProject's default page (100)
// captures the full assessment in one round-trip. The pagination loop
// exists because the F26 pattern is a CLI-wide invariant — the
// invariant "no client-side caller silently truncates server-paginated
// data" must hold even when the data set is currently small.

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
// Wire DTOs (mirror sbomhub/apps/api/internal/handler/meti.go +
// repository.MetiAssessment)
// ----------------------------------------------------------------------------

// MetiAssessment mirrors repository.MetiAssessment. JSON tags match the
// server-side struct verbatim so the CLI decodes the handler response
// without a parallel DTO (M1 #F28 carried over — wire-shape drift
// between repository and handler caused silent UI breakage).
//
// All timestamp fields are surfaced as strings because the M3 CLI only
// displays them; downstream consumers that need time.Time can parse
// from the *At fields themselves.
type MetiAssessment struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`

	ProjectID string `json:"project_id"`

	CriterionID    string `json:"criterion_id"`
	CriterionPhase string `json:"criterion_phase"`

	// Evaluator verdict: achieved | not_achieved | needs_review | not_applicable.
	Status string `json:"status"`

	// Evidence: JSONB array of {kind, ref} or {kind, value} citations.
	// The server enforces NOT NULL + jsonb_array_length >= 0; we surface
	// the raw bytes so callers that want to render evidence can
	// json.Unmarshal further.
	Evidence json.RawMessage `json:"evidence,omitempty"`

	EvaluatorVersion string `json:"evaluator_version,omitempty"`
	EvaluatedAt      string `json:"evaluated_at,omitempty"`

	// Operator override layer. Empty / nil when no override has been
	// applied. OverrideStatus / OverrideBy / OverrideAt / OverrideNote
	// are stamped together by the OverrideCriterion call.
	OverrideStatus string  `json:"override_status,omitempty"`
	OverrideBy     *string `json:"override_by,omitempty"`
	OverrideAt     *string `json:"override_at,omitempty"`
	OverrideNote   string  `json:"override_note,omitempty"`

	// Operator-authored remediation plan. Independent from override.
	ImprovementAction string `json:"improvement_action,omitempty"`

	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// MetiAssessmentListFilter narrows GetAssessment. Empty fields are not
// sent to the server. HasOverride is a pointer so the CLI can
// distinguish "no filter" (nil) from "must NOT be overridden" (false)
// — mirrors repository.MetiAssessmentListFilter.HasOverride.
type MetiAssessmentListFilter struct {
	Phase       string // env_setup | sbom_creation | sbom_operation
	Status      string // achieved | not_achieved | needs_review | not_applicable
	HasOverride *bool
}

// metiAssessmentListResponse mirrors handler.metiAssessmentListResponse.
type metiAssessmentListResponse struct {
	Assessments []MetiAssessment `json:"assessments"`
}

// MetiRefreshResult mirrors handler.metiRefreshResponse.
//
// EvaluatorVersion is surfaced at the top level so the CLI / Web UI
// (M3-5) can show a "evaluated by X" pill without scanning the per-row
// evaluator_version fields.
type MetiRefreshResult struct {
	Assessments      []MetiAssessment `json:"assessments"`
	EvaluatorVersion string           `json:"evaluator_version"`
	Refreshed        int              `json:"refreshed"`

	// Error is an optional top-level error string. A well-behaved
	// server NEVER emits this on a 2xx response — when present it is
	// the F23 protocol-violation signal: the handler returned HTTP 200
	// but logically failed. The CLI promotes this to a transient
	// *MetiError in RefreshAssessment so the exit-code path can flag
	// the failure.
	Error string `json:"error,omitempty"`
}

// MetiOverrideRequest is the body of PUT
// /meti/assessment/:criterion_id/override.
//
// OverrideStatus is REQUIRED — the server 400s missing / unknown
// values. ImprovementAction is a pointer because the server uses the
// nil/non-nil distinction to tell "do not change" apart from "set to
// empty"; mirrors the CRA EditedDraftText contract.
type MetiOverrideRequest struct {
	OverrideStatus    string  `json:"override_status"`
	OverrideNote      string  `json:"override_note,omitempty"`
	ImprovementAction *string `json:"improvement_action,omitempty"`
}

// MetiClearOverrideRequest is the body of DELETE
// /meti/assessment/:criterion_id/override (M3 Codex review #F33/#F36).
//
// Note is REQUIRED and must be 1..MaxMetiOverrideNoteLen (4096) chars
// after trim — the server's validateMetiOverrideNote rejects empty /
// over-long values with 400. The operator's rationale for the clear
// is persisted in the audit_logs row so an auditor can reconstruct
// the correction.
type MetiClearOverrideRequest struct {
	Note string `json:"note"`
}

// ImprovementAction mirrors handler.metiImprovementAction. Used by the
// `meti list --improvements` shorthand once the CLI grows one; for now
// GetImprovementActions returns this slice directly so callers can
// render the "still needs action" board.
type ImprovementAction struct {
	CriterionID       string          `json:"criterion_id"`
	CriterionPhase    string          `json:"criterion_phase"`
	CriterionTitleJA  string          `json:"criterion_title_ja,omitempty"`
	CriterionTitleEN  string          `json:"criterion_title_en,omitempty"`
	Status            string          `json:"status"`
	OverrideStatus    string          `json:"override_status,omitempty"`
	EffectiveStatus   string          `json:"effective_status"`
	Evidence          json.RawMessage `json:"evidence,omitempty"`
	ImprovementAction string          `json:"improvement_action,omitempty"`
}

// metiImprovementActionsResponse mirrors handler.metiImprovementActionsResponse.
type metiImprovementActionsResponse struct {
	Actions []ImprovementAction `json:"actions"`
}

// ----------------------------------------------------------------------------
// Error decoding
// ----------------------------------------------------------------------------

// MetiError is the typed error returned by the METI helpers when the
// server emits a non-2xx response. Mirrors *CRAError so the CLI loop
// can branch on the same IsPermanent / IsTransient surface.
//
// The METI handler has no AI / LLM dependency — there is no analog of
// CRAError.IsAIDisabled() because the evaluator is fully local. F19 /
// F25 are intentionally not in scope at the handler layer for the
// same reason (see meti.go MetiHandler doc comment).
type MetiError struct {
	StatusCode int
	URL        string
	Method     string
	Message    string // top-level "error" field
	Raw        string // original body, preserved for debug logging

	// ProtocolError flags a synthesised MetiError raised for a 2xx
	// response that violated the success contract — server returned
	// HTTP 200/201 but the body had no assessments slice, or carried
	// an explicit "error" field. Callers inspect this via IsTransient
	// (always true when set) so the CLI loop surfaces such bugs
	// through the exit-4 transient path instead of silently bucketing
	// the call as a success (mirrors M1 #F23).
	ProtocolError bool
}

func (e *MetiError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("meti API %s %s -> %d: %s", e.Method, e.URL, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("meti API %s %s -> %d: %s", e.Method, e.URL, e.StatusCode, e.Raw)
}

// IsPermanent reports whether the error is a permanent 4xx that the
// caller cannot retry without fixing config / input (auth / unknown
// criterion / already-overridden). 429 is intentionally transient.
//
// 409 (re-override rejected: row already overridden) is treated as
// permanent because the operator's correct response is "clear the
// existing override first", NOT "retry tomorrow" — mirrors the CRA
// 409 classification (no approved VEX draft → operator must triage
// first).
func (e *MetiError) IsPermanent() bool {
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
// error / upstream blip). Symmetric with IsPermanent so the CLI loop
// can categorise each failure into exactly one of: permanent,
// transient, or unclassified.
//
// ProtocolError joins the transient bucket because the operator's
// correct response is the same (retry, possibly after a server
// redeploy) — mirrors M1 #F23.
func (e *MetiError) IsTransient() bool {
	if e == nil {
		return false
	}
	if e.ProtocolError {
		return true
	}
	if e.StatusCode == http.StatusTooManyRequests {
		return true
	}
	return e.StatusCode >= 500 && e.StatusCode < 600
}

// decodeMetiError builds a MetiError from a non-2xx response body.
// Tolerates non-JSON bodies (intermediate gateways sometimes send HTML
// 502 pages) — Raw always carries the original text.
func decodeMetiError(method, url string, status int, body []byte) *MetiError {
	te := &MetiError{
		StatusCode: status,
		URL:        url,
		Method:     method,
		Raw:        string(body),
	}
	var parsed struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil {
		te.Message = parsed.Error
	}
	return te
}

// ----------------------------------------------------------------------------
// GetAssessment — GET /api/v1/projects/:id/meti/assessment
// ----------------------------------------------------------------------------

// metiAssessmentsListPageSize is the per-page request size the CLI
// uses when paging /meti/assessment. M1 #F26 carry-over: the server
// caps ?limit= at MaxMetiAssessmentsListLimit (500), so the CLI
// requests pages at the maximum allowed size to minimise round-trips.
//
// ※要確認: the server's catalog currently ships 27 criterion entries,
// so this loop will always complete in one page. The pagination logic
// is wired anyway because the F26 invariant ("CLI never silently
// truncates server-paginated data") must hold across the surface.
const metiAssessmentsListPageSize = 500

// metiAssessmentsListMaxPages is a defensive ceiling on the number of
// pages the CLI is willing to fetch. Tuned to match the server's
// MaxMetiAssessmentsListOffset (10000) / metiAssessmentsListPageSize
// (500) so the loop cannot iterate past the server's offset clamp.
const metiAssessmentsListMaxPages = 25

// GetAssessment returns the project's METI assessment rows
// (paginated). Returns the joined slice + the server's X-Total-Count
// (M1 #F28 carried over) + an error.
//
// M1 #F26 carry-over: pages through using metiAssessmentsListPageSize
// per request and stops when either:
//   - a page returns fewer rows than the requested page size (canonical
//     "no more rows" signal), or
//   - metiAssessmentsListMaxPages is reached (defensive ceiling).
func (c *Client) GetAssessment(ctx context.Context, projectID string, filter MetiAssessmentListFilter) ([]MetiAssessment, int, error) {
	all := make([]MetiAssessment, 0, metiAssessmentsListPageSize)
	offset := 0
	total := 0
	for page := 0; page < metiAssessmentsListMaxPages; page++ {
		batch, pageTotal, err := c.getAssessmentPage(ctx, projectID, filter, metiAssessmentsListPageSize, offset)
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
		if len(batch) < metiAssessmentsListPageSize {
			return all, total, nil
		}
		offset += len(batch)
	}
	return nil, 0, fmt.Errorf("meti/assessment ページング上限 (%d ページ × %d 件) 到達: サーバーがページング終端を返していない可能性があります",
		metiAssessmentsListMaxPages, metiAssessmentsListPageSize)
}

// getAssessmentPage fetches a single (limit, offset) page from the
// server. Extracted from GetAssessment so the paging loop stays
// readable and so tests can drive the per-page decode independently.
func (c *Client) getAssessmentPage(ctx context.Context, projectID string, filter MetiAssessmentListFilter, limit, offset int) ([]MetiAssessment, int, error) {
	endpoint := fmt.Sprintf("%s/api/v1/projects/%s/meti/assessment", c.baseURL, projectID)

	q := url.Values{}
	if filter.Phase != "" {
		q.Set("phase", filter.Phase)
	}
	if filter.Status != "" {
		q.Set("status", filter.Status)
	}
	if filter.HasOverride != nil {
		if *filter.HasOverride {
			q.Set("has_override", "true")
		} else {
			q.Set("has_override", "false")
		}
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
		return nil, 0, fmt.Errorf("meti/assessment リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, 0, decodeMetiError(http.MethodGet, endpoint, resp.StatusCode, respBody)
	}

	var out metiAssessmentListResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, 0, fmt.Errorf("meti/assessment レスポンス解析エラー: %w", err)
	}
	if out.Assessments == nil {
		out.Assessments = []MetiAssessment{}
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

	return out.Assessments, total, nil
}

// ----------------------------------------------------------------------------
// RefreshAssessment — POST /api/v1/projects/:id/meti/assessment/refresh
// ----------------------------------------------------------------------------

// RefreshAssessment re-runs the server-side evaluator over the project
// and Upserts every criterion result. Operator-applied overrides are
// preserved by the repository (Upsert does NOT touch override_*) so an
// operator's manual verdict survives a refresh cycle.
//
// F23 carry-over: a 2xx response with an "error" field set or a nil
// Assessments slice is surfaced as a transient *MetiError so the CLI
// exit-4 path catches such bugs rather than silently green-lighting a
// no-op refresh.
func (c *Client) RefreshAssessment(ctx context.Context, projectID string) (*MetiRefreshResult, error) {
	endpoint := fmt.Sprintf("%s/api/v1/projects/%s/meti/assessment/refresh", c.baseURL, projectID)

	// The server's refresh handler does not consume a request body —
	// the fan-out reads the project's evidence directly. We send an
	// empty JSON object so any future server-side body validation
	// (e.g. "{requested_evaluator_version}") finds a parseable payload.
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("meti/assessment/refresh リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, decodeMetiError(http.MethodPost, endpoint, resp.StatusCode, respBody)
	}

	return decodeRefreshResult(http.MethodPost, endpoint, resp.StatusCode, respBody)
}

// decodeRefreshResult parses a 2xx response body for RefreshAssessment
// and validates the success contract (M1 #F23 carried over): a 2xx
// response MUST carry (a) Error == "" AND (b) a non-nil Assessments
// slice. Either violation is surfaced as a ProtocolError so the CLI
// can route it through IsTransient → exit code 4 rather than silently
// treating the call as a success with an empty fan-out.
func decodeRefreshResult(method, endpoint string, status int, body []byte) (*MetiRefreshResult, error) {
	var out MetiRefreshResult
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("meti/assessment/refresh レスポンス解析エラー: %w", err)
	}

	if out.Error != "" {
		return nil, &MetiError{
			StatusCode:    status,
			URL:           endpoint,
			Method:        method,
			Message:       out.Error,
			Raw:           string(body),
			ProtocolError: true,
		}
	}
	if out.Assessments == nil {
		return nil, &MetiError{
			StatusCode:    status,
			URL:           endpoint,
			Method:        method,
			Message:       "meti/assessment/refresh success response missing assessments slice (server protocol error — F23 contract violation)",
			Raw:           string(body),
			ProtocolError: true,
		}
	}
	return &out, nil
}

// ----------------------------------------------------------------------------
// OverrideCriterion — PUT /api/v1/projects/:id/meti/assessment/:criterion_id/override
// ----------------------------------------------------------------------------

// OverrideCriterion applies one operator override to a meti_assessments
// row. The evaluator-owned fields are preserved unconditionally; only
// override_status / override_by / override_at / override_note (and
// optionally improvement_action) are written.
//
// Server semantics (M3-4 handler):
//   - 400 if override_status is missing / unknown
//   - 403 if the caller lacks write permission
//   - 404 if the (tenant, project, criterion) row does not exist OR
//     the criterion id is not in the catalog (generic body — no oracle)
//   - 409 if the row has already been overridden (F31 state-machine guard)
//
// Returns the refreshed row from the server so callers can render the
// post-override timestamps without a second round-trip.
func (c *Client) OverrideCriterion(ctx context.Context, projectID, criterionID string, override MetiOverrideRequest) (*MetiAssessment, error) {
	if strings.TrimSpace(criterionID) == "" {
		return nil, fmt.Errorf("criterion_id is required")
	}
	endpoint := fmt.Sprintf("%s/api/v1/projects/%s/meti/assessment/%s/override",
		c.baseURL, projectID, url.PathEscape(criterionID))

	body, err := json.Marshal(override)
	if err != nil {
		return nil, fmt.Errorf("meti override リクエストのシリアライズに失敗: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("meti override リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, decodeMetiError(http.MethodPut, endpoint, resp.StatusCode, respBody)
	}

	var out MetiAssessment
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("meti override レスポンス解析エラー: %w", err)
	}
	if out.ID == "" && out.CriterionID == "" {
		// F23 carry-over: 2xx with empty body is a server contract
		// violation — surface as ProtocolError / transient so the CLI
		// retries instead of silently confirming a no-op override.
		return nil, &MetiError{
			StatusCode:    resp.StatusCode,
			URL:           endpoint,
			Method:        http.MethodPut,
			Message:       "meti override success response missing assessment row (server protocol error — F23 contract violation)",
			Raw:           string(respBody),
			ProtocolError: true,
		}
	}
	return &out, nil
}

// ----------------------------------------------------------------------------
// ClearOverrideCriterion — DELETE /api/v1/projects/:id/meti/assessment/:criterion_id/override
// ----------------------------------------------------------------------------

// ClearOverrideCriterion drops a prior operator override on a
// meti_assessments row (M3 Codex review #F33 / #F36). Without this
// verb, an erroneous override is a one-way trip — it continues to win
// over the evaluator's verdict and re-override is rejected with 409
// until the existing override is cleared.
//
// Server semantics (M3-4 handler):
//   - 400 if note is missing / empty / over 4096 chars after trim
//   - 401 / 403 if the caller lacks write permission (or user identity
//     for the audit row)
//   - 404 if (tenant, project, criterion) row does not exist OR the
//     row exists but has no override to clear (generic body — no
//     oracle to probe prior override state)
//   - 409 if a concurrent clear / re-override raced (TOCTOU)
//
// The handler returns 200 OK with the post-clear row in the body so
// the operator can confirm override_status is now empty without a
// second round-trip; the body is discarded here (caller signature is
// error-only) and a follow-up GetAssessment is the way to render the
// post-clear state. 204 No Content is also accepted in case the
// handler migrates to a body-less success shape.
func (c *Client) ClearOverrideCriterion(ctx context.Context, projectID, criterionID string, req MetiClearOverrideRequest) error {
	if strings.TrimSpace(criterionID) == "" {
		return fmt.Errorf("criterion_id is required")
	}
	// F34 mirror: server bounds note at 1..4096 after trim. CLI-side
	// early validation surfaces a friendlier error than a 400 round-trip.
	cleaned := strings.TrimSpace(req.Note)
	if len(cleaned) < 1 || len(cleaned) > 4096 {
		return fmt.Errorf("note is required and must be 1-4096 characters")
	}

	endpoint := fmt.Sprintf("%s/api/v1/projects/%s/meti/assessment/%s/override",
		c.baseURL, projectID, url.PathEscape(criterionID))

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("meti clear-override リクエストのシリアライズに失敗: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("meti clear-override リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return decodeMetiError(http.MethodDelete, endpoint, resp.StatusCode, respBody)
	}
	return nil
}

// ----------------------------------------------------------------------------
// GetImprovementActions — GET /api/v1/projects/:id/meti/improvement-actions
// ----------------------------------------------------------------------------

// GetImprovementActions returns the project's still-to-do action items
// (i.e. rows whose EFFECTIVE status is not "achieved"). The server
// handles the "effective" merge (override wins over evaluator status)
// and the "not achieved" filter — the CLI just renders.
//
// Unlike GetAssessment, this endpoint pulls the full filtered set in a
// single round-trip server-side (the handler asks the repository for
// MaxMetiAssessmentsListLimit rows because the catalog is bounded at
// 27). No CLI-side pagination required; the X-Total-Count header
// carries the action count for the summary line.
func (c *Client) GetImprovementActions(ctx context.Context, projectID string) ([]ImprovementAction, int, error) {
	endpoint := fmt.Sprintf("%s/api/v1/projects/%s/meti/improvement-actions", c.baseURL, projectID)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, 0, fmt.Errorf("meti/improvement-actions リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, 0, decodeMetiError(http.MethodGet, endpoint, resp.StatusCode, respBody)
	}

	var out metiImprovementActionsResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, 0, fmt.Errorf("meti/improvement-actions レスポンス解析エラー: %w", err)
	}
	if out.Actions == nil {
		out.Actions = []ImprovementAction{}
	}
	total := len(out.Actions)
	if v := resp.Header.Get("X-Total-Count"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			total = n
		}
	}
	return out.Actions, total, nil
}
