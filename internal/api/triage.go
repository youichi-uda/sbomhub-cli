package api

// Triage API client — wraps the M1 VEX draft endpoints documented in
// sbomhub/apps/api/internal/handler/vex_drafts.go (truth source):
//
//	POST   /api/v1/projects/:id/triage/run
//	GET    /api/v1/projects/:id/vex-drafts
//	PUT    /api/v1/projects/:id/vex-drafts/:draft_id/decision
//
// The CLI's `sbomhub triage` command uses these three to:
//  1. enumerate the existing vulnerabilities for a project (via the
//     pre-existing GET /api/v1/projects/:id/vulnerabilities endpoint —
//     see ListVulnerabilities below),
//  2. ask the server to run one AI triage cycle per (cve_id, vuln_id),
//  3. surface the AI-drafted VEX to the operator and persist their
//     approve / edit / reject decision.
//
// All three helpers share the existing api.Client (Bearer auth, base
// URL, default 60s timeout). Non-2xx responses fall through to the
// shared parsing helper triageDecodeError which carries the server's
// JSON body verbatim so the CLI can surface the "AI features are
// disabled" reason text from llm.DisabledError end-to-end.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ----------------------------------------------------------------------------
// Wire DTOs (mirror sbomhub/apps/api/internal/handler/vex_drafts.go)
// ----------------------------------------------------------------------------

// TriageRunRequest is the body of POST /api/v1/projects/:id/triage/run.
//
// `VulnerabilityID` is required by the server (parsed via uuid.Parse);
// `CVEID` is also required. `ComponentID` is deprecated as a CLI wire
// field — the server resolves component_id(s) from
// (tenant, project, vulnerability_id) and fans out one draft per
// affected component (M1 Codex review #F3). Callers that have a pinned
// component_id may still supply it; the server uses that one component
// without fanning out.
type TriageRunRequest struct {
	VulnerabilityID string `json:"vulnerability_id"`
	CVEID           string `json:"cve_id"`
	// Deprecated: server resolves component_id from vulnerability_id.
	ComponentID string `json:"component_id,omitempty"`
}

// TriageEvidence mirrors triage.EvidencePointer in the API.
//
// Only the fields the CLI needs for the interactive UX are decoded;
// the JSON tag set keeps this loose so we tolerate the server adding
// new fields without a breaking change.
type TriageEvidence struct {
	Kind        string `json:"kind"`
	FilePath    string `json:"file_path,omitempty"`
	Line        int    `json:"line,omitempty"`
	Column      int    `json:"column,omitempty"`
	Symbol      string `json:"symbol,omitempty"`
	ImportPath  string `json:"import_path,omitempty"`
	Description string `json:"description,omitempty"`
	RawSnippet  string `json:"raw_snippet,omitempty"`
	Source      string `json:"source,omitempty"`
	Note        string `json:"note,omitempty"`
}

// ParsedDecision mirrors triage.ParsedDecision in the API.
//
// State is one of "not_affected" / "affected" / "under_investigation"
// / "resolved" per CycloneDX VEX 1.5. Confidence is in [0.0, 1.0]
// after server-side clamping (the runner already applied the
// threshold guard before sending the response).
type ParsedDecision struct {
	State         string           `json:"state"`
	Justification string           `json:"justification,omitempty"`
	Detail        string           `json:"detail,omitempty"`
	Confidence    float64          `json:"confidence"`
	Evidence      []TriageEvidence `json:"evidence,omitempty"`
}

// VEXDraft mirrors repository.VEXDraft.
//
// We decode only the fields the interactive UI needs to render and the
// decision PUT needs as a draft_id. Server-side timestamps / hashes
// land in the raw JSON map for forward compatibility — the CLI does
// not currently surface them but they would round-trip cleanly into a
// debug `--json` flag.
type VEXDraft struct {
	ID              string  `json:"id"`
	ProjectID       string  `json:"project_id"`
	ComponentID     string  `json:"component_id"`
	VulnerabilityID string  `json:"vulnerability_id"`
	CVEID           string  `json:"cve_id"`
	State           string  `json:"state"`
	Justification   string  `json:"justification"`
	Detail          string  `json:"detail"`
	Confidence      *float64 `json:"confidence,omitempty"`
	Provider        string  `json:"provider,omitempty"`
	Model           string  `json:"model,omitempty"`
	// Evidence here is the server-persisted JSONB array — same shape
	// as ParsedDecision.Evidence but the field name in the DB row is
	// `evidence` per repository.VEXDraft.
	Evidence  json.RawMessage `json:"evidence,omitempty"`
	Decision  string          `json:"decision"`
	CreatedAt string          `json:"created_at,omitempty"`
	UpdatedAt string          `json:"updated_at,omitempty"`
}

// TriageRunResult is what POST /triage/run returns on success (201).
//
// Threshold echoes the server's effective SBOMHUB_AI_CONFIDENCE_THRESHOLD
// so the CLI can render "(threshold=0.7)" alongside the AI confidence.
// Clamped reports whether the server demoted state to
// `under_investigation` because confidence fell below the threshold —
// that flag is the trigger for the CLI's auto-`under_investigation`
// path in `--non-interactive`.
//
// Drafts is populated when the server fanned out across multiple
// components affected by the same vulnerability (M1 Codex review #F3);
// Draft mirrors Drafts[0] for backward compatibility.
//
// AIDisabled is true when the server skipped the LLM call because no
// BYOK provider is configured. The server still persists
// under_investigation drafts + audit rows; the CLI uses this flag to
// surface the "APIキー未設定" hint without inventing a counter-only
// fallback (M1 Codex review #F4).
type TriageRunResult struct {
	Draft      *VEXDraft       `json:"draft"`
	Drafts     []*VEXDraft     `json:"drafts,omitempty"`
	LLMCallID  string          `json:"llm_call_id,omitempty"`
	Parsed     *ParsedDecision `json:"parsed_decision,omitempty"`
	Clamped    bool            `json:"clamped"`
	Threshold  float64         `json:"threshold"`
	AIDisabled bool            `json:"ai_disabled,omitempty"`

	// Error is an optional top-level error string. A well-behaved
	// server NEVER emits this on a 2xx response — when present it is
	// the F23 protocol-violation signal: the handler returned HTTP 200
	// but logically failed, almost always because the upstream LLM
	// provider raised an exception that the handler papered over. The
	// CLI promotes this to a transient *TriageError in RunTriage so
	// the exit-code path can flag the failure (M1 Codex review #F23).
	Error string `json:"error,omitempty"`
}

// vexDraftListResponse mirrors handler.vexDraftListResponse.
type vexDraftListResponse struct {
	Drafts []VEXDraft `json:"drafts"`
}

// VEXDraftListFilter narrows ListVEXDrafts. Empty fields are not sent
// to the server (zero-valued query params have no effect server-side
// anyway, but skipping them keeps the URL clean and the test golden).
type VEXDraftListFilter struct {
	CVEID    string
	Decision string
	Limit    int
	Offset   int
}

// DecisionRequest is the body of PUT /vex-drafts/:draft_id/decision.
//
// Decision must be one of "approved", "edited", "rejected" — the server
// 400's other values. EditedState / EditedJustification / EditedDetail
// are only honored when Decision == "edited"; for "approved" /
// "rejected" they are ignored server-side (see runner.UpdateDecision).
type DecisionRequest struct {
	Decision            string `json:"decision"`
	EditedState         string `json:"edited_state,omitempty"`
	EditedJustification string `json:"edited_justification,omitempty"`
	EditedDetail        string `json:"edited_detail,omitempty"`
	Note                string `json:"note,omitempty"`
}

// ----------------------------------------------------------------------------
// Error decoding
// ----------------------------------------------------------------------------

// TriageError is the typed error returned by the triage helpers when the
// server emits a non-2xx response. It carries the parsed JSON body
// (`error` + optional `reason`) so the CLI can branch on:
//
//   - 503 + reason  → llm.DisabledError ("AI features are disabled") →
//     fall back to under_investigation
//   - 4xx           → permanent user / config error
//   - 5xx (non-503) → transient server error
//
// Callers test category with the helpers IsAIDisabled / IsPermanent
// rather than reaching into StatusCode directly, so the classification
// stays in one place.
type TriageError struct {
	StatusCode int
	URL        string
	Method     string
	Message    string // top-level "error" field
	Reason     string // "reason" field (only populated for 503 DisabledError)
	Raw        string // original body, preserved for debug logging

	// ProtocolError flags a synthesised TriageError raised for a 2xx
	// response that violated the success contract — server returned
	// HTTP 200/201 but the body had no draft (and was not flagged
	// ai_disabled), or carried an explicit "error" field. Callers
	// inspect this via IsTransient (always true when set) so the CLI
	// triage loop surfaces such bugs through the exit-4 transient path
	// instead of silently bucketing the vuln as `skipped` (M1 Codex
	// review #F23).
	ProtocolError bool
}

func (e *TriageError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("triage API %s %s -> %d: %s (%s)", e.Method, e.URL, e.StatusCode, e.Message, e.Reason)
	}
	if e.Message != "" {
		return fmt.Sprintf("triage API %s %s -> %d: %s", e.Method, e.URL, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("triage API %s %s -> %d: %s", e.Method, e.URL, e.StatusCode, e.Raw)
}

// aiDisabledReasonMarkers are the substrings (case-insensitive) we
// recognise as the legacy BYOK-not-configured signal on a 503 response.
// F19 moved the canonical AI-disabled path onto 2xx + ai_disabled=true,
// so this list only catches OLD servers that still emit
// llm.DisabledError on 503. Anything else on 503 is a real outage and
// must classify as transient (see IsTransient).
//
// ※要確認: kept in lower-case for case-insensitive substring match.
// The exact server reason text was `"AI features are disabled"` (with
// reason `"no LLM provider configured"`) per the legacy DisabledError.
// Synonyms ("BYOK key not configured") guard against minor copy edits.
var aiDisabledReasonMarkers = []string{
	"ai features are disabled",
	"byok key not configured",
	"byok not configured",
}

// IsAIDisabled reports whether the server signalled the BYOK-not-configured
// fallback path. The canonical M1 server returns this on a 2xx response
// with TriageRunResult.AIDisabled=true — the CLI does not consult this
// helper on the 2xx success path (it inspects AIDisabled directly).
//
// M1 Codex review #F22: legacy server compatibility — a server that
// has not yet shipped the F19 2xx+ai_disabled change still returns 503
// from llm.DisabledError. We accept that legacy shape only when the
// response carries the known reason text. Any other 503 is treated as
// a transient outage (gateway timeout, pgx connection refused, server
// overload) and surfaces through IsTransient → exit code 4. Previously
// every 503 was silently swallowed as "AI off" and CI exited 0 with
// zero persisted drafts on a real outage.
func (e *TriageError) IsAIDisabled() bool {
	if e == nil || e.StatusCode != http.StatusServiceUnavailable {
		return false
	}
	// Lower-case once so the substring match is case-insensitive across
	// Message + Reason + Raw — the server has historically emitted the
	// reason text in any of the three slots depending on whether the
	// JSON body parsed cleanly.
	hay := strings.ToLower(e.Message + " " + e.Reason + " " + e.Raw)
	for _, m := range aiDisabledReasonMarkers {
		if strings.Contains(hay, m) {
			return true
		}
	}
	return false
}

// IsPermanent reports whether the error is a permanent 4xx that the
// caller cannot retry without fixing config (auth / input validation /
// missing draft). 429 is intentionally treated as transient (not
// permanent) to match the same R13 classification the scan polling
// loop uses.
//
// 503 is never permanent — it is either AI-disabled (handled by
// IsAIDisabled / the per-vuln short-circuit) or a transient outage
// (handled by IsTransient). Treating it as permanent would inflate the
// permanent-failure exit code on a legitimate retry case (M1 Codex
// review #F21, #F22).
func (e *TriageError) IsPermanent() bool {
	if e == nil {
		return false
	}
	if e.StatusCode == http.StatusTooManyRequests {
		return false
	}
	if e.StatusCode == http.StatusServiceUnavailable {
		// AI-disabled (legacy) vs transient outage — both handled
		// elsewhere, never as permanent.
		return false
	}
	return e.StatusCode >= 400 && e.StatusCode < 500
}

// IsTransient reports whether the error is a transient failure the
// operator can resolve by retrying — 429 (rate limit) and 5xx (server
// error / upstream blip). The bucket is symmetric with IsPermanent so
// runTriageLoop can categorise each failure into exactly one of:
// AI-disabled (caller-handled), permanent, transient, or otherwise.
//
// M1 Codex review #F21: this helper exists so the CLI's triage loop
// can distinguish "the server is broken right now, retry tomorrow"
// (transient → exit 4) from "the operator's API key cannot do this
// thing, fix config" (permanent → exit 3) — silently swallowing both
// as "skipped" used to make CI green on 403/429 storms.
//
// M1 Codex review #F22: a 503 with no recognised AI-disabled marker
// is now classified transient. Previously the helper returned false
// for every 503 because IsAIDisabled was assumed to swallow them all;
// after the strict IsAIDisabled check, real upstream outages (pgx
// connection refused, gateway timeout, server overload) reach this
// helper and must surface as exit 4.
//
// M1 Codex review #F23: ProtocolError signals a synthesised TriageError
// for a 2xx response that violated the success contract (missing draft
// or error field present). The operator's correct response is the same
// as for any transient — retry, possibly after a server redeploy — so
// it joins the transient bucket here.
func (e *TriageError) IsTransient() bool {
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
		// AI-disabled (legacy) wins via IsAIDisabled() and the per-vuln
		// short-circuit; everything else on 503 is a real outage that
		// the operator can resolve by retrying. F22: previously this
		// returned false unconditionally for 503 and the failure was
		// silently dropped.
		return !e.IsAIDisabled()
	}
	return e.StatusCode >= 500 && e.StatusCode < 600
}

// decodeTriageError builds a TriageError from a non-2xx response body.
// We tolerate non-JSON bodies (some intermediate gateways send HTML
// 502 pages) — Raw always carries the original text so the operator
// can still see what came back.
func decodeTriageError(method, url string, status int, body []byte) *TriageError {
	te := &TriageError{
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
// RunTriage — POST /api/v1/projects/:id/triage/run
// ----------------------------------------------------------------------------

// RunTriage executes one AI triage cycle for (project, vulnerability)
// on the server and returns the persisted draft + parsed decision +
// the clamping outcome.
//
// 503 from llm.DisabledError is returned as a *TriageError where
// IsAIDisabled() == true — the CLI inspects that with errors.As and
// short-circuits the interactive loop into the under_investigation
// fallback.
func (c *Client) RunTriage(ctx context.Context, projectID string, req TriageRunRequest) (*TriageRunResult, error) {
	endpoint := fmt.Sprintf("%s/api/v1/projects/%s/triage/run", c.baseURL, projectID)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("triage リクエストのシリアライズに失敗: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("triage リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, decodeTriageError(http.MethodPost, endpoint, resp.StatusCode, respBody)
	}

	var out TriageRunResult
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("triage レスポンス解析エラー: %w", err)
	}

	// M1 Codex review #F23: success contract validation. A 2xx response
	// must carry (a) a top-level error == "" AND (b) at least one
	// persisted draft. Before this guard, a server that returned 200
	// with {"error":"..."} or {"clamped":false,"threshold":0.7} (no
	// draft) was decoded as a zero-valued success and the CLI bucketed
	// the vuln as `skipped` → exit 0 with zero persisted drafts on a
	// silent server protocol bug. ProtocolError=true routes the error
	// through IsTransient → exit code 4 so CI can retry rather than
	// silently green-light an empty run.
	if out.Error != "" {
		return nil, &TriageError{
			StatusCode:    resp.StatusCode,
			URL:           endpoint,
			Method:        http.MethodPost,
			Message:       out.Error,
			Raw:           string(respBody),
			ProtocolError: true,
		}
	}
	if out.Draft == nil && len(out.Drafts) == 0 {
		var msg string
		if out.AIDisabled {
			msg = "triage success response carried ai_disabled=true but no draft persisted (server bug — F4 contract violation)"
		} else {
			msg = "triage success response missing draft (server protocol error — F23 contract violation)"
		}
		return nil, &TriageError{
			StatusCode:    resp.StatusCode,
			URL:           endpoint,
			Method:        http.MethodPost,
			Message:       msg,
			Raw:           string(respBody),
			ProtocolError: true,
		}
	}
	return &out, nil
}

// ----------------------------------------------------------------------------
// ListVEXDrafts — GET /api/v1/projects/:id/vex-drafts
// ----------------------------------------------------------------------------

// ListVEXDrafts returns the project's existing VEX drafts, optionally
// filtered by CVE ID / decision / paginated. Returns an empty slice
// (not nil) when there are no drafts so callers can `range` safely.
func (c *Client) ListVEXDrafts(ctx context.Context, projectID string, filter VEXDraftListFilter) ([]VEXDraft, error) {
	endpoint := fmt.Sprintf("%s/api/v1/projects/%s/vex-drafts", c.baseURL, projectID)

	q := url.Values{}
	if filter.CVEID != "" {
		q.Set("cve_id", filter.CVEID)
	}
	if filter.Decision != "" {
		q.Set("decision", filter.Decision)
	}
	if filter.Limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", filter.Limit))
	}
	if filter.Offset > 0 {
		q.Set("offset", fmt.Sprintf("%d", filter.Offset))
	}
	if encoded := q.Encode(); encoded != "" {
		endpoint = endpoint + "?" + encoded
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("vex-drafts リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, decodeTriageError(http.MethodGet, endpoint, resp.StatusCode, respBody)
	}

	var out vexDraftListResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("vex-drafts レスポンス解析エラー: %w", err)
	}
	if out.Drafts == nil {
		return []VEXDraft{}, nil
	}
	return out.Drafts, nil
}

// ----------------------------------------------------------------------------
// DecideDraft — PUT /api/v1/projects/:id/vex-drafts/:draft_id/decision
// ----------------------------------------------------------------------------

// DecideDraft applies a human approve / edit / reject decision to a
// VEX draft. The server mirrors approve/edit verdicts into the
// vex_statements table and writes an audit log row — neither concern
// surfaces in this client API.
func (c *Client) DecideDraft(ctx context.Context, projectID, draftID string, dec DecisionRequest) (*VEXDraft, error) {
	endpoint := fmt.Sprintf("%s/api/v1/projects/%s/vex-drafts/%s/decision", c.baseURL, projectID, draftID)

	body, err := json.Marshal(dec)
	if err != nil {
		return nil, fmt.Errorf("decision リクエストのシリアライズに失敗: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("decision リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, decodeTriageError(http.MethodPut, endpoint, resp.StatusCode, respBody)
	}

	var out VEXDraft
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decision レスポンス解析エラー: %w", err)
	}
	return &out, nil
}

// ----------------------------------------------------------------------------
// ListVulnerabilities — GET /api/v1/projects/:id/vulnerabilities
// ----------------------------------------------------------------------------

// VulnerabilityRecord is the per-project vulnerability row returned by
// GET /api/v1/projects/:id/vulnerabilities (handler.GetVulnerabilities
// in sbom.go). We decode only the fields the triage loop needs to call
// RunTriage with — ID is the local `vulnerabilities.id` UUID, CVEID is
// the human-facing identifier surfaced in the prompt.
//
// ※要確認: the server-side `/vulnerabilities` endpoint returns the
// per-vulnerability model rows but does not currently include a
// component_id on each row (the cross-table relation lives in
// component_vulnerabilities). The CLI therefore omits ComponentID in
// TriageRunRequest, letting the server resolve a representative
// component from vulnerability_id. Once the server adds a richer
// projection (cve + component pair), the CLI should switch to passing
// component_id explicitly so drafts are pinned to the precise
// (component, vuln) tuple.
type VulnerabilityRecord struct {
	ID          string  `json:"id"`
	CVEID       string  `json:"cve_id"`
	Description string  `json:"description,omitempty"`
	Severity    string  `json:"severity,omitempty"`
	CVSSScore   float64 `json:"cvss_score,omitempty"`
	InKEV       bool    `json:"in_kev,omitempty"`
	Source      string  `json:"source,omitempty"`
}

// listVulnerabilitiesPageSize is the per-page request size the CLI uses
// when paging /api/v1/projects/:id/vulnerabilities. M1 Codex review #F26:
// the server now caps `?limit=` at 500 (handler.VulnsMaxLimit) and returns
// 400 on out-of-band values, so the CLI requests pages at the maximum
// allowed size to minimise the round-trip count while staying within the
// server's clamp.
//
// ※要確認: keep this in sync with sbomhub/apps/api/internal/handler/sbom.go
// VulnsMaxLimit (500). If the server raises the cap, the CLI can be
// updated independently, but a value above the server's cap will start
// returning 400 on the first request.
const listVulnerabilitiesPageSize = 500

// listVulnerabilitiesMaxPages is a defensive ceiling on the number of
// pages the CLI is willing to fetch before erroring out. At 500 rows per
// page this caps the CLI at 100,000 vulnerabilities per project, which
// is well above any realistic Japanese SMB inventory and serves only as
// a runaway guard if the server starts ignoring the truncation signal
// (returning full pages forever). Hit ceiling → return whatever we have
// + an error so the operator can investigate rather than the CLI
// looping forever.
//
// ※要確認: 200 pages is arbitrary; tune once we have real-world fleet
// data. A value too low would silently truncate; too high lets a buggy
// server keep the CLI hung.
const listVulnerabilitiesMaxPages = 200

// ListVulnerabilities returns the project's vulnerabilities so the
// triage CLI can iterate over them.
//
// M1 Codex review #F26: the server now paginates responses with
// `?limit=&offset=` (default 100, max 500). The CLI pages through using
// listVulnerabilitiesPageSize per request and stops when either:
//   - a page returns fewer rows than the requested page size (canonical
//     "no more rows" signal for offset-based pagination), or
//   - listVulnerabilitiesMaxPages is reached (defensive ceiling).
//
// The server returns a bare JSON array per page (no envelope) so the
// existing Web UI fetch path keeps working unchanged. We retain the
// enveloped-shape fallback for forward compatibility with a future
// server that may switch to `{ "vulnerabilities": [...] }` — but the
// fallback only applies to single-page responses (a server that
// switches to envelopes would also have to add a paging cursor, at
// which point this client needs an update).
func (c *Client) ListVulnerabilities(ctx context.Context, projectID string) ([]VulnerabilityRecord, error) {
	all := make([]VulnerabilityRecord, 0, listVulnerabilitiesPageSize)
	offset := 0
	for page := 0; page < listVulnerabilitiesMaxPages; page++ {
		batch, err := c.listVulnerabilitiesPage(ctx, projectID, listVulnerabilitiesPageSize, offset)
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)
		// Server returned fewer rows than the page size → end of the
		// dataset. This is the canonical offset-pagination "no more
		// rows" signal because the server does not (yet) emit a
		// has_more / next_cursor envelope.
		if len(batch) < listVulnerabilitiesPageSize {
			return all, nil
		}
		offset += len(batch)
	}
	// Defensive ceiling — should be unreachable in practice for realistic
	// inventories. We return the partial result + an error so the operator
	// can decide whether to act on what was fetched.
	return all, fmt.Errorf("vulnerabilities ページング上限 (%d ページ × %d 件) 到達: サーバーがページング終端を返していない可能性があります",
		listVulnerabilitiesMaxPages, listVulnerabilitiesPageSize)
}

// listVulnerabilitiesPage fetches a single (limit, offset) page from the
// server. Extracted from ListVulnerabilities so the paging loop stays
// readable and so tests can drive the per-page decode independently.
func (c *Client) listVulnerabilitiesPage(ctx context.Context, projectID string, limit, offset int) ([]VulnerabilityRecord, error) {
	endpoint := fmt.Sprintf("%s/api/v1/projects/%s/vulnerabilities?limit=%d&offset=%d",
		c.baseURL, projectID, limit, offset)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("vulnerabilities リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, decodeTriageError(http.MethodGet, endpoint, resp.StatusCode, respBody)
	}

	// Accept both shapes — the canonical handler returns a bare array,
	// but defensive decoding for an enveloped `{ "vulnerabilities":
	// [...] }` keeps the CLI compatible with future server changes
	// without a coordinated release.
	var bare []VulnerabilityRecord
	if err := json.Unmarshal(respBody, &bare); err == nil {
		return bare, nil
	}
	var enveloped struct {
		Vulnerabilities []VulnerabilityRecord `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(respBody, &enveloped); err != nil {
		return nil, fmt.Errorf("vulnerabilities レスポンス解析エラー: %w", err)
	}
	return enveloped.Vulnerabilities, nil
}
