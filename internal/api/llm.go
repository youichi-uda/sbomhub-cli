package api

// LLM provider connectivity health client — wraps the public
// /api/v1/health endpoint exposed by sbomhub/apps/api (see
// sbomhub/apps/api/cmd/server/main.go where it is the only no-auth
// GET under /api/v1).
//
// The CLI's `sbomhub llm test` subcommand uses Health() to confirm
// the API server is reachable and to surface whichever LLM provider
// metadata the server is willing to publish on the unauthenticated
// health path. The bench harness (`sbomhub llm bench`) is implemented
// out-of-band by shelling out to sbomhub/apps/api/cmd/llm-bench (see
// cmd/sbomhub/commands/llm.go) and does NOT live here.
//
// ※要確認:
//   - The current sbomhub API health endpoint
//     (apps/api/cmd/server/main.go line 591) returns only
//     {status, mode} — no provider / model / connected fields. The
//     Health() helper parses the response permissively so the CLI
//     gracefully reports "N/A" for the missing fields until the
//     server is extended (tracked as a separate M4-* issue, scoped
//     out of this milestone). When the server adds a richer payload
//     the matching fields below pick it up automatically.
//   - There is no LLM-specific health endpoint yet
//     (/api/v1/health/llm). Adding one is the cleanest long-term
//     answer but requires an API surface bump + auth decision
//     (public vs. API-key gated) that is out of scope for this CLI
//     wave. The CLI falls back to /api/v1/health for now.
//
// M1 / M2 / M3 fix patterns carried over (regression coverage in
// llm_test.go):
//   - F21 exit code classification (3 permanent, 4 transient — done
//         at the command layer; the typed LLMError + IsPermanent /
//         IsTransient surface mirrors *MetiError so the command
//         layer can branch consistently)
//   - F22 strict 503 AI-disabled detection (only 503s with a
//         recognised reason classify as ai_disabled; gateway 503s
//         remain transient outages)
//   - F23 2xx response contract validation (a 200 with no status
//         field is a protocol violation)

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ----------------------------------------------------------------------------
// Wire DTOs
// ----------------------------------------------------------------------------

// LLMHealthResponse is the parsed shape of GET /api/v1/health as
// consumed by the CLI's `sbomhub llm test` subcommand.
//
// The server today (apps/api/cmd/server/main.go line 591) returns
// only {status, mode}. The richer Provider / Model / Connected /
// Reason fields are reserved for a follow-up server change (※要確認
// above); the JSON decoder leaves them at zero values when absent so
// the CLI can render "N/A" rather than misreporting a particular
// provider. When the server adds the fields they round-trip through
// here verbatim.
type LLMHealthResponse struct {
	// Status is the API server's self-reported liveness. The current
	// server returns "ok" on the happy path. The field is REQUIRED
	// for a valid 2xx response — its absence is treated as a F23
	// protocol violation.
	Status string `json:"status"`

	// Mode mirrors config.Mode() on the server side ("byok" /
	// "managed_gemini"). Currently emitted; the CLI surfaces it so
	// operators can confirm a self-host deployment is in "byok"
	// rather than accidentally hitting a SaaS endpoint.
	Mode string `json:"mode,omitempty"`

	// Provider is the active LLM provider identifier
	// (openai / anthropic / gemini / azure_openai / ollama).
	// Empty when the server does not publish it on the health path
	// (today's behaviour) — the CLI renders "N/A".
	Provider string `json:"provider,omitempty"`

	// Model is the active provider's model id (e.g. gpt-5,
	// qwen2.5-coder:7b). Empty when not published.
	Model string `json:"model,omitempty"`

	// Connected reports whether the server believes the LLM provider
	// is reachable / authenticated. Pointer so the CLI can
	// distinguish "server did not publish" (nil → render "N/A") from
	// "server explicitly says false" (*false → render "disconnected"
	// + the Reason).
	Connected *bool `json:"connected,omitempty"`

	// Reason is the human-readable explanation for !Connected — e.g.
	// "OPENAI_API_KEY not set", "ollama unreachable at
	// http://localhost:11434". Only meaningful when Connected is
	// non-nil and *Connected == false.
	Reason string `json:"reason,omitempty"`
}

// ----------------------------------------------------------------------------
// Error decoding
// ----------------------------------------------------------------------------

// LLMError is the typed error returned by Health() when the server
// emits a non-2xx response. Mirrors *MetiError so the CLI loop can
// branch on the same IsPermanent / IsTransient surface (F21).
//
// IsAIDisabled is the M2-CRA-style oracle on 503: when the body
// carries a recognised "AI features disabled / BYOK key not
// configured" reason the CLI treats the failure as a soft signal
// (still permanent, but the operator's correct action is "configure
// BYOK in /settings/llm", not "retry"). A gateway 503 page without
// the marker stays in the transient bucket (F22).
type LLMError struct {
	StatusCode int
	URL        string
	Method     string
	Message    string // top-level "error" field
	Reason     string // top-level "reason" field (only populated for 503 DisabledError)
	Raw        string // original body, preserved for debug logging

	// ProtocolError flags a synthesised LLMError raised for a 2xx
	// response that violated the success contract — server returned
	// HTTP 200 but the body had no status field, or carried an
	// explicit "error" field. Callers inspect this via IsTransient
	// (always true when set) so the CLI loop surfaces such bugs
	// through the exit-4 transient path instead of silently
	// bucketing the call as a success (mirrors M1 #F23).
	ProtocolError bool
}

func (e *LLMError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("llm health %s %s -> %d: %s (%s)", e.Method, e.URL, e.StatusCode, e.Message, e.Reason)
	}
	if e.Message != "" {
		return fmt.Sprintf("llm health %s %s -> %d: %s", e.Method, e.URL, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("llm health %s %s -> %d: %s", e.Method, e.URL, e.StatusCode, e.Raw)
}

// llmAIDisabledReasonMarkers are the substrings (case-insensitive)
// we recognise as the BYOK-not-configured signal on a 503 response.
// Mirrors craAIDisabledReasonMarkers verbatim — keep them in sync if
// the server changes its DisabledError reason wording.
//
// F22 carry-over: only 503s with a recognised reason text classify
// as AI-disabled. Anything else on 503 is treated as a real outage
// and classifies as transient (see IsTransient).
var llmAIDisabledReasonMarkers = []string{
	"ai features are disabled",
	"byok key not configured",
	"byok not configured",
}

// IsAIDisabled reports whether the server signalled the BYOK-not-
// configured fallback path on a 503 response.
//
// The CLI's `sbomhub llm test` surfaces this as a permanent (exit-3)
// failure with the operator-actionable hint "configure BYOK in
// /settings/llm" — distinct from a generic 503 (which the CLI
// surfaces as transient and tells the operator to retry).
func (e *LLMError) IsAIDisabled() bool {
	if e == nil || e.StatusCode != http.StatusServiceUnavailable {
		return false
	}
	hay := strings.ToLower(e.Message + " " + e.Reason + " " + e.Raw)
	for _, m := range llmAIDisabledReasonMarkers {
		if strings.Contains(hay, m) {
			return true
		}
	}
	return false
}

// IsPermanent reports whether the error is a permanent failure that
// the operator cannot retry without fixing config (auth / missing
// endpoint / AI-disabled). 429 (rate limit) is transient. Generic
// 503 is transient (the operator's correct response is "retry" — an
// AI-disabled 503 is folded into permanent via IsAIDisabled which
// the command layer checks first).
func (e *LLMError) IsPermanent() bool {
	if e == nil {
		return false
	}
	if e.IsAIDisabled() {
		// BYOK-not-configured needs operator action (configure key),
		// not a retry — bucket as permanent.
		return true
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
// operator can resolve by retrying — 429 (rate limit), generic 5xx
// (server error / upstream blip), and ProtocolError (server contract
// violation that may be redeploy-fixed).
//
// Symmetric with IsPermanent: a properly-classified error must land
// in exactly one bucket.
func (e *LLMError) IsTransient() bool {
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
		// AI-disabled wins via IsAIDisabled() + the command-layer
		// short-circuit; everything else on 503 is a real outage
		// that the operator can resolve by retrying.
		return !e.IsAIDisabled()
	}
	return e.StatusCode >= 500 && e.StatusCode < 600
}

// decodeLLMError builds an LLMError from a non-2xx response body.
// Tolerates non-JSON bodies (intermediate gateways sometimes send
// HTML 502 pages) — Raw always carries the original text.
func decodeLLMError(method, url string, status int, body []byte) *LLMError {
	te := &LLMError{
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
// Health — GET /api/v1/health
// ----------------------------------------------------------------------------

// Health probes the server's public /api/v1/health endpoint and
// returns the parsed response.
//
// Auth: the endpoint is the only no-auth GET under /api/v1 (see
// sbomhub/apps/api/cmd/server/main.go line 591). The Authorization
// header is sent anyway so a gateway / reverse proxy that requires
// it does not reject the probe; the upstream Echo handler ignores
// the header.
//
// F23 carry-over: a 2xx response with no "status" field is surfaced
// as a transient *LLMError (ProtocolError=true) so the command layer
// catches the server bug rather than silently green-lighting a
// no-payload probe.
func (c *Client) Health(ctx context.Context) (*LLMHealthResponse, error) {
	endpoint := fmt.Sprintf("%s/api/v1/health", c.baseURL)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	// Auth header is informational on this endpoint (server ignores
	// it) but sending it costs nothing and protects against gateway
	// configurations that strip unauthenticated requests.
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("llm health リクエスト送信エラー: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	// M4 Codex review #F39 fix: treat any non-2xx response (not just
	// the narrow != 200 case) as an LLMError. Previously a 204 No
	// Content / 206 Partial Content would skip this branch, then
	// fall into the JSON-parse / status-validation path and surface
	// as a plain fmt.Errorf — which the command layer's default
	// switch maps to exit-3 instead of the intended transient
	// exit-4 (F23 contract). With the wider range, 2xx-but-not-200
	// responses with empty / missing-status bodies now correctly
	// flow through the ProtocolError=true transient bucket below.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, decodeLLMError(http.MethodGet, endpoint, resp.StatusCode, respBody)
	}

	var out LLMHealthResponse
	// 204 No Content (and any other empty-body 2xx) must NOT be
	// flagged as a JSON parse error — skip the unmarshal when the
	// body is blank and let the status check below classify the
	// empty payload as a ProtocolError. A malformed (non-empty)
	// body still falls into the parse-error path so the operator
	// sees a precise diagnostic.
	if len(strings.TrimSpace(string(respBody))) > 0 {
		if err := json.Unmarshal(respBody, &out); err != nil {
			return nil, fmt.Errorf("llm health レスポンス解析エラー: %w", err)
		}
	}
	if strings.TrimSpace(out.Status) == "" {
		// F23 carry-over: a 2xx without a recognisable status field
		// is a server protocol violation. Surface as ProtocolError /
		// transient so the CLI retries instead of silently
		// confirming a no-op probe.
		//
		// F39 carry-over: this branch now also catches 204 / 206
		// / any other "success but non-OK" response that the
		// widened status check above lets through to the decode
		// stage.
		return nil, &LLMError{
			StatusCode:    resp.StatusCode,
			URL:           endpoint,
			Method:        http.MethodGet,
			Message:       "llm health success response missing status field (server protocol error — F23 / F39 contract violation)",
			Raw:           string(respBody),
			ProtocolError: true,
		}
	}
	return &out, nil
}
