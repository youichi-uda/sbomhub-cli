package api

// Unit tests for the LLM health API client helper. Mirrors the M3
// meti_test.go structure so each fix pattern carried over to M4 has
// regression coverage at the wire layer, independent of the
// `sbomhub llm test` command surface.
//
// Coverage matrix (one test class per pattern):
//   - F21 happy path + permanent vs transient classification
//   - F22 strict 503 AI-disabled detection (gateway 503 vs
//         BYOK-not-configured 503)
//   - F23 2xx contract validation (no status field → ProtocolError)

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ----------------------------------------------------------------------------
// Happy path
// ----------------------------------------------------------------------------

// TestHealth_HappyPath_MinimalServer verifies the today-shape of
// /api/v1/health (just {status, mode}) decodes cleanly and the CLI
// gracefully reports the missing provider/model fields.
func TestHealth_HappyPath_MinimalServer(t *testing.T) {
	var seenAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/api/v1/health" {
			t.Errorf("path = %s, want /api/v1/health", r.URL.Path)
		}
		seenAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
			"mode":   "byok",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	res, err := client.Health(context.Background())
	if err != nil {
		t.Fatalf("Health error: %v", err)
	}
	if res.Status != "ok" {
		t.Errorf("Status = %q, want ok", res.Status)
	}
	if res.Mode != "byok" {
		t.Errorf("Mode = %q, want byok", res.Mode)
	}
	if res.Provider != "" || res.Model != "" || res.Connected != nil {
		t.Errorf("Provider/Model/Connected should default zero when server omits them: %+v", res)
	}
	if seenAuth != "Bearer test-key" {
		// Even though the server ignores the header, the CLI should
		// send it so gateways that reject unauthenticated requests
		// do not break the probe.
		t.Errorf("Authorization = %q, want Bearer test-key", seenAuth)
	}
}

// TestHealth_HappyPath_RichServer verifies the forward-compat path
// where the server eventually publishes provider/model/connected on
// the health response.
func TestHealth_HappyPath_RichServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "ok",
			"mode":      "byok",
			"provider":  "ollama",
			"model":     "qwen2.5-coder:7b",
			"connected": true,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "k")
	res, err := client.Health(context.Background())
	if err != nil {
		t.Fatalf("Health error: %v", err)
	}
	if res.Provider != "ollama" || res.Model != "qwen2.5-coder:7b" {
		t.Errorf("provider/model not surfaced: %+v", res)
	}
	if res.Connected == nil || !*res.Connected {
		t.Errorf("Connected should be *true, got %v", res.Connected)
	}
}

// TestHealth_NoAPIKey verifies the helper still works when no API
// key is configured (the endpoint is public; the Authorization
// header is suppressed).
func TestHealth_NoAPIKey(t *testing.T) {
	var seenAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "")
	if _, err := client.Health(context.Background()); err != nil {
		t.Fatalf("Health error: %v", err)
	}
	if seenAuth != "" {
		t.Errorf("Authorization = %q, want empty when no API key set", seenAuth)
	}
}

// ----------------------------------------------------------------------------
// F21 — exit-code classification surface
// ----------------------------------------------------------------------------

// TestHealth_PermanentClientError verifies 4xx (except 429) → IsPermanent.
func TestHealth_PermanentClientError(t *testing.T) {
	cases := []struct {
		name string
		code int
		want bool // IsPermanent
	}{
		{"400 bad request", http.StatusBadRequest, true},
		{"401 unauthorized", http.StatusUnauthorized, true},
		{"403 forbidden", http.StatusForbidden, true},
		{"404 not found", http.StatusNotFound, true},
		{"429 rate limit", http.StatusTooManyRequests, false},
		{"500 internal", http.StatusInternalServerError, false},
		{"503 generic", http.StatusServiceUnavailable, false},
		{"502 bad gateway", http.StatusBadGateway, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(`{"error":"x"}`))
			}))
			defer server.Close()
			client := NewClient(server.URL, "k")
			_, err := client.Health(context.Background())
			var le *LLMError
			if !errors.As(err, &le) {
				t.Fatalf("err = %v, want *LLMError", err)
			}
			if got := le.IsPermanent(); got != tc.want {
				t.Errorf("IsPermanent() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestHealth_TransientClassification verifies the transient surface
// is symmetric with the permanent one (429 + 5xx → transient).
func TestHealth_TransientClassification(t *testing.T) {
	cases := []struct {
		name string
		code int
		want bool // IsTransient
	}{
		{"400", http.StatusBadRequest, false},
		{"401", http.StatusUnauthorized, false},
		{"429", http.StatusTooManyRequests, true},
		{"500", http.StatusInternalServerError, true},
		{"503 generic", http.StatusServiceUnavailable, true},
		{"504 gateway timeout", http.StatusGatewayTimeout, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(`{"error":"x"}`))
			}))
			defer server.Close()
			client := NewClient(server.URL, "k")
			_, err := client.Health(context.Background())
			var le *LLMError
			if !errors.As(err, &le) {
				t.Fatalf("err = %v, want *LLMError", err)
			}
			if got := le.IsTransient(); got != tc.want {
				t.Errorf("IsTransient() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// F22 — strict 503 AI-disabled detection
// ----------------------------------------------------------------------------

// TestHealth_503AIDisabled_Strict verifies only 503s with a
// recognised reason marker classify as ai_disabled. A gateway 503
// page (no marker) stays transient — a regression that mis-classified
// gateway 503 as "BYOK off" would silently let CI exit 0 against a
// dead server.
func TestHealth_503AIDisabled_Strict(t *testing.T) {
	cases := []struct {
		name           string
		body           string
		wantAIDisabled bool
		wantTransient  bool
		wantPermanent  bool
	}{
		{
			name:           "503 with reason: ai features are disabled",
			body:           `{"error":"AI disabled","reason":"AI features are disabled"}`,
			wantAIDisabled: true,
			wantTransient:  false,
			wantPermanent:  true,
		},
		{
			name:           "503 with reason: byok key not configured",
			body:           `{"error":"BYOK","reason":"BYOK key not configured"}`,
			wantAIDisabled: true,
			wantTransient:  false,
			wantPermanent:  true,
		},
		{
			name:           "503 generic gateway page",
			body:           `<html><body>503 Service Unavailable</body></html>`,
			wantAIDisabled: false,
			wantTransient:  true,
			wantPermanent:  false,
		},
		{
			name:           "503 with unrelated reason",
			body:           `{"error":"upstream blip","reason":"redis disconnected"}`,
			wantAIDisabled: false,
			wantTransient:  true,
			wantPermanent:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			client := NewClient(server.URL, "k")
			_, err := client.Health(context.Background())
			var le *LLMError
			if !errors.As(err, &le) {
				t.Fatalf("err = %v, want *LLMError", err)
			}
			if got := le.IsAIDisabled(); got != tc.wantAIDisabled {
				t.Errorf("F22: IsAIDisabled = %v, want %v (body=%s)", got, tc.wantAIDisabled, tc.body)
			}
			if got := le.IsTransient(); got != tc.wantTransient {
				t.Errorf("F22: IsTransient = %v, want %v", got, tc.wantTransient)
			}
			if got := le.IsPermanent(); got != tc.wantPermanent {
				t.Errorf("F22: IsPermanent = %v, want %v", got, tc.wantPermanent)
			}
		})
	}
}

// TestHealth_NonJSONErrorBody confirms the helper does not crash on
// non-JSON bodies (intermediate gateways often emit HTML 502 pages).
func TestHealth_NonJSONErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "<html>502 Bad Gateway</html>")
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	_, err := client.Health(context.Background())
	var le *LLMError
	if !errors.As(err, &le) {
		t.Fatalf("err = %v, want *LLMError", err)
	}
	if le.StatusCode != http.StatusBadGateway {
		t.Errorf("StatusCode = %d, want 502", le.StatusCode)
	}
	if !strings.Contains(le.Raw, "Bad Gateway") {
		t.Errorf("Raw body lost: %q", le.Raw)
	}
}

// ----------------------------------------------------------------------------
// F23 — 2xx contract validation
// ----------------------------------------------------------------------------

// TestHealth_2xxEmptyStatus_F23 — a 200 with no status field is a
// server protocol violation. Must surface as transient so CI does
// not silently green-light a no-payload probe.
func TestHealth_2xxEmptyStatus_F23(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	_, err := client.Health(context.Background())
	if err == nil {
		t.Fatal("F23: expected error for 2xx with no status field")
	}
	var le *LLMError
	if !errors.As(err, &le) {
		t.Fatalf("F23: err = %v (%T), want *LLMError", err, err)
	}
	if !le.ProtocolError {
		t.Errorf("F23: ProtocolError must be true")
	}
	if !le.IsTransient() {
		t.Errorf("F23: protocol violation must classify transient")
	}
	if le.IsPermanent() {
		t.Errorf("F23: protocol violation must NOT classify permanent")
	}
}

// TestHealth_2xxMalformedJSON — a 200 whose body is not parseable
// JSON should surface as a parse error (not silently bucket as
// success). We do not require a typed *LLMError here because the
// JSON parser failure is a stdlib error; the operator just needs
// the round-trip to fail visibly.
func TestHealth_2xxMalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "not json {{")
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	res, err := client.Health(context.Background())
	if err == nil {
		t.Fatalf("expected JSON parse error, got res=%+v", res)
	}
}

// ----------------------------------------------------------------------------
// F39 — 2xx (non-200) contract validation
//
// Codex review M4 #F39: before the fix `Health` only treated
// `resp.StatusCode != 200` as an error path, so 204 / 206 fell
// through to the JSON decode and surfaced as plain fmt.Errorf —
// classified by the command layer's default branch as exit-3
// permanent. The contract per F23 is that a 2xx with a contract
// violation is transient (ProtocolError=true → exit-4).
// ----------------------------------------------------------------------------

// TestHealth_204NoContent_F39 — a 204 No Content (empty body, no
// status field) must surface as a ProtocolError transient. Reverting
// the F39 fix re-introduces the exit-3 misclassification.
func TestHealth_204NoContent_F39(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// http.ResponseWriter clears the body for 204 automatically;
		// we set it explicitly here as documentation of intent.
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	_, err := client.Health(context.Background())
	if err == nil {
		t.Fatal("F39: expected error for 204 No Content (no status field)")
	}
	var le *LLMError
	if !errors.As(err, &le) {
		t.Fatalf("F39: err = %v (%T), want *LLMError", err, err)
	}
	if le.StatusCode != http.StatusNoContent {
		t.Errorf("F39: StatusCode = %d, want 204", le.StatusCode)
	}
	if !le.ProtocolError {
		t.Errorf("F39: ProtocolError must be true for 204 with no status field")
	}
	if !le.IsTransient() {
		t.Errorf("F39: 204 ProtocolError must classify transient (exit-4)")
	}
	if le.IsPermanent() {
		t.Errorf("F39: 204 ProtocolError must NOT classify permanent")
	}
}

// TestHealth_206PartialContent_F39 — a 206 with a non-empty but
// status-less JSON body must also surface as ProtocolError
// transient. 206 is plausible if a misconfigured reverse proxy
// hands back partial Range responses for the health probe.
func TestHealth_206PartialContent_F39(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(w, `{"mode":"byok"}`)
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	_, err := client.Health(context.Background())
	if err == nil {
		t.Fatal("F39: expected error for 206 without status field")
	}
	var le *LLMError
	if !errors.As(err, &le) {
		t.Fatalf("F39: err = %v (%T), want *LLMError", err, err)
	}
	if le.StatusCode != http.StatusPartialContent {
		t.Errorf("F39: StatusCode = %d, want 206", le.StatusCode)
	}
	if !le.ProtocolError {
		t.Errorf("F39: ProtocolError must be true for 206 with no status field")
	}
	if !le.IsTransient() {
		t.Errorf("F39: 206 ProtocolError must classify transient (exit-4)")
	}
	if le.IsPermanent() {
		t.Errorf("F39: 206 ProtocolError must NOT classify permanent")
	}
}

// TestHealth_202Accepted_WithStatus_F39 — a 202 Accepted that does
// carry a valid status field must succeed (the widened 2xx check
// must not break legitimate non-200 successes that fulfil the
// contract).
func TestHealth_202Accepted_WithStatus_F39(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
			"mode":   "byok",
		})
	}))
	defer server.Close()
	client := NewClient(server.URL, "k")
	res, err := client.Health(context.Background())
	if err != nil {
		t.Fatalf("F39: 202 with status field should succeed, got err: %v", err)
	}
	if res.Status != "ok" {
		t.Errorf("F39: Status = %q, want ok", res.Status)
	}
}
