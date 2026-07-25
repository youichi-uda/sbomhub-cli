package commands

// Unit tests for `sbomhub evidence-pack` (M31 Wave C — F407, sbomhub-cli
// issue #7). Follows the cra_test.go convention: the run body is replayed
// with an injected api.Client + buffered OutputConfig so tests exercise
// the real command helpers (path resolution, file write, confirmation
// render, exit-code classification) without leaking package globals.
//
// Coverage:
//   - zip happy path: response bytes written verbatim to --output, and
//     the confirmation block reports size + VEX/CRA counts
//   - markdown path: text bytes written, .md default naming
//   - 403 / 400 surfaced as an exit-3 error and NO file written
//   - output-path resolution precedence (flag > server filename > synth)
//   - format validation + filename sanitisation helpers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/youichi-uda/sbomhub-cli/internal/api"
)

// ---------------------------------------------------------------------------
// Replay harness (mirrors runDraftAndCapture)
// ---------------------------------------------------------------------------

type evidencePackArgs struct {
	project     string
	format      string
	output      string
	includeVEX  bool
	includeCRA  bool
	includeMETI bool
}

// runEvidencePackAndCapture replays runEvidencePack's body with an injected
// client + buffered OutputConfig. Deliberately mirrors runEvidencePack
// step-by-step so a refactor there surfaces here.
func runEvidencePackAndCapture(t *testing.T, client *api.Client, args evidencePackArgs) (capturedResult, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	out := &OutputConfig{Writer: &stdout, ErrWriter: &stderr}

	if strings.TrimSpace(args.project) == "" {
		return capturedResult{err: fmt.Errorf("--project は必須です / --project is required")}, &stdout, &stderr
	}
	format := strings.ToLower(strings.TrimSpace(args.format))
	if format == "" {
		format = api.EvidencePackFormatZip
	}
	if err := validateEvidencePackFormat(format); err != nil {
		return capturedResult{err: err}, &stdout, &stderr
	}

	ctx := context.Background()
	res, err := client.BuildEvidencePack(ctx, args.project, format,
		api.WithVEXApproved(args.includeVEX),
		api.WithCRAApproved(args.includeCRA),
		api.WithMETIAssessment(args.includeMETI),
	)
	if err != nil {
		return capturedResult{err: evidencePackFailureToExitError("evidence-pack build", err)}, &stdout, &stderr
	}
	if res == nil || len(res.Data) == 0 {
		return capturedResult{err: &evidencePackExitError{code: 4, msg: "empty pack"}}, &stdout, &stderr
	}
	outputPath := resolveEvidencePackOutputPath(args.output, args.project, res.Format, res.Filename)
	if werr := os.WriteFile(outputPath, res.Data, 0o600); werr != nil {
		return capturedResult{err: fmt.Errorf("write %s: %w", outputPath, werr)}, &stdout, &stderr
	}
	renderErr := renderEvidencePackResult(out, res, outputPath)
	return capturedResult{err: renderErr}, &stdout, &stderr
}

func defaultEvidencePackArgs(project, format, output string) evidencePackArgs {
	return evidencePackArgs{
		project:     project,
		format:      format,
		output:      output,
		includeVEX:  true,
		includeCRA:  true,
		includeMETI: true,
	}
}

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

func TestRunEvidencePack_ZipHappyPath(t *testing.T) {
	wantBytes := []byte("PK\x03\x04\x00\x00zip-body\xff")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req api.BuildEvidencePackRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Format != "zip" {
			t.Errorf("server saw format=%q, want zip", req.Format)
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="evidence-pack-srv-20260704.zip"`)
		w.Header().Set("X-Evidence-Pack-VEX-Count", "4")
		w.Header().Set("X-Evidence-Pack-CRA-Count", "1")
		w.Header().Set("X-Evidence-Pack-Format", "zip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(wantBytes)
	}))
	defer server.Close()

	outPath := filepath.Join(t.TempDir(), "pack.zip")
	client := api.NewClient(server.URL, "test-key")

	res, stdout, stderr := runEvidencePackAndCapture(t, client, defaultEvidencePackArgs("my-app", "zip", outPath))
	if res.err != nil {
		t.Fatalf("evidence-pack returned err: %v (stderr=%s)", res.err, stderr.String())
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read written pack: %v", err)
	}
	if !bytes.Equal(got, wantBytes) {
		t.Errorf("written bytes = %q, want %q", got, wantBytes)
	}
	sout := stdout.String()
	if !strings.Contains(sout, outPath) {
		t.Errorf("stdout missing output path %q: %s", outPath, sout)
	}
	if !strings.Contains(sout, strconv.Itoa(len(wantBytes))+" bytes") {
		t.Errorf("stdout missing byte size: %s", sout)
	}
	if !strings.Contains(sout, "VEX      : 4 approved") {
		t.Errorf("stdout missing VEX count: %s", sout)
	}
	if !strings.Contains(sout, "CRA      : 1 approved") {
		t.Errorf("stdout missing CRA count: %s", sout)
	}
}

func TestRunEvidencePack_MarkdownPath(t *testing.T) {
	wantText := []byte("# Evidence Pack\n\nbody\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req api.BuildEvidencePackRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Format != "markdown" {
			t.Errorf("server saw format=%q, want markdown", req.Format)
		}
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(wantText)
	}))
	defer server.Close()

	outPath := filepath.Join(t.TempDir(), "report.md")
	client := api.NewClient(server.URL, "test-key")

	res, stdout, stderr := runEvidencePackAndCapture(t, client, defaultEvidencePackArgs("my-app", "markdown", outPath))
	if res.err != nil {
		t.Fatalf("evidence-pack returned err: %v (stderr=%s)", res.err, stderr.String())
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read written markdown: %v", err)
	}
	if !bytes.Equal(got, wantText) {
		t.Errorf("written bytes = %q, want %q", got, wantText)
	}
	// Counts absent → not rendered.
	if strings.Contains(stdout.String(), "VEX      :") {
		t.Errorf("stdout should omit VEX count when header absent: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Format   : markdown") {
		t.Errorf("stdout missing markdown format line: %s", stdout.String())
	}
}

// ---------------------------------------------------------------------------
// Error surfacing — must NOT write an error page to disk
// ---------------------------------------------------------------------------

func TestRunEvidencePack_Forbidden403(t *testing.T) {
	assertEvidencePackErrorNoWrite(t, http.StatusForbidden, `{"error":"write permission required"}`, 3)
}

func TestRunEvidencePack_BadFormat400(t *testing.T) {
	assertEvidencePackErrorNoWrite(t, http.StatusBadRequest, `{"error":"unsupported format"}`, 3)
}

func TestRunEvidencePack_ServerError500(t *testing.T) {
	assertEvidencePackErrorNoWrite(t, http.StatusInternalServerError, `boom`, 4)
}

func assertEvidencePackErrorNoWrite(t *testing.T, status int, body string, wantExit int) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	outPath := filepath.Join(t.TempDir(), "should-not-exist.zip")
	client := api.NewClient(server.URL, "test-key")

	res, _, _ := runEvidencePackAndCapture(t, client, defaultEvidencePackArgs("my-app", "zip", outPath))
	if res.err == nil {
		t.Fatalf("expected error for status %d, got nil", status)
	}
	var ec interface{ ExitCode() int }
	if !errors.As(res.err, &ec) {
		t.Fatalf("error %v does not carry an exit code", res.err)
	}
	if ec.ExitCode() != wantExit {
		t.Errorf("exit code = %d, want %d (err=%v)", ec.ExitCode(), wantExit, res.err)
	}
	if _, statErr := os.Stat(outPath); !os.IsNotExist(statErr) {
		t.Errorf("output file was written on error (%d) — must be surfaced, not saved", status)
	}
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

func TestRunEvidencePack_MissingProject(t *testing.T) {
	client := api.NewClient("http://unused", "test-key")
	res, _, _ := runEvidencePackAndCapture(t, client, defaultEvidencePackArgs("", "zip", ""))
	if res.err == nil {
		t.Fatalf("expected error for missing --project")
	}
}

func TestRunEvidencePack_InvalidFormat(t *testing.T) {
	client := api.NewClient("http://unused", "test-key")
	res, _, _ := runEvidencePackAndCapture(t, client, defaultEvidencePackArgs("my-app", "pdf", ""))
	if res.err == nil {
		t.Fatalf("expected validation error for --format pdf")
	}
	if !strings.Contains(res.err.Error(), "--format") {
		t.Errorf("error = %v, want a --format validation message", res.err)
	}
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

func TestResolveEvidencePackOutputPath(t *testing.T) {
	// 1. --output wins verbatim.
	if got := resolveEvidencePackOutputPath("/tmp/x.zip", "proj", "zip", "server.zip"); got != "/tmp/x.zip" {
		t.Errorf("flag precedence: got %q, want /tmp/x.zip", got)
	}
	// 2. server filename used when no flag (basename only).
	if got := resolveEvidencePackOutputPath("", "proj", "zip", "evidence-pack-proj-20260704.zip"); got != filepath.Join(".", "evidence-pack-proj-20260704.zip") {
		t.Errorf("server filename: got %q", got)
	}
	// 3. hostile server filename reduced to basename.
	if got := resolveEvidencePackOutputPath("", "proj", "zip", "../../etc/evil.zip"); got != filepath.Join(".", "evil.zip") {
		t.Errorf("hostile filename not sanitised: got %q", got)
	}
	// 4. synthesised default: prefix + sanitised project + .zip suffix.
	got := resolveEvidencePackOutputPath("", "my project/v2", "zip", "")
	base := filepath.Base(got)
	if !strings.HasPrefix(base, "evidence-pack-my-project-v2-") {
		t.Errorf("synth zip name = %q, want evidence-pack-my-project-v2-<ts>.zip", base)
	}
	if !strings.HasSuffix(base, ".zip") {
		t.Errorf("synth zip name = %q, want .zip suffix", base)
	}
	// 5. markdown default → .md suffix.
	gotMd := resolveEvidencePackOutputPath("", "proj", "markdown", "")
	if !strings.HasSuffix(filepath.Base(gotMd), ".md") {
		t.Errorf("synth md name = %q, want .md suffix", gotMd)
	}
}

func TestEvidencePackExt(t *testing.T) {
	if got := evidencePackExt("markdown"); got != ".md" {
		t.Errorf("markdown ext = %q, want .md", got)
	}
	if got := evidencePackExt("zip"); got != ".zip" {
		t.Errorf("zip ext = %q, want .zip", got)
	}
	if got := evidencePackExt("anything-else"); got != ".zip" {
		t.Errorf("default ext = %q, want .zip", got)
	}
}

func TestSanitizeForFilename(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"my-app", "my-app"},
		{"my project/v2", "my-project-v2"},
		{"a//b", "a-b"},
		{"../../etc", "etc"},
		{"日本語", "project"},
		{"", "project"},
	}
	for _, tc := range cases {
		if got := sanitizeForFilename(tc.in); got != tc.want {
			t.Errorf("sanitizeForFilename(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestValidateEvidencePackFormat(t *testing.T) {
	for _, ok := range []string{"zip", "markdown"} {
		if err := validateEvidencePackFormat(ok); err != nil {
			t.Errorf("validateEvidencePackFormat(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"pdf", "", "ZIP", "json"} {
		if err := validateEvidencePackFormat(bad); err == nil {
			t.Errorf("validateEvidencePackFormat(%q) = nil, want error", bad)
		}
	}
}

func TestEvidencePackFailureToExitError_Classification(t *testing.T) {
	perm := &api.EvidencePackError{StatusCode: http.StatusForbidden}
	trans := &api.EvidencePackError{StatusCode: http.StatusInternalServerError}

	if got := exitCodeOf(t, evidencePackFailureToExitError("op", perm)); got != 3 {
		t.Errorf("403 → exit %d, want 3", got)
	}
	if got := exitCodeOf(t, evidencePackFailureToExitError("op", trans)); got != 4 {
		t.Errorf("500 → exit %d, want 4", got)
	}
	// Non-typed (network) error → transient (exit 4).
	if got := exitCodeOf(t, evidencePackFailureToExitError("op", fmt.Errorf("dial tcp: connection refused"))); got != 4 {
		t.Errorf("network error → exit %d, want 4", got)
	}
	if evidencePackFailureToExitError("op", nil) != nil {
		t.Errorf("nil error must map to nil")
	}
}

func exitCodeOf(t *testing.T, err error) int {
	t.Helper()
	var ec interface{ ExitCode() int }
	if !errors.As(err, &ec) {
		t.Fatalf("error %v carries no exit code", err)
	}
	return ec.ExitCode()
}

// ---------------------------------------------------------------------------
// Cobra wiring
// ---------------------------------------------------------------------------

func TestEvidencePackCommandRegistered(t *testing.T) {
	var found *cobraCmdShape
	for _, c := range rootCmd.Commands() {
		if c.Name() == "evidence-pack" {
			found = &cobraCmdShape{use: c.Use, formatDefault: c.Flags().Lookup("format").DefValue}
			// project + output flags must exist.
			if c.Flags().Lookup("project") == nil {
				t.Errorf("evidence-pack missing --project flag")
			}
			if c.Flags().Lookup("output") == nil {
				t.Errorf("evidence-pack missing --output flag")
			}
			break
		}
	}
	if found == nil {
		t.Fatalf("evidence-pack command not registered on root")
	}
	if found.formatDefault != "zip" {
		t.Errorf("--format default = %q, want zip", found.formatDefault)
	}
}

type cobraCmdShape struct {
	use           string
	formatDefault string
}

// ---------------------------------------------------------------------------
// F409 — --project is a UUID, not a name.
// ---------------------------------------------------------------------------

// TestEvidencePack_ProjectFlagUUIDOnly pins F409: the value is forwarded
// verbatim as the :id path segment and the server parses it with uuid.Parse,
// so the flag help + examples must NOT advertise name support (a name 400s).
// This command deliberately does NOT resolve names to IDs.
func TestEvidencePack_ProjectFlagUUIDOnly(t *testing.T) {
	flag := evidencePackCmd.Flags().Lookup("project")
	if flag == nil {
		t.Fatal("evidence-pack missing --project flag")
	}
	if strings.Contains(flag.Usage, "名前") || strings.Contains(strings.ToLower(flag.Usage), "name") {
		t.Errorf("--project usage must not advertise name support (server 400s a non-UUID): %q", flag.Usage)
	}
	// The Long help examples must not use the ambiguous non-UUID "my-device"
	// value a user would copy-paste into a 400.
	if strings.Contains(evidencePackCmd.Long, "my-device") {
		t.Errorf("evidence-pack Long help must not use the non-UUID 'my-device' example")
	}
}

// looksLikeUUIDForTest mirrors internal/api.looksLikeUUID (unexported) so the
// test can model the server's uuid.Parse gate without adding a uuid dep.
func looksLikeUUIDForTest(s string) bool {
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
			isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}

// TestRunEvidencePack_ForwardsProjectAsPathSegment models the real server
// shape (handler/evidence_pack.go parses :id with uuid.Parse -> 400 on a
// non-UUID): a UUID --project is forwarded verbatim into the path and
// succeeds; a name is forwarded unchanged and the server rejects it with 400
// -> permanent exit 3 with no file written. This documents that names are
// NOT resolved client-side (F409).
func TestRunEvidencePack_ForwardsProjectAsPathSegment(t *testing.T) {
	const goodUUID = "3f1c2d4e-5a6b-7c8d-9e0f-1a2b3c4d5e6f"

	var seenPathSegment string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the :id segment from /api/v1/projects/<id>/evidence-pack/build.
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 4 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "projects" {
			seenPathSegment = parts[3]
		}
		if !looksLikeUUIDForTest(seenPathSegment) {
			// Mirror handler/evidence_pack.go: uuid.Parse fails -> 400.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid project id"}`))
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("PK\x03\x04ok"))
	}))
	defer server.Close()

	client := api.NewClient(server.URL, "test-key")

	// 1. A UUID is forwarded verbatim as the path segment and succeeds.
	outUUID := filepath.Join(t.TempDir(), "uuid.zip")
	res, _, stderr := runEvidencePackAndCapture(t, client, defaultEvidencePackArgs(goodUUID, "zip", outUUID))
	if res.err != nil {
		t.Fatalf("UUID project returned err: %v (stderr=%s)", res.err, stderr.String())
	}
	if seenPathSegment != goodUUID {
		t.Errorf("server saw path segment %q, want the UUID forwarded verbatim %q", seenPathSegment, goodUUID)
	}
	if _, statErr := os.Stat(outUUID); statErr != nil {
		t.Errorf("expected pack written for UUID project: %v", statErr)
	}

	// 2. A name (not a UUID) is forwarded unchanged and the server 400s it
	//    -> permanent exit 3, no file written. Names are NOT resolved here.
	outName := filepath.Join(t.TempDir(), "name.zip")
	resName, _, _ := runEvidencePackAndCapture(t, client, defaultEvidencePackArgs("my-device", "zip", outName))
	if resName.err == nil {
		t.Fatal("expected a 400 error for a non-UUID --project (name), got nil")
	}
	if seenPathSegment != "my-device" {
		t.Errorf("server saw path segment %q, want the name forwarded verbatim (no client-side resolution)", seenPathSegment)
	}
	var ec interface{ ExitCode() int }
	if !errors.As(resName.err, &ec) || ec.ExitCode() != 3 {
		t.Errorf("name -> want permanent exit 3, got err=%v", resName.err)
	}
	if _, statErr := os.Stat(outName); !os.IsNotExist(statErr) {
		t.Errorf("no file must be written when the server 400s the name")
	}
}
