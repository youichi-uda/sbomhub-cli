package api

// Wire-layer tests for the Evidence Pack API client (M31 Wave C — F407,
// sbomhub-cli issue #7). Mirrors the cra_test.go httptest harness so each
// contract rule has regression coverage independent of the
// `sbomhub evidence-pack` command interaction loop.
//
// Coverage:
//   - zip happy path: binary body round-trips verbatim, filename parsed
//     from Content-Disposition, VEX/CRA counts + format from headers
//   - markdown path: text body round-trips, counts default to -1 when the
//     server omits the count headers (distinguishes "zero" from "unknown")
//   - include_* toggles serialise into the request body
//   - 400 / 403 / 404 surface as *EvidencePackError (IsPermanent), 429 /
//     5xx surface as transient — never silently returned as a pack
//   - Content-Disposition / header parsing helpers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildEvidencePack_ZipHappyPath(t *testing.T) {
	const projectID = "00000000-0000-0000-0000-000000000aaa"
	wantBytes := []byte("PK\x03\x04\x00\x00fake-zip-bytes\xff\xfe")
	const wantFilename = "evidence-pack-my-app-20260704-101112.zip"

	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		wantPath := "/api/v1/projects/" + projectID + "/evidence-pack/build"
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("Authorization = %q, want Bearer test-key", got)
		}
		seenBody, _ = io.ReadAll(r.Body)

		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="`+wantFilename+`"`)
		w.Header().Set("X-Evidence-Pack-VEX-Count", "3")
		w.Header().Set("X-Evidence-Pack-CRA-Count", "2")
		w.Header().Set("X-Evidence-Pack-Format", "zip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(wantBytes)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	res, err := client.BuildEvidencePack(context.Background(), projectID, EvidencePackFormatZip)
	if err != nil {
		t.Fatalf("BuildEvidencePack error: %v", err)
	}
	if !bytes.Equal(res.Data, wantBytes) {
		t.Errorf("Data = %q, want %q", res.Data, wantBytes)
	}
	if res.Filename != wantFilename {
		t.Errorf("Filename = %q, want %q", res.Filename, wantFilename)
	}
	if res.Format != "zip" {
		t.Errorf("Format = %q, want zip", res.Format)
	}
	if res.VEXCount != 3 {
		t.Errorf("VEXCount = %d, want 3", res.VEXCount)
	}
	if res.CRACount != 2 {
		t.Errorf("CRACount = %d, want 2", res.CRACount)
	}
	if res.ContentType != "application/zip" {
		t.Errorf("ContentType = %q, want application/zip", res.ContentType)
	}

	// Request body must carry the format + all three include toggles
	// (default true).
	var req BuildEvidencePackRequest
	if err := json.Unmarshal(seenBody, &req); err != nil {
		t.Fatalf("body parse: %v", err)
	}
	if req.Format != "zip" {
		t.Errorf("body format = %q, want zip", req.Format)
	}
	if !req.IncludeVEXApproved || !req.IncludeCRAApproved || !req.IncludeMETIAssessment {
		t.Errorf("body includes = %+v, want all true", req)
	}
}

func TestBuildEvidencePack_MarkdownPath(t *testing.T) {
	const projectID = "p1"
	wantText := []byte("# Evidence Pack\n\nApproved VEX + CRA bundle...\n")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req BuildEvidencePackRequest
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		if req.Format != "markdown" {
			t.Errorf("body format = %q, want markdown", req.Format)
		}
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		// Intentionally omit the count headers — older server shape.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(wantText)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	res, err := client.BuildEvidencePack(context.Background(), projectID, EvidencePackFormatMarkdown)
	if err != nil {
		t.Fatalf("BuildEvidencePack error: %v", err)
	}
	if !bytes.Equal(res.Data, wantText) {
		t.Errorf("Data = %q, want %q", res.Data, wantText)
	}
	if res.Format != "markdown" {
		t.Errorf("Format = %q, want markdown", res.Format)
	}
	// Absent headers → -1 (unknown), NOT 0 (zero approved).
	if res.VEXCount != -1 || res.CRACount != -1 {
		t.Errorf("counts = %d/%d, want -1/-1 when headers absent", res.VEXCount, res.CRACount)
	}
	if res.Filename != "" {
		t.Errorf("Filename = %q, want empty when Content-Disposition absent", res.Filename)
	}
}

func TestBuildEvidencePack_IncludeToggles(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/zip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("PKzip"))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	_, err := client.BuildEvidencePack(context.Background(), "p", EvidencePackFormatZip,
		WithVEXApproved(true),
		WithCRAApproved(false),
		WithMETIAssessment(false),
	)
	if err != nil {
		t.Fatalf("BuildEvidencePack error: %v", err)
	}
	var req BuildEvidencePackRequest
	if err := json.Unmarshal(seenBody, &req); err != nil {
		t.Fatalf("body parse: %v", err)
	}
	if !req.IncludeVEXApproved {
		t.Errorf("IncludeVEXApproved = false, want true")
	}
	if req.IncludeCRAApproved {
		t.Errorf("IncludeCRAApproved = true, want false")
	}
	if req.IncludeMETIAssessment {
		t.Errorf("IncludeMETIAssessment = true, want false")
	}
}

func TestBuildEvidencePack_ErrorsSurfaced(t *testing.T) {
	cases := []struct {
		name          string
		status        int
		body          string
		wantPermanent bool
		wantTransient bool
	}{
		{"400 unsupported format", http.StatusBadRequest, `{"error":"unsupported format"}`, true, false},
		{"403 no write permission", http.StatusForbidden, `{"error":"write permission required"}`, true, false},
		{"404 project not found", http.StatusNotFound, `{"error":"project not found"}`, true, false},
		{"429 rate limited", http.StatusTooManyRequests, `{"error":"slow down"}`, false, true},
		{"500 server error", http.StatusInternalServerError, `boom`, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-key")
			res, err := client.BuildEvidencePack(context.Background(), "p", EvidencePackFormatZip)
			if err == nil {
				t.Fatalf("expected error for status %d, got nil (res=%+v)", tc.status, res)
			}
			if res != nil {
				t.Errorf("res = %+v, want nil on error (must NOT return an error page as a pack)", res)
			}
			var ee *EvidencePackError
			if !errors.As(err, &ee) {
				t.Fatalf("error type = %T, want *EvidencePackError", err)
			}
			if ee.StatusCode != tc.status {
				t.Errorf("StatusCode = %d, want %d", ee.StatusCode, tc.status)
			}
			if ee.IsPermanent() != tc.wantPermanent {
				t.Errorf("IsPermanent = %v, want %v", ee.IsPermanent(), tc.wantPermanent)
			}
			if ee.IsTransient() != tc.wantTransient {
				t.Errorf("IsTransient = %v, want %v", ee.IsTransient(), tc.wantTransient)
			}
		})
	}
}

func TestFilenameFromContentDisposition(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{"", ""},
		{`attachment; filename="evidence-pack-p-20260704.zip"`, "evidence-pack-p-20260704.zip"},
		{`attachment; filename=plain.md`, "plain.md"},
		{`inline`, ""},
		// Hostile path component must be reduced to a basename.
		{`attachment; filename="../../etc/passwd"`, "passwd"},
	}
	for _, tc := range cases {
		if got := filenameFromContentDisposition(tc.header); got != tc.want {
			t.Errorf("filenameFromContentDisposition(%q) = %q, want %q", tc.header, got, tc.want)
		}
	}
}

func TestHeaderCountOrNeg(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", -1},
		{"0", 0},
		{"7", 7},
		{" 42 ", 42},
		{"-1", -1},
		{"abc", -1},
	}
	for _, tc := range cases {
		if got := headerCountOrNeg(tc.in); got != tc.want {
			t.Errorf("headerCountOrNeg(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
