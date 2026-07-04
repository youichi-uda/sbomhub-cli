package commands

// `sbomhub evidence-pack` — download a Compliance Evidence Pack for a
// project (M31 Wave C — F407, sbomhub-cli issue #7).
//
// The pack is assembled on-demand by the server from the project's
// approved VEX drafts, approved CRA reports, and METI self-assessment
// rows and streamed back as either a machine-readable Zip bundle
// (default) or the legacy Markdown report:
//
//	sbomhub evidence-pack --project <id|name> \
//	    [--format zip|markdown] \
//	    [--output <path>] \
//	    [--include-vex-approved] \
//	    [--include-cra-approved] \
//	    [--include-meti-assessment]
//
// The response body is written to disk verbatim: to --output when given,
// otherwise to the server-supplied filename (Content-Disposition) in the
// current directory, otherwise to a locally-synthesised
// ./evidence-pack-<project>-<timestamp>.<ext> name.
//
// Exit codes follow the shared M1/M2 envelope via evidencePackExitError:
//   0  success (pack written)
//   3  permanent (400 unsupported format / 403 no write permission /
//      404 project not found — fix config, not a retry)
//   4  transient (429 / 5xx — retry recommended)
//
// This is a download-only surface: the pack is NOT auto-submitted to any
// authority. The 24h/72h CRA clock and the decision to submit remain a
// human judgement (M0-M30 "AI drafts, humans approve" invariant).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/youichi-uda/sbomhub-cli/internal/api"
)

// ---------------------------------------------------------------------------
// Flag globals — package-scoped to match the triage / cra / scan conventions.
// ---------------------------------------------------------------------------

var (
	evidencePackProject     string
	evidencePackFormat      string
	evidencePackOutput      string
	evidencePackIncludeVEX  bool
	evidencePackIncludeCRA  bool
	evidencePackIncludeMETI bool
)

// evidencePackExitError lets runEvidencePack request a specific process
// exit code through the cobra RunE contract, picked up by main.go's
// exitCoder hook (mirrors craExitError / triageExitError).
type evidencePackExitError struct {
	code int
	msg  string
}

func (e *evidencePackExitError) Error() string { return e.msg }
func (e *evidencePackExitError) ExitCode() int { return e.code }

var evidencePackCmd = &cobra.Command{
	Use:   "evidence-pack",
	Short: "コンプライアンス Evidence Pack を生成・ダウンロード / Build & download a compliance evidence pack",
	Long: `プロジェクトの承認済 VEX draft / CRA 報告書 / METI 自己評価から
Compliance Evidence Pack を組み立ててダウンロードします (M31)。

Formats:
  zip       machine-readable な Zip bundle (default)。 中身:
              report.md / vex.cdx.json / cra/<type>.<lang>.md /
              meti-assessment.json / manifest.json (SHA-256 + provenance)
  markdown  既存の Markdown レポート (browser 版と同一、 後方互換)

内部では POST /api/v1/projects/:id/evidence-pack/build を呼び、 レスポンス
本文をそのまま file に書き出します。 --output 省略時は
./evidence-pack-<project>-<timestamp>.<zip|md> に保存します。

使用例 / Examples:
  sbomhub evidence-pack --project my-device
  sbomhub evidence-pack --project my-device --format markdown -o report.md
  sbomhub evidence-pack --project my-device --include-meti-assessment=false

※ このコマンドは download 専用です。 pack を当局へ自動提出はしません。
   24h/72h の CRA 提出 clock と提出可否の判断は人間が行ってください。

Exit codes:
  0  正常終了 / success (pack written)
  3  恒久エラー / permanent (400 unsupported format / 403 no write / 404 not found)
  4  一時エラー / transient (429 / 5xx — retry recommended)`,
	RunE: runEvidencePack,
}

func init() {
	rootCmd.AddCommand(evidencePackCmd)

	evidencePackCmd.Flags().StringVarP(&evidencePackProject, "project", "p", "", "対象プロジェクト ID (UUID) または名前 / project ID (UUID) or name (必須)")
	evidencePackCmd.Flags().StringVar(&evidencePackFormat, "format", api.EvidencePackFormatZip, "出力形式 / output format (zip | markdown)")
	evidencePackCmd.Flags().StringVarP(&evidencePackOutput, "output", "o", "", "書き出し先 path / output file path (省略時は自動命名)")
	evidencePackCmd.Flags().BoolVar(&evidencePackIncludeVEX, "include-vex-approved", true, "承認済 VEX draft を含める / include approved VEX drafts")
	evidencePackCmd.Flags().BoolVar(&evidencePackIncludeCRA, "include-cra-approved", true, "承認済 CRA 報告書を含める / include approved CRA reports")
	evidencePackCmd.Flags().BoolVar(&evidencePackIncludeMETI, "include-meti-assessment", true, "METI 自己評価を含める / include METI self-assessment")
}

func runEvidencePack(cmd *cobra.Command, args []string) error {
	out := GetOutputConfig()

	if strings.TrimSpace(evidencePackProject) == "" {
		return fmt.Errorf("--project は必須です / --project is required")
	}
	format := strings.ToLower(strings.TrimSpace(evidencePackFormat))
	if format == "" {
		format = api.EvidencePackFormatZip
	}
	if err := validateEvidencePackFormat(format); err != nil {
		return err
	}

	client, err := loadConfigAndClient()
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	res, err := client.BuildEvidencePack(ctx, evidencePackProject, format,
		api.WithVEXApproved(evidencePackIncludeVEX),
		api.WithCRAApproved(evidencePackIncludeCRA),
		api.WithMETIAssessment(evidencePackIncludeMETI),
	)
	if err != nil {
		return evidencePackFailureToExitError("evidence-pack build", err)
	}

	// Defensive: a 2xx with an empty body is a server protocol bug. Surface
	// it as transient so CI can retry rather than writing a 0-byte pack that
	// looks like a success.
	if res == nil || len(res.Data) == 0 {
		return &evidencePackExitError{code: 4, msg: "サーバが空の evidence pack を返しました (protocol error) — retry してください"}
	}

	outputPath := resolveEvidencePackOutputPath(evidencePackOutput, evidencePackProject, res.Format, res.Filename)
	if err := os.WriteFile(outputPath, res.Data, 0o600); err != nil {
		return fmt.Errorf("evidence pack 書き込み失敗 (%s): %w", outputPath, err)
	}

	return renderEvidencePackResult(out, res, outputPath)
}

// validateEvidencePackFormat returns nil iff format is in the allow-list.
// Enforced client-side so an obvious typo fails before a round-trip; the
// server independently rejects unsupported values with 400.
func validateEvidencePackFormat(format string) error {
	switch format {
	case api.EvidencePackFormatZip, api.EvidencePackFormatMarkdown:
		return nil
	}
	return fmt.Errorf("--format は %s / %s のいずれかを指定してください (got %q)",
		api.EvidencePackFormatZip, api.EvidencePackFormatMarkdown, format)
}

// resolveEvidencePackOutputPath decides where the pack is written.
//
// Precedence:
//  1. --output, used verbatim (operator owns the path).
//  2. the server-supplied Content-Disposition filename, in the current
//     directory (already basename-sanitised by the API layer).
//  3. a locally-synthesised ./evidence-pack-<project>-<timestamp>.<ext>.
func resolveEvidencePackOutputPath(outputFlag, project, format, serverFilename string) string {
	if strings.TrimSpace(outputFlag) != "" {
		return outputFlag
	}
	if fn := strings.TrimSpace(serverFilename); fn != "" {
		return filepath.Join(".", filepath.Base(fn))
	}
	ts := time.Now().UTC().Format("20060102-150405")
	name := fmt.Sprintf("evidence-pack-%s-%s%s", sanitizeForFilename(project), ts, evidencePackExt(format))
	return filepath.Join(".", name)
}

// evidencePackExt maps a format to its file extension. Anything other than
// markdown gets .zip (zip is the default and only other value).
func evidencePackExt(format string) string {
	if format == api.EvidencePackFormatMarkdown {
		return ".md"
	}
	return ".zip"
}

// sanitizeForFilename reduces an arbitrary project ref (which may be a
// display name with spaces / slashes) to a filesystem-safe token so the
// synthesised default filename cannot traverse directories or break the
// shell. Non [A-Za-z0-9._-] runs collapse to a single '-'.
func sanitizeForFilename(s string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		return "project"
	}
	return out
}

// renderEvidencePackResult prints the confirmation block (path + size +
// format + VEX/CRA counts when the server supplied them). In --json mode a
// machine-readable summary lands on stdout instead.
func renderEvidencePackResult(out *OutputConfig, res *api.EvidencePackResult, outputPath string) error {
	if out.IsJSON() {
		summary := map[string]interface{}{
			"path":   outputPath,
			"bytes":  len(res.Data),
			"format": res.Format,
		}
		if res.Filename != "" {
			summary["server_filename"] = res.Filename
		}
		if res.VEXCount >= 0 {
			summary["vex_count"] = res.VEXCount
		}
		if res.CRACount >= 0 {
			summary["cra_count"] = res.CRACount
		}
		return out.PrintJSON(summary)
	}

	w := out.humanWriter()
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Evidence Pack")
	fmt.Fprintln(w, "-------------")
	fmt.Fprintf(w, "  Saved to : %s\n", outputPath)
	fmt.Fprintf(w, "  Format   : %s\n", res.Format)
	fmt.Fprintf(w, "  Size     : %d bytes\n", len(res.Data))
	if res.VEXCount >= 0 {
		fmt.Fprintf(w, "  VEX      : %d approved\n", res.VEXCount)
	}
	if res.CRACount >= 0 {
		fmt.Fprintf(w, "  CRA      : %d approved\n", res.CRACount)
	}
	return nil
}

// evidencePackFailureToExitError translates an evidence-pack API error into
// the exit-code envelope (3=permanent, 4=transient), mirroring
// craFailureToExitError. Network / parse errors fall into the transient
// bucket because the operator's correct response (retry) is the same.
func evidencePackFailureToExitError(op string, err error) error {
	if err == nil {
		return nil
	}
	var ee *api.EvidencePackError
	if errors.As(err, &ee) {
		switch {
		case ee.IsPermanent():
			return &evidencePackExitError{code: 3, msg: fmt.Sprintf("%s 恒久エラー / permanent failure: %v", op, err)}
		case ee.IsTransient():
			return &evidencePackExitError{code: 4, msg: fmt.Sprintf("%s 一時エラー / transient failure (retry): %v", op, err)}
		default:
			// Unclassified 4xx (e.g. a future 451) — treat as permanent
			// because the operator's response is "fix something", not "retry".
			return &evidencePackExitError{code: 3, msg: fmt.Sprintf("%s 不明な失敗: %v", op, err)}
		}
	}
	return &evidencePackExitError{code: 4, msg: fmt.Sprintf("%s 一時エラー / transient failure (retry): %v", op, err)}
}
