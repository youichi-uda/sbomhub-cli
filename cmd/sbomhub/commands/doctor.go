// Package commands — `sbomhub doctor`
//
// Self-check the local CLI environment so onboarding can fail loudly with
// actionable hints, not silently with confusing API errors later. Each check
// reports `[OK] / [WARN] / [FAIL]`; the command exits 0 unless at least one
// `[FAIL]` is emitted (Trust Rescue P1 #6 / 9.2.2).
package commands

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/youichi-uda/sbomhub-cli/internal/config"
)

// apiKeyPrefix mirrors the server-side constant in
// apps/api/internal/middleware/multiauth.go. Keys not prefixed with this are
// flagged as suspicious by `sbomhub doctor`.
const doctorAPIKeyPrefix = "sbh_"

// doctorDefaultAPIURL is the legacy SaaS endpoint that ships as the `login`
// default. Trust Rescue 9.x has reframed the product as self-host-first, so a
// config still pointing here is reported as [WARN] (operational, not broken,
// but probably not what the user wants now that the SaaS instance is sunset).
const doctorDefaultAPIURL = "https://api.sbomhub.app"

// doctorHTTPTimeout caps each individual HTTP probe. We keep it short because
// `doctor` is meant to be a fast smoke test, not a real health monitor.
const doctorHTTPTimeout = 10 * time.Second

// doctorScanners are the SBOM generators the CLI knows how to drive. If none
// are present we [WARN] rather than [FAIL]: the operator can still upload an
// SBOM produced elsewhere.
var doctorScanners = []string{"syft", "trivy", "cdxgen"}

type doctorStatus int

const (
	doctorOK doctorStatus = iota
	doctorWarn
	doctorFail
)

func (s doctorStatus) String() string {
	switch s {
	case doctorOK:
		return "[OK]"
	case doctorWarn:
		return "[WARN]"
	case doctorFail:
		return "[FAIL]"
	default:
		return "[??]"
	}
}

// doctorResult is one line of `sbomhub doctor` output. `detail` is shown only
// when --verbose is set so the default output stays scannable.
type doctorResult struct {
	name    string
	status  doctorStatus
	message string
	detail  string
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "CLI 環境のセルフチェック",
	Long: `sbomhub doctor は CLI の動作環境を診断します。

設定ファイル / API キー / API URL / API 到達性 / 認証 / scanner 検出 を
順にチェックし、 [OK] / [WARN] / [FAIL] で 1 行ずつ報告します。
[FAIL] が 1 つでもあれば exit 1 を返します。

  sbomhub doctor                # 通常実行
  sbomhub doctor --verbose      # 各 HTTP レスポンス詳細も表示`,
	// We print our own status lines and own the exit code; let cobra stay out
	// of the way (no usage banner, no double-reported error).
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runDoctor,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

func runDoctor(cmd *cobra.Command, args []string) error {
	client := &http.Client{Timeout: doctorHTTPTimeout}
	return runDoctorWith(cmd.OutOrStdout(), defaultConfigDir(), client, verboseFlag)
}

// defaultConfigDir mirrors the lookup used by loadConfigAndClient in
// projects.go so `doctor` reports against the same path that real commands
// will read.
func defaultConfigDir() string {
	dir := filepath.Join(os.Getenv("HOME"), ".sbomhub")
	if os.Getenv("USERPROFILE") != "" {
		dir = filepath.Join(os.Getenv("USERPROFILE"), ".sbomhub")
	}
	return dir
}

// runDoctorWith is the testable seam: it takes an explicit config dir and HTTP
// client so unit tests can point the checks at a temp directory and an
// httptest server without touching $HOME or the real network.
func runDoctorWith(out io.Writer, configDir string, client *http.Client, verbose bool) error {
	results := doctorChecks(configDir, client)
	anyFail := false
	for _, r := range results {
		fmt.Fprintf(out, "%s %s\n", r.status, r.message)
		if verbose && r.detail != "" {
			fmt.Fprintf(out, "       %s\n", r.detail)
		}
		if r.status == doctorFail {
			anyFail = true
		}
	}
	if anyFail {
		// Returning a sentinel error makes main exit 1 (SilenceErrors above
		// suppresses cobra's own "Error: ..." line so we don't double-report).
		return fmt.Errorf("doctor: 1 つ以上の項目で [FAIL] を検出しました")
	}
	return nil
}

// doctorChecks runs every diagnostic and returns the results as a slice.
// Splitting this out from the printer keeps the unit tests free of stdout
// assertions — they just inspect the structured results.
func doctorChecks(configDir string, client *http.Client) []doctorResult {
	var results []doctorResult

	// 1. config file presence. If this fails the rest of the checks can't
	// say anything useful, so we early-return with an actionable hint.
	configPath := filepath.Join(configDir, "config.yaml")
	if _, err := os.Stat(configPath); err != nil {
		if os.IsNotExist(err) {
			return append(results, doctorResult{
				name:   "config-file",
				status: doctorFail,
				message: fmt.Sprintf("設定ファイルが見つかりません (%s) — `sbomhub login` で初期化してください",
					configPath),
			})
		}
		return append(results, doctorResult{
			name:    "config-file",
			status:  doctorFail,
			message: fmt.Sprintf("設定ファイル参照エラー (%s): %v", configPath, err),
		})
	}
	results = append(results, doctorResult{
		name:    "config-file",
		status:  doctorOK,
		message: fmt.Sprintf("設定ファイル存在 (%s)", configPath),
	})

	cfg, err := config.Load(configDir)
	if err != nil {
		// File existed but parse failed; downstream checks can't run.
		return append(results, doctorResult{
			name:    "config-parse",
			status:  doctorFail,
			message: fmt.Sprintf("設定ファイルの解析に失敗しました: %v", err),
		})
	}

	// 2. API key (prefix sanity check — the real auth probe is #5).
	switch {
	case cfg.APIKey == "":
		results = append(results, doctorResult{
			name:    "api-key",
			status:  doctorFail,
			message: "api_key が未設定です — `sbomhub login` で設定してください",
		})
	case !strings.HasPrefix(cfg.APIKey, doctorAPIKeyPrefix):
		results = append(results, doctorResult{
			name: "api-key",
			// WARN not FAIL: a non-sbh_ key may still work against a forked
			// server, and the auth-verify step below will catch real breakage.
			status:  doctorWarn,
			message: fmt.Sprintf("api_key が期待される prefix (%s) で始まっていません", doctorAPIKeyPrefix),
		})
	default:
		results = append(results, doctorResult{
			name:    "api-key",
			status:  doctorOK,
			message: fmt.Sprintf("api_key 設定済み (%s)", maskAPIKey(cfg.APIKey)),
		})
	}

	// 3. API URL — empty is fatal, SaaS default is a self-host nudge (WARN).
	switch cfg.APIURL {
	case "":
		results = append(results, doctorResult{
			name:    "api-url",
			status:  doctorFail,
			message: "api_url が未設定です — `sbomhub login --url <self-host-url>` で設定してください",
		})
	case doctorDefaultAPIURL:
		results = append(results, doctorResult{
			name:   "api-url",
			status: doctorWarn,
			message: fmt.Sprintf(
				"api_url が SaaS 既定 (%s) のままです — SaaS は 2026-06-23 sunset、 self-host への切替を推奨",
				cfg.APIURL),
		})
	default:
		results = append(results, doctorResult{
			name:    "api-url",
			status:  doctorOK,
			message: fmt.Sprintf("api_url 設定済み (%s)", cfg.APIURL),
		})
	}

	// 4. API reachability via /api/v1/health (public, no auth needed). See
	// sbomhub/apps/api/cmd/server/main.go where it is wired as the only
	// no-auth GET under the /api/v1 group.
	if cfg.APIURL != "" {
		healthURL := strings.TrimRight(cfg.APIURL, "/") + "/api/v1/health"
		status, body, err := doctorGet(client, healthURL, "")
		switch {
		case err != nil:
			results = append(results, doctorResult{
				name:    "api-reachability",
				status:  doctorFail,
				message: fmt.Sprintf("API 到達失敗 (%s): %v", healthURL, err),
			})
		case status == http.StatusOK:
			results = append(results, doctorResult{
				name:    "api-reachability",
				status:  doctorOK,
				message: fmt.Sprintf("API 到達 OK (%s)", healthURL),
				detail:  fmt.Sprintf("status=%d body=%s", status, truncateBody(body)),
			})
		case status == http.StatusUnauthorized, status == http.StatusForbidden:
			results = append(results, doctorResult{
				name:    "api-reachability",
				status:  doctorWarn,
				message: fmt.Sprintf("API は応答したが認可拒否 (status=%d) — gateway/reverse proxy の auth 設定を確認", status),
				detail:  fmt.Sprintf("url=%s body=%s", healthURL, truncateBody(body)),
			})
		default:
			results = append(results, doctorResult{
				name:    "api-reachability",
				status:  doctorWarn,
				message: fmt.Sprintf("API は応答したが想定外 status (status=%d) — server バージョンを確認", status),
				detail:  fmt.Sprintf("url=%s body=%s", healthURL, truncateBody(body)),
			})
		}
	}

	// 5. Auth verify against a tenant-scoped endpoint the CLI actually uses.
	// Successful 200 here proves the api_key resolves to a tenant and the
	// MultiAuth middleware accepts it (apps/api/internal/middleware/multiauth.go).
	if cfg.APIURL != "" && cfg.APIKey != "" {
		verifyURL := strings.TrimRight(cfg.APIURL, "/") + "/api/v1/cli/projects"
		status, body, err := doctorGet(client, verifyURL, cfg.APIKey)
		switch {
		case err != nil:
			results = append(results, doctorResult{
				name:    "auth-verify",
				status:  doctorFail,
				message: fmt.Sprintf("認証検証リクエスト失敗 (%s): %v", verifyURL, err),
			})
		case status == http.StatusOK:
			results = append(results, doctorResult{
				name:    "auth-verify",
				status:  doctorOK,
				message: fmt.Sprintf("認証 OK (%s)", verifyURL),
				detail:  fmt.Sprintf("status=%d body=%s", status, truncateBody(body)),
			})
		case status == http.StatusUnauthorized:
			results = append(results, doctorResult{
				name:    "auth-verify",
				status:  doctorFail,
				message: "認証失敗 (401) — api_key が無効・失効しています。 `sbomhub login` で再設定してください",
				detail:  fmt.Sprintf("url=%s body=%s", verifyURL, truncateBody(body)),
			})
		default:
			results = append(results, doctorResult{
				name:    "auth-verify",
				status:  doctorWarn,
				message: fmt.Sprintf("認証検証で想定外 status (status=%d)", status),
				detail:  fmt.Sprintf("url=%s body=%s", verifyURL, truncateBody(body)),
			})
		}
	}

	// 6. Scanner binaries. Missing all 3 is WARN, not FAIL: `sbomhub scan`
	// breaks but uploading an existing SBOM keeps working.
	var found, missing []string
	for _, s := range doctorScanners {
		if path, err := exec.LookPath(s); err == nil {
			found = append(found, fmt.Sprintf("%s (%s)", s, path))
		} else {
			missing = append(missing, s)
		}
	}
	switch {
	case len(found) > 0:
		results = append(results, doctorResult{
			name:    "scanners",
			status:  doctorOK,
			message: fmt.Sprintf("SBOM scanner 検出: %s", strings.Join(found, ", ")),
			detail:  fmt.Sprintf("未検出: %s", strings.Join(missing, ", ")),
		})
	default:
		results = append(results, doctorResult{
			name:   "scanners",
			status: doctorWarn,
			message: "SBOM scanner (syft / trivy / cdxgen) が 1 つも見つかりません — " +
				"`sbomhub scan` は使えません (既存 SBOM の upload は可能)",
		})
	}

	return results
}

// doctorGet performs a single bounded GET, capping body reads so a hostile or
// misconfigured upstream cannot make `doctor` hang or eat memory.
func doctorGet(client *http.Client, url, bearer string) (int, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), doctorHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, string(body), nil
}

func truncateBody(s string) string {
	s = strings.TrimSpace(s)
	const max = 200
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
