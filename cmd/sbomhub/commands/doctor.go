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
	"gopkg.in/yaml.v3"
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
	// Capture explicit-flag state here (cobra owns this knowledge); it lets
	// the source-attribution logic in doctorChecks tell flag-supplied
	// credentials apart from env / config / default fall-throughs.
	return runDoctorWith(
		cmd.OutOrStdout(),
		defaultConfigDir(),
		client,
		verboseFlag,
		cmd.Flags().Changed("api-key"),
		cmd.Flags().Changed("api-url"),
	)
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
//
// apiKeyFromFlag / apiURLFromFlag mirror cmd.Flags().Changed(...) so tests can
// exercise the flag precedence path without spinning up a cobra command tree.
func runDoctorWith(
	out io.Writer,
	configDir string,
	client *http.Client,
	verbose, apiKeyFromFlag, apiURLFromFlag bool,
) error {
	results := doctorChecks(configDir, client, apiKeyFromFlag, apiURLFromFlag)
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
//
// apiKeyFromFlag / apiURLFromFlag are the cmd.Flags().Changed(...) values for
// --api-key / --api-url. They are used only for source attribution in the
// resulting messages; the actual precedence is owned by resolveCredentials.
func doctorChecks(configDir string, client *http.Client, apiKeyFromFlag, apiURLFromFlag bool) []doctorResult {
	var results []doctorResult

	// 1. Config file presence. A missing file is NOT fatal: env vars
	// (SBOMHUB_API_URL / SBOMHUB_API_KEY) and CLI flags (--api-url /
	// --api-key) are equally valid credential sources (Trust Rescue
	// R2-2e / R9-9b: resolveCredentials is the canonical merge). Without
	// this downgrade, `SBOMHUB_API_KEY=... sbomhub doctor` in a clean CI
	// runner always [FAIL]s before reaching the real checks.
	configPath := filepath.Join(configDir, "config.yaml")
	configFileExists := false
	if _, err := os.Stat(configPath); err == nil {
		configFileExists = true
		results = append(results, doctorResult{
			name:    "config-file",
			status:  doctorOK,
			message: fmt.Sprintf("設定ファイル存在 (%s)", configPath),
		})
	} else if os.IsNotExist(err) {
		results = append(results, doctorResult{
			name:    "config-file",
			status:  doctorOK,
			message: fmt.Sprintf("設定ファイル無し (%s) — env / flag 経路で動作", configPath),
		})
	} else {
		// stat returned something other than ENOENT (permission denied,
		// I/O error, ...) — bail out, the rest is undefined.
		return append(results, doctorResult{
			name:    "config-file",
			status:  doctorFail,
			message: fmt.Sprintf("設定ファイル参照エラー (%s): %v", configPath, err),
		})
	}

	// Raw file values (no DefaultAPIURL injection) for source attribution.
	// config.Load() rewrites an empty api_url to DefaultAPIURL, which would
	// make us mislabel "default" as "config"; reading the file directly
	// preserves the distinction.
	var fileAPIURL, fileAPIKey string
	if configFileExists {
		if data, readErr := os.ReadFile(configPath); readErr == nil {
			var raw config.Config
			if yamlErr := yaml.Unmarshal(data, &raw); yamlErr != nil {
				// File exists but is malformed; downstream merges will
				// also fail. Surface the parse error and stop.
				return append(results, doctorResult{
					name:    "config-parse",
					status:  doctorFail,
					message: fmt.Sprintf("設定ファイルの解析に失敗しました: %v", yamlErr),
				})
			}
			fileAPIURL = raw.APIURL
			fileAPIKey = raw.APIKey
		}
	}

	// Resolve credentials through the same path real commands use, so
	// what doctor reports is exactly what e.g. `scan` / `projects` would
	// see (flag > env > file > default).
	cfg, err := resolveCredentials(configDir)
	if err != nil {
		return append(results, doctorResult{
			name:    "credentials",
			status:  doctorFail,
			message: fmt.Sprintf("credential 解決に失敗しました: %v", err),
		})
	}

	envKey := os.Getenv("SBOMHUB_API_KEY")
	envURL := os.Getenv("SBOMHUB_API_URL")

	// 2. API key (prefix sanity check — the real auth probe is #5).
	keySource := doctorCredSource(apiKeyFromFlag, envKey, fileAPIKey, "", cfg.APIKey)
	switch {
	case cfg.APIKey == "":
		results = append(results, doctorResult{
			name:    "api-key",
			status:  doctorFail,
			message: "api_key が未設定です — SBOMHUB_API_KEY env / --api-key flag / `sbomhub login` のいずれかが必要",
		})
	case !strings.HasPrefix(cfg.APIKey, doctorAPIKeyPrefix):
		results = append(results, doctorResult{
			name: "api-key",
			// WARN not FAIL: a non-sbh_ key may still work against a forked
			// server, and the auth-verify step below will catch real breakage.
			status:  doctorWarn,
			message: fmt.Sprintf("api_key が期待される prefix (%s) で始まっていません (source: %s)", doctorAPIKeyPrefix, keySource),
		})
	default:
		results = append(results, doctorResult{
			name:    "api-key",
			status:  doctorOK,
			message: fmt.Sprintf("api_key 設定済み (source: %s, %s)", keySource, maskAPIKey(cfg.APIKey)),
		})
	}

	// 3. API URL — empty is fatal (resolveCredentials applies a default,
	// so this is essentially unreachable), SaaS default is a self-host
	// nudge (WARN).
	urlSource := doctorCredSource(apiURLFromFlag, envURL, fileAPIURL, config.DefaultAPIURL, cfg.APIURL)
	switch cfg.APIURL {
	case "":
		results = append(results, doctorResult{
			name:    "api-url",
			status:  doctorFail,
			message: "api_url が未設定です — SBOMHUB_API_URL env / --api-url flag / `sbomhub login --url <self-host-url>` のいずれかが必要",
		})
	case doctorDefaultAPIURL:
		results = append(results, doctorResult{
			name:   "api-url",
			status: doctorWarn,
			message: fmt.Sprintf(
				"api_url が SaaS 既定 (%s) のままです — SaaS は 2026-06-23 sunset、 self-host への切替を推奨 (source: %s)",
				cfg.APIURL, urlSource),
		})
	default:
		results = append(results, doctorResult{
			name:    "api-url",
			status:  doctorOK,
			message: fmt.Sprintf("api_url 設定済み (source: %s, %s)", urlSource, cfg.APIURL),
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

// doctorCredSource reports which precedence layer ultimately supplied the
// credential, mirroring resolveCredentials (flag > env > config > default).
// defaultVal is the built-in fallback (e.g. config.DefaultAPIURL for api_url;
// empty for api_key, which has no default).
func doctorCredSource(fromFlag bool, envVal, fileVal, defaultVal, finalVal string) string {
	switch {
	case finalVal == "":
		return "none"
	case fromFlag:
		return "flag"
	case envVal != "" && envVal == finalVal:
		return "env"
	case fileVal != "" && fileVal == finalVal:
		return "config"
	case defaultVal != "" && defaultVal == finalVal:
		return "default"
	default:
		// Final value did not match any known source. This can happen when
		// the file specified a non-empty value that exactly equals the
		// default — attribute to config in that case (the file is the
		// proximate cause of the value being present).
		if fileVal != "" {
			return "config"
		}
		return "unknown"
	}
}

func truncateBody(s string) string {
	s = strings.TrimSpace(s)
	const max = 200
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
