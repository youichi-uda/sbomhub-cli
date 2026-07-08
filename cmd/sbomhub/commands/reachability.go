package commands

// `sbomhub reachability <path> --project <id>` — M32 Wave D (P4).
//
// Runs the Go reachability analyzer against a LOCAL source tree
// CLIENT-SIDE and uploads only the per-(component, cve) verdicts to the
// backend. The backend never sees the source (privacy): the analyzer
// walks the user's go.mod / source tree here, and only the compact
// verdicts (status + confidence + evidence pointers) leave the machine.
//
// Flow per invocation:
//
//  1. resolve credentials (config file → env → CLI flag, same precedence
//     as `sbomhub scan` / `sbomhub triage`),
//  2. GET /api/v1/projects/:id/reachability/targets?ecosystem=go — the
//     server joins component_vulnerabilities and returns one (cve_id,
//     component_id, purl) tuple per affected component,
//  3. for each target, derive a Go module coordinate from its purl and run
//     the vendored two-stage analyzer against <path>,
//  4. POST the verdicts to /api/v1/projects/:id/reachability.
//
// GRANULARITY (M43, issue #168): the targets endpoint publishes the
// server-normalized vulnerable symbols per (cve, component) row as
// `vuln_funcs` ("Pkg.Func" / "Pkg.Type.Method"). When present they are
// forwarded verbatim into the analyzer's VulnerableSymbols, enabling
// stage 2 (AST symbol walk) and symbol-level `reachable` verdicts. When
// absent or empty — pre-M43 server, or an advisory with no symbol data —
// the analyzer stops at stage 1 and the coarsest verdict a matched module
// can reach stays `import_only` (graceful degrade, the M32 behavior).
//
// A target whose purl is empty (component has no package URL) cannot yield
// a module coordinate; the command skips it and reports the count on
// stderr. component_id always comes from the server, so no uploadable
// verdict is dropped for want of a component id.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/youichi-uda/sbomhub-cli/internal/api"
	"github.com/youichi-uda/sbomhub-cli/internal/reachability"
)

var (
	reachProject   string
	reachEcosystem string
	reachCVE       string
)

var reachabilityCmd = &cobra.Command{
	Use:   "reachability <path>",
	Short: "ローカルソースを静的解析し到達性判定をアップロード / analyze a local source tree for reachability and upload the verdicts",
	Long: `ローカルのソースツリーに対して到達性 (reachability) の静的解析を
クライアント側で実行し、 判定結果のみをバックエンドにアップロードします。
ソースコードはアップロードされません (privacy)。

Runs the Go reachability analyzer against a LOCAL source tree
client-side and uploads ONLY the per-(component, cve) verdicts. The
source never leaves your machine.

使用例 / Examples:
  sbomhub reachability . --project <uuid>
  sbomhub reachability ./src --project <uuid> --ecosystem go
  sbomhub reachability . --project <uuid> --cve CVE-2024-12345

フロー / Flow:
  1. プロジェクトの脆弱性 (+ 影響コンポーネント) を取得
     Fetch the project's vulnerabilities (+ affected components)
  2. 各コンポーネントの Go module 座標を purl から導出
     Derive each component's Go module coordinate from its purl
  3. ローカルソースを解析 (import 有無 → not_present / import_only)
     Analyze the local source (module presence → not_present / import_only)
  4. 判定を POST /api/v1/projects/:id/reachability でアップロード
     Upload the verdicts

粒度 / Granularity (M43):
  サーバーがターゲットに vuln_funcs (脆弱シンボル) を公開している場合は
  symbol レベルの reachable まで判定します。 vuln_funcs が無い場合は
  従来どおり最大 import_only です (旧サーバーでも動作)。
  Targets carrying vuln_funcs are analyzed to symbol-level reachable;
  without symbols a matched module still reaches at most import_only
  (graceful degrade against older servers).`,
	Args: cobra.ExactArgs(1),
	RunE: runReachability,
}

func init() {
	rootCmd.AddCommand(reachabilityCmd)

	reachabilityCmd.Flags().StringVarP(&reachProject, "project", "p", "", "対象プロジェクトの UUID / project UUID (必須) — server accepts a UUID only, not a name")
	reachabilityCmd.Flags().StringVar(&reachEcosystem, "ecosystem", "go", "対象エコシステム / target ecosystem (M32: go のみサポート / only `go` is supported)")
	reachabilityCmd.Flags().StringVar(&reachCVE, "cve", "", "特定の CVE に絞り込む / scope analysis to a single CVE ID")
}

// runReachability is the cobra entrypoint. Kept thin: input validation +
// credential wiring + delegating to runReachabilityAnalysis, which takes
// an injected *api.Client + analyzer + writers so the test does not need
// to shell out cobra or resolve real credentials.
func runReachability(cmd *cobra.Command, args []string) error {
	out := GetOutputConfig()

	if strings.TrimSpace(reachProject) == "" {
		return fmt.Errorf("--project は必須です / --project is required")
	}

	ecosystem := strings.ToLower(strings.TrimSpace(reachEcosystem))
	if ecosystem != "go" {
		fmt.Fprintf(out.ErrWriter, "警告: --ecosystem=%q は M32 では未対応です。 go として解析します。\n", reachEcosystem)
		fmt.Fprintf(out.ErrWriter, "warning: --ecosystem=%q is unsupported in M32; analyzing as `go`.\n", reachEcosystem)
		ecosystem = "go"
	}

	// Resolve + validate the source path. Unlike `triage`, path is the
	// actual analysis root — it must exist and (for a useful result)
	// contain a go.mod. A missing go.mod is not fatal (the analyzer
	// downgrades to `unknown`), but we warn so the operator is not
	// surprised by an all-unknown run.
	absPath, err := filepath.Abs(args[0])
	if err != nil {
		return fmt.Errorf("パスの解決に失敗しました: %w", err)
	}
	info, err := os.Stat(absPath)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("解析対象ディレクトリが存在しません: %s", absPath)
	}
	if _, err := os.Stat(filepath.Join(absPath, "go.mod")); os.IsNotExist(err) {
		fmt.Fprintf(out.ErrWriter, "警告: %s に go.mod が見つかりません。 判定は unknown になる可能性があります。\n", absPath)
		fmt.Fprintf(out.ErrWriter, "warning: no go.mod under %s; verdicts may be `unknown`.\n", absPath)
	}

	cfg, err := resolveCredentials(getConfigDir())
	if err != nil {
		return fmt.Errorf("設定の読み込みに失敗しました: %w", err)
	}
	if cfg.APIKey == "" {
		return fmt.Errorf("API Keyが設定されていません。 'sbomhub login' で対話設定するか、 --api-key フラグ・ 環境変数 SBOMHUB_API_KEY を指定してください")
	}
	if cfg.APIURL == "" {
		return fmt.Errorf("API URLが設定されていません。 'sbomhub login' で設定するか、 --api-url フラグ・ 環境変数 SBOMHUB_API_URL を指定してください")
	}

	client := api.NewClient(cfg.APIURL, cfg.APIKey)

	return runReachabilityAnalysis(cmd.Context(), client, reachOpts{
		projectID: reachProject,
		ecosystem: ecosystem,
		cve:       strings.TrimSpace(reachCVE),
		path:      absPath,
		analyzer:  &reachability.GoAnalyzer{},
		stdout:    out.humanWriter(),
		stderr:    out.ErrWriter,
	})
}

// reachAnalyzer is the analyzer surface runReachabilityAnalysis depends
// on. *reachability.GoAnalyzer satisfies it; the command test injects it
// directly (a real GoAnalyzer against a fixture path — no mock).
type reachAnalyzer interface {
	Analyze(ctx context.Context, projectPath string, input reachability.ReachabilityInput) (*reachability.ReachabilityResult, error)
}

// reachOpts groups the parameters for the testable entrypoint so the test
// constructs a single struct rather than threading a long argument list.
type reachOpts struct {
	projectID string
	ecosystem string
	cve       string
	path      string
	analyzer  reachAnalyzer
	stdout    io.Writer
	stderr    io.Writer
}

// reachWorkItem is one (component, cve, module) triple to analyze, plus
// the union of the server-published vulnerable symbols (vuln_funcs) from
// every target row that deduplicated onto it.
type reachWorkItem struct {
	componentID string
	cveID       string
	module      string
	ecosystem   string
	symbols     []string // nil when the server published no vuln_funcs
}

// mergeVulnFuncs appends the server-published vuln_funcs in add onto dst,
// dropping blank entries and exact duplicates while preserving first-seen
// order. The surviving symbol strings are forwarded verbatim — the server
// owns normalization ("Pkg.Func" / "Pkg.Type.Method", frozen M43
// contract) and the CLI does not re-sanitize. Returns nil when nothing
// survives, so the result can be handed straight to
// ReachabilityInput.VulnerableSymbols (len==0 → stage 1 only).
func mergeVulnFuncs(dst, add []string) []string {
	for _, s := range add {
		if strings.TrimSpace(s) == "" {
			continue
		}
		dup := false
		for _, have := range dst {
			if have == s {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, s)
		}
	}
	return dst
}

// runReachabilityAnalysis is the testable core. It fetches the project's
// reachability targets (one (cve, component) pair each, with a real
// component_id + purl from the server), derives a Go module coordinate per
// target, runs the analyzer once per item, and uploads the verdicts.
func runReachabilityAnalysis(ctx context.Context, client *api.Client, opts reachOpts) error {
	targets, err := client.GetReachabilityTargets(ctx, opts.projectID, opts.ecosystem)
	if err != nil {
		return fmt.Errorf("reachability targets の取得に失敗しました: %w", err)
	}

	// Optional --cve scoping (exact match on the CVE identifier).
	if opts.cve != "" {
		filtered := targets[:0:0]
		for _, tgt := range targets {
			if strings.EqualFold(tgt.CVEID, opts.cve) {
				filtered = append(filtered, tgt)
			}
		}
		targets = filtered
	}

	if len(targets) == 0 {
		fmt.Fprintln(opts.stdout, "対象の脆弱性がありません。 何もすることがありません。")
		fmt.Fprintln(opts.stdout, "No matching reachability targets. Nothing to analyze.")
		return nil
	}

	// Build deduplicated work items. component_id always comes from the
	// server now; the only skip reason is a target with no derivable module
	// coordinate (empty / non-golang purl).
	var (
		items           []reachWorkItem
		itemIndex       = map[string]int{} // dedupe key → index into items
		droppedNoModule int                // target had no derivable Go module (empty/non-go purl)
	)
	for _, tgt := range targets {
		if tgt.ComponentID == "" {
			// Contract says component_id is always present; guard defensively.
			droppedNoModule++
			continue
		}
		module, ok := tgt.ModulePath()
		if !ok {
			droppedNoModule++
			continue
		}
		key := tgt.ComponentID + "\x00" + tgt.CVEID
		if idx, dup := itemIndex[key]; dup {
			// The same (component, cve) can appear on several target rows;
			// union their vuln_funcs (order-preserving dedupe) so stage 2
			// sees every published symbol.
			items[idx].symbols = mergeVulnFuncs(items[idx].symbols, tgt.VulnFuncs)
			continue
		}
		ecosystem := tgt.Ecosystem
		if ecosystem == "" {
			ecosystem = "go"
		}
		itemIndex[key] = len(items)
		items = append(items, reachWorkItem{
			componentID: tgt.ComponentID,
			cveID:       tgt.CVEID,
			module:      module,
			ecosystem:   ecosystem,
			symbols:     mergeVulnFuncs(nil, tgt.VulnFuncs),
		})
	}

	if droppedNoModule > 0 {
		fmt.Fprintf(opts.stderr, "注意: %d 件のターゲットは purl から Go module 座標を導出できずスキップしました。\n", droppedNoModule)
		fmt.Fprintf(opts.stderr, "note: skipped %d targets whose purl yielded no Go module coordinate (empty or non-go purl).\n", droppedNoModule)
	}

	if len(items) == 0 {
		fmt.Fprintln(opts.stdout, "アップロード可能な到達性判定がありませんでした。")
		fmt.Fprintln(opts.stdout, "No uploadable reachability verdicts were produced.")
		return nil
	}

	// Analyze each item and build the upload payload.
	results := make([]api.ReachabilityUploadResult, 0, len(items))
	statusCounts := map[string]int{}
	for _, it := range items {
		res, err := opts.analyzer.Analyze(ctx, opts.path, reachability.ReachabilityInput{
			AdvisoryID:        it.cveID,
			Ecosystem:         "go",
			VulnerableModules: []string{it.module},
			// M43: server-published vuln_funcs (unioned across duplicate
			// target rows) drive stage 2 (symbol walk). nil/empty — old
			// server or no symbol data — keeps the analyzer at stage 1 =
			// import_only granularity (pre-M43 behavior).
			VulnerableSymbols: it.symbols,
		})
		if err != nil {
			// The analyzer only errors on nil / cancelled context or an
			// OS-level failure — treat as fatal (retrying the same input
			// will not help).
			return fmt.Errorf("解析に失敗しました (component=%s cve=%s): %w", it.componentID, it.cveID, err)
		}

		var evidence json.RawMessage
		if len(res.Evidence) > 0 {
			if b, mErr := json.Marshal(res.Evidence); mErr == nil {
				evidence = b
			}
		}
		results = append(results, api.ReachabilityUploadResult{
			ComponentID:     it.componentID,
			CVEID:           it.cveID,
			Ecosystem:       it.ecosystem,
			Status:          string(res.Status),
			Confidence:      res.Confidence,
			AnalyzerVersion: res.AnalyzerName,
			AnalyzedAt:      res.AnalyzedAt,
			Evidence:        evidence,
		})
		statusCounts[string(res.Status)]++
	}

	if err := client.UploadReachability(ctx, opts.projectID, results); err != nil {
		return fmt.Errorf("到達性判定のアップロードに失敗しました: %w", err)
	}

	printReachabilitySummary(opts.stdout, len(items), statusCounts, len(results))
	return nil
}

// printReachabilitySummary writes the human summary: components analyzed,
// the status breakdown (stable order), and the uploaded count.
func printReachabilitySummary(w io.Writer, analyzed int, statusCounts map[string]int, uploaded int) {
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Reachability 結果 / Reachability summary")
	fmt.Fprintln(w, "----------------------------------------")
	fmt.Fprintf(w, "  解析済 (component×cve) / analyzed : %d\n", analyzed)

	// Stable ordering for deterministic output + test golden.
	order := []string{
		string(reachability.StatusReachable),
		string(reachability.StatusImportOnly),
		string(reachability.StatusNotPresent),
		string(reachability.StatusUnknown),
	}
	printed := map[string]bool{}
	for _, s := range order {
		if n, ok := statusCounts[s]; ok {
			fmt.Fprintf(w, "  %-12s : %d\n", s, n)
			printed[s] = true
		}
	}
	// Surface any status not in the known set (forward compatibility).
	var extra []string
	for s := range statusCounts {
		if !printed[s] {
			extra = append(extra, s)
		}
	}
	sort.Strings(extra)
	for _, s := range extra {
		fmt.Fprintf(w, "  %-12s : %d\n", s, statusCounts[s])
	}

	fmt.Fprintf(w, "  アップロード / uploaded : %d\n", uploaded)
}
