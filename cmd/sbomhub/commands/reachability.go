package commands

// `sbomhub reachability <path> --project <id>` — M32 Wave D (P4);
// npm ecosystem wired in M44 Wave 4 (F472).
//
// Runs the reachability analyzers (Go + npm) against a LOCAL source tree
// CLIENT-SIDE and uploads only the per-(component, cve) verdicts to the
// backend. The backend never sees the source (privacy): the analyzers
// walk the user's go.mod / package.json / source tree here, and only the
// compact verdicts (status + confidence + evidence pointers) leave the
// machine.
//
// Flow per invocation:
//
//  1. resolve credentials (config file → env → CLI flag, same precedence
//     as `sbomhub scan` / `sbomhub triage`),
//  2. GET /api/v1/projects/:id/reachability/targets — the server joins
//     component_vulnerabilities and returns one (cve_id, component_id,
//     purl, ecosystem) tuple per affected component. With the default
//     --ecosystem=all the fetch is UNFILTERED (the M32 no-?ecosystem=
//     behavior: every ecosystem in one call) and the CLI dispatches per
//     row; an explicit --ecosystem=go|npm forwards the server-side
//     ?ecosystem= filter instead,
//  3. for each target, derive a package coordinate from its purl (Go
//     module path or npm package name, dispatched on the row's ecosystem)
//     and run the matching vendored analyzer against <path> — "go" →
//     GoAnalyzer, "npm" → NpmAnalyzer (M44 Wave 1); rows in ecosystems
//     with no analyzer are skipped and counted on stderr,
//  4. POST the verdicts to /api/v1/projects/:id/reachability (the POST
//     contract is ecosystem-agnostic; the row's ecosystem token is
//     forwarded verbatim).
//
// GRANULARITY (M43, issue #168; npm arm M44): the targets endpoint
// publishes the server-normalized vulnerable symbols per (cve, component)
// row as `vuln_funcs` — "Pkg.Func" / "Pkg.Type.Method" for Go rows,
// npm-form selectors (bare export names like "defaultsDeep",
// "recv.method", "a.b.c") for npm rows. When present they are forwarded
// verbatim into the analyzer's VulnerableSymbols — modulo a
// defense-in-depth shape filter (isWellFormedSymbolSelector /
// isWellFormedNpmSymbolSelector, dispatched on the work item's ecosystem)
// that drops malformed entries so one bad selector cannot fail the whole
// symbol walk, and a per-work-item cap (maxVulnFuncsPerItem, mirroring
// the server's serving-edge cap) so a non-conforming server cannot
// inflate the walk — enabling symbol-level `reachable` verdicts (Go: AST
// symbol walk; npm: binding-aware source scan). When absent or empty —
// pre-M43 server, or an advisory with no symbol data — the analyzer stops
// at the import stage and the coarsest verdict a matched package can
// reach stays `import_only` (graceful degrade, the M32 behavior).
//
// A target whose purl is empty (component has no package URL) or does not
// parse under its ecosystem's derivation cannot yield a package
// coordinate; the command skips it and reports the count on stderr.
// component_id always comes from the server, so no uploadable verdict is
// dropped for want of a component id.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

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

Runs the Go and npm reachability analyzers against a LOCAL source tree
client-side and uploads ONLY the per-(component, cve) verdicts. The
source never leaves your machine.

使用例 / Examples:
  sbomhub reachability . --project <uuid>
  sbomhub reachability ./src --project <uuid> --ecosystem go
  sbomhub reachability ./web --project <uuid> --ecosystem npm
  sbomhub reachability . --project <uuid> --cve CVE-2024-12345

フロー / Flow:
  1. プロジェクトの脆弱性 (+ 影響コンポーネント) を取得
     Fetch the project's vulnerabilities (+ affected components)
  2. 各コンポーネントの座標 (Go module / npm package) を purl から導出
     Derive each component's coordinate (Go module / npm package) from its purl
  3. ローカルソースを ecosystem 別の analyzer で解析
     Analyze the local source with the ecosystem's analyzer
     (Go: go.mod + AST / npm: package.json + lockfile + source scan)
  4. 判定を POST /api/v1/projects/:id/reachability でアップロード
     Upload the verdicts

粒度 / Granularity (M43; npm 対応 M44):
  サーバーがターゲットに vuln_funcs (脆弱シンボル) を公開している場合は
  symbol レベルの reachable まで判定します — Go は "Pkg.Func" /
  "Pkg.Type.Method" 形、 npm は bare export 名 ("defaultsDeep") や
  "recv.method" 形。 vuln_funcs が無い場合は従来どおり最大 import_only
  です (旧サーバーでも動作)。
  Targets carrying vuln_funcs are analyzed to symbol-level reachable —
  Go selectors are "Pkg.Func" / "Pkg.Type.Method", npm selectors are
  bare export names ("defaultsDeep") or "recv.method" forms; without
  symbols a matched package still reaches at most import_only (graceful
  degrade against older servers).`,
	Args: cobra.ExactArgs(1),
	RunE: runReachability,
}

func init() {
	rootCmd.AddCommand(reachabilityCmd)

	reachabilityCmd.Flags().StringVarP(&reachProject, "project", "p", "", "対象プロジェクトの UUID / project UUID (必須) — server accepts a UUID only, not a name")
	reachabilityCmd.Flags().StringVar(&reachEcosystem, "ecosystem", "all", "対象エコシステム / target ecosystem: go, npm, all (default: 全対応 ecosystem を解析 / analyze every supported ecosystem)")
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
	if ecosystem == "" {
		ecosystem = "all"
	}
	switch ecosystem {
	case "go", "npm", "all":
	default:
		return fmt.Errorf("--ecosystem=%q は未対応です。 go / npm / all を指定してください / unsupported --ecosystem %q (supported: go, npm, all)", reachEcosystem, reachEcosystem)
	}

	// Resolve + validate the source path. Unlike `triage`, path is the
	// actual analysis root — it must exist and (for a useful result)
	// contain the scoped ecosystem's manifest (go.mod / package.json). A
	// missing manifest is not fatal (the analyzer downgrades to `unknown`),
	// but we warn so the operator is not surprised by an all-unknown run.
	absPath, err := filepath.Abs(args[0])
	if err != nil {
		return fmt.Errorf("パスの解決に失敗しました: %w", err)
	}
	info, err := os.Stat(absPath)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("解析対象ディレクトリが存在しません: %s", absPath)
	}
	hasManifest := func(name string) bool {
		_, err := os.Stat(filepath.Join(absPath, name))
		return err == nil
	}
	switch {
	case ecosystem == "go" && !hasManifest("go.mod"):
		fmt.Fprintf(out.ErrWriter, "警告: %s に go.mod が見つかりません。 判定は unknown になる可能性があります。\n", absPath)
		fmt.Fprintf(out.ErrWriter, "warning: no go.mod under %s; verdicts may be `unknown`.\n", absPath)
	case ecosystem == "npm" && !hasManifest("package.json"):
		fmt.Fprintf(out.ErrWriter, "警告: %s に package.json が見つかりません。 判定は unknown になる可能性があります。\n", absPath)
		fmt.Fprintf(out.ErrWriter, "warning: no package.json under %s; verdicts may be `unknown`.\n", absPath)
	case ecosystem == "all" && !hasManifest("go.mod") && !hasManifest("package.json"):
		fmt.Fprintf(out.ErrWriter, "警告: %s に go.mod も package.json も見つかりません。 判定は unknown になる可能性があります。\n", absPath)
		fmt.Fprintf(out.ErrWriter, "warning: neither go.mod nor package.json under %s; verdicts may be `unknown`.\n", absPath)
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
		analyzers: map[string]reachAnalyzer{
			"go":  &reachability.GoAnalyzer{},
			"npm": &reachability.NpmAnalyzer{},
		},
		stdout: out.humanWriter(),
		stderr: out.ErrWriter,
	})
}

// reachAnalyzer is the analyzer surface runReachabilityAnalysis depends
// on. *reachability.GoAnalyzer and *reachability.NpmAnalyzer satisfy it;
// the command test injects them directly (real analyzers against fixture
// paths — no mock).
type reachAnalyzer interface {
	Analyze(ctx context.Context, projectPath string, input reachability.ReachabilityInput) (*reachability.ReachabilityResult, error)
}

// reachOpts groups the parameters for the testable entrypoint so the test
// constructs a single struct rather than threading a long argument list.
type reachOpts struct {
	projectID string
	// ecosystem is the validated --ecosystem value: "go" / "npm" forward
	// the server-side ?ecosystem= filter; "all" fetches unfiltered (every
	// ecosystem in one call, the M32 no-param behavior) and dispatches per
	// row.
	ecosystem string
	cve       string
	path      string
	// analyzers maps a lowercase ecosystem token to its analyzer ("go" →
	// GoAnalyzer, "npm" → NpmAnalyzer). Targets whose ecosystem has no
	// entry are skipped and counted on stderr.
	analyzers map[string]reachAnalyzer
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
	// ecosystem is the target row's token forwarded verbatim onto the
	// uploaded verdict ("" defaulted to "go", the M32 behavior).
	ecosystem string
	// analyzerKey is the lowercase dispatch token into reachOpts.analyzers
	// (and the ecosystem-shape key for the vuln_funcs filter). The server
	// always lowercases the wire token, so in practice it equals
	// ecosystem; the normalization is defense-in-depth.
	analyzerKey string
	symbols     []string // nil when the server published no vuln_funcs
}

// maxVulnFuncsPerItem caps the union of server-published vuln_funcs a
// single work item forwards to the analyzer (M43 Phase D round 2 review).
// Mirrors the server's serving-edge cap — maxVulnFuncsPerCVE = 200 in
// sbomhub apps/api/internal/handler/reachability.go, keep the two values
// in sync. A conforming server never exceeds it, so this only bites
// against a drifted / hostile / non-conforming server shipping thousands
// of well-formed selectors, which would otherwise inflate the AST symbol
// walk and the merge itself. Elements past the cap are dropped,
// preserving first-seen order (first wins).
const maxVulnFuncsPerItem = 200

// mergeVulnFuncs appends the server-published vuln_funcs in add onto dst,
// dropping blank entries, malformed shapes (the shape rule dispatches on
// ecosystem — isWellFormedSymbolSelector for Go rows,
// isWellFormedNpmSymbolSelector for npm rows; unknown ecosystems keep the
// conservative Go rule, mirroring the server's
// normalizeVulnFuncsForEcosystem default arm), and exact duplicates while
// preserving first-seen order, and capping the surviving union at
// maxVulnFuncsPerItem (elements past the cap are dropped, first wins —
// duplicates and malformed entries never consume cap budget). The
// surviving symbol strings are forwarded in their TrimSpace'd form and
// otherwise verbatim — the server owns normalization (frozen M43
// contract; npm arm M44 Wave 3) and the CLI never rewrites a selector's
// content; it only drops shapes the analyzer would reject outright.
// Append and dedupe both operate on the trimmed form so whitespace
// variants of one selector cannot slip past dedupe and consume cap budget
// (M43 Phase D R9 finding 3).
// The linear-scan dedupe is O(n²) in the survivor count,
// which the cap bounds at n ≤ maxVulnFuncsPerItem (= 200) — fine as is,
// no map needed. Returns nil when nothing survives, so the result can be
// handed straight to ReachabilityInput.VulnerableSymbols (len==0 → stage
// 1 only).
func mergeVulnFuncs(dst, add []string, ecosystem string) []string {
	wellFormed := isWellFormedSymbolSelector
	if ecosystem == "npm" {
		wellFormed = isWellFormedNpmSymbolSelector
	}
	for _, s := range add {
		if len(dst) >= maxVulnFuncsPerItem {
			break
		}
		trimmed := strings.TrimSpace(s)
		if trimmed == "" || !wellFormed(trimmed) {
			continue
		}
		dup := false
		for _, have := range dst {
			if have == trimmed {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, trimmed)
		}
	}
	return dst
}

// isWellFormedSymbolSelector reports whether a (TrimSpace'd, non-empty)
// vuln_func has the "Pkg.Func" / "Pkg.Type.Method" shape: 2..3
// dot-separated parts, each part shaped like a Go identifier (first rune
// a unicode letter or '_', remaining runes letters, digits, or '_').
//
// Defense-in-depth (M43 Phase D review). The server normalizer remains
// the single source of truth for symbol normalization (frozen M43
// contract) — this filter never rewrites a value, it only drops shapes
// that would be fatal to the analyzer. It mirrors the acceptance set of
// the vendored analyzer's parseSymbolSelectors
// (internal/reachability/go_analyzer.go), which returns an error when any
// single selector is malformed — downgrading the WHOLE work item to
// import_only + analyzer_error and losing every legitimate symbol
// alongside the bad one (server drift / non-conforming server). The
// identifier-shape requirement is a conservative subset of what
// parseSymbolSelectors tolerates: a part that is not identifier-shaped
// (e.g. "baz()") can never match an *ast.Ident name in the symbol walk,
// so dropping it loses no reachability signal.
func isWellFormedSymbolSelector(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return false
	}
	for _, p := range parts {
		if !isGoIdentifierShaped(p) {
			return false
		}
	}
	return true
}

// isGoIdentifierShaped reports whether s looks like a Go identifier:
// non-empty, first rune a unicode letter or '_', remaining runes unicode
// letters, unicode digits, or '_'.
func isGoIdentifierShaped(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r == '_' || unicode.IsLetter(r) {
			continue
		}
		if i > 0 && unicode.IsDigit(r) {
			continue
		}
		return false
	}
	return true
}

// maxNpmVulnFuncBytes bounds one npm vuln_funcs selector. LOCKSTEP with
// the server's maxNpmVulnFuncBytes (sbomhub
// apps/api/internal/handler/reachability.go, M44 Wave 3 / F471) — real npm
// export names and recv.method selectors run well under 100 bytes;
// anything longer is minifier output or a prose fragment the extraction
// heuristics let through.
const maxNpmVulnFuncBytes = 256

// isWellFormedNpmSymbolSelector reports whether a (TrimSpace'd, non-empty)
// vuln_func has the npm selector shape: 1..3 dot-separated parts — npm
// advisories overwhelmingly name BARE export identifiers ("defaultsDeep"),
// a 1-part shape the Go rule rejects — each part shaped like a JavaScript
// identifier ('$' and '_' are legal JS identifier runes), total length ≤
// maxNpmVulnFuncBytes.
//
// Defense-in-depth (M44 Wave 4 / F472), the npm counterpart of
// isWellFormedSymbolSelector. LOCKSTEP: the acceptance rule mirrors the
// server's isNpmVulnFuncSelector (sbomhub
// apps/api/internal/handler/reachability.go, M44 Wave 3 / F471) — the
// serving edge is the single source of truth for normalization and this
// filter never rewrites a value (in particular it does NOT strip a
// trailing "()" the way the server's normalizeVulnFuncsShaped does before
// shape-checking; a "()" variant reaching this filter is server drift and
// is dropped, not repaired). Unlike the Go analyzer's fatal
// parseSymbolSelectors, the vendored npm analyzer already skips malformed
// selectors INDIVIDUALLY (parseNpmSymbolSelectors, never fatal), so this
// filter is not load-bearing for verdict integrity — it exists to keep a
// drifted/hostile server's junk from consuming the per-item cap budget
// and to keep the two ecosystems' shape rules symmetric. The shape check
// is deliberately FORM-ONLY, mirroring the server: a form-valid but
// semantically generic token ("headers.location") passes; the analyzer's
// binding-aware matching owns precision.
func isWellFormedNpmSymbolSelector(s string) bool {
	if len(s) > maxNpmVulnFuncBytes {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return false
	}
	for _, p := range parts {
		if !isJSIdentifierShaped(p) {
			return false
		}
	}
	return true
}

// isJSIdentifierShaped reports whether s is shaped like a JavaScript
// identifier: non-empty, first rune a unicode letter, '_' or '$',
// remaining runes may add unicode digits — the conservative core of the
// ECMAScript IdentifierName grammar, a strict superset of
// isGoIdentifierShaped ('$' is the only addition). LOCKSTEP with the
// server's isJSIdentifier (sbomhub
// apps/api/internal/handler/reachability.go, M44 Wave 3 / F471).
func isJSIdentifierShaped(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r == '_' || r == '$' || unicode.IsLetter(r) {
			continue
		}
		if i > 0 && unicode.IsDigit(r) {
			continue
		}
		return false
	}
	return true
}

// runReachabilityAnalysis is the testable core. It fetches the project's
// reachability targets (one (cve, component) pair each, with a real
// component_id + purl + ecosystem from the server), derives a package
// coordinate per target (Go module / npm package, by ecosystem), runs the
// ecosystem's analyzer once per item, and uploads the verdicts.
func runReachabilityAnalysis(ctx context.Context, client *api.Client, opts reachOpts) error {
	// "all" (the default) fetches WITHOUT the ?ecosystem= filter — the
	// M32-era servers already served every ecosystem on the unfiltered
	// call (the parameter has always been an optional filter), so one
	// round-trip covers go + npm and lets the CLI count the rows it has no
	// analyzer for (a filtered fetch per ecosystem would never see them).
	fetchEcosystem := opts.ecosystem
	if fetchEcosystem == "all" {
		fetchEcosystem = ""
	}
	targets, err := client.GetReachabilityTargets(ctx, opts.projectID, fetchEcosystem)
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
	// server now; the skip reasons are a target in an ecosystem with no
	// analyzer, and a target with no derivable package coordinate (empty /
	// underivable purl).
	var (
		items            []reachWorkItem
		itemIndex        = map[string]int{} // dedupe key → index into items
		droppedNoModule  int                // no derivable package coordinate (empty/underivable purl)
		droppedEcosystem int                // ecosystem has no analyzer (e.g. maven, pypi)
	)
	for _, tgt := range targets {
		if tgt.ComponentID == "" {
			// Contract says component_id is always present; guard defensively.
			droppedNoModule++
			continue
		}
		// Dispatch token: the server lowercases the wire ecosystem
		// (repository.EcosystemFromPurl); "" — purl-less rows, and every
		// pre-ecosystem M32 row — stays on the Go arm, matching
		// ReachabilityTarget.ModulePath and the pre-M44 behavior.
		analyzerKey := strings.ToLower(tgt.Ecosystem)
		if analyzerKey == "" {
			analyzerKey = "go"
		}
		if _, ok := opts.analyzers[analyzerKey]; !ok {
			droppedEcosystem++
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
			// union their vuln_funcs (order-preserving dedupe) so the
			// symbol stage sees every published symbol. The row's
			// ecosystem cannot differ from the merged item's (same
			// component → same purl → same derived ecosystem), so the
			// item's shape rule applies.
			items[idx].symbols = mergeVulnFuncs(items[idx].symbols, tgt.VulnFuncs, items[idx].analyzerKey)
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
			analyzerKey: analyzerKey,
			symbols:     mergeVulnFuncs(nil, tgt.VulnFuncs, analyzerKey),
		})
	}

	if droppedNoModule > 0 {
		fmt.Fprintf(opts.stderr, "注意: %d 件のターゲットは purl からパッケージ座標 (Go module / npm package) を導出できずスキップしました。\n", droppedNoModule)
		fmt.Fprintf(opts.stderr, "note: skipped %d targets whose purl yielded no package coordinate (empty or underivable purl).\n", droppedNoModule)
	}
	if droppedEcosystem > 0 {
		fmt.Fprintf(opts.stderr, "注意: %d 件のターゲットは未対応 ecosystem のためスキップしました (対応: go, npm)。\n", droppedEcosystem)
		fmt.Fprintf(opts.stderr, "note: skipped %d targets in unsupported ecosystems (supported: go, npm).\n", droppedEcosystem)
	}

	if len(items) == 0 {
		fmt.Fprintln(opts.stdout, "アップロード可能な到達性判定がありませんでした。")
		fmt.Fprintln(opts.stdout, "No uploadable reachability verdicts were produced.")
		return nil
	}

	// Analyze each item with its ecosystem's analyzer and build the upload
	// payload.
	results := make([]api.ReachabilityUploadResult, 0, len(items))
	statusCounts := map[string]int{}
	for _, it := range items {
		// Presence was checked at work-item build; a missing entry here is
		// unreachable.
		analyzer := opts.analyzers[it.analyzerKey]
		res, err := analyzer.Analyze(ctx, opts.path, reachability.ReachabilityInput{
			AdvisoryID:        it.cveID,
			Ecosystem:         it.analyzerKey,
			VulnerableModules: []string{it.module},
			// M43: server-published vuln_funcs (unioned across duplicate
			// target rows) drive the symbol stage (Go: AST walk; npm:
			// binding-aware source scan). nil/empty — old server or no
			// symbol data — keeps the analyzer at the import stage =
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
