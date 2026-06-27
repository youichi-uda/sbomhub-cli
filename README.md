# SBOMHub CLI

[![日本語](https://img.shields.io/badge/lang-日本語-red.svg)](./README.md) [![English](https://img.shields.io/badge/lang-English-blue.svg)](./README_en.md)

![License](https://img.shields.io/badge/license-MIT-green)
![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8)

SBOMHub CLI: SBOM 生成からアップロード、 将来は CRA 提出向け VEX エクスポート / CRA レポート下書きまで、 1 コマンドで CRA 2026/9 期限対応を進めるためのコマンドラインツール。 Syft/Trivy/cdxgen 等の SBOM 生成ツールをラップし、 self-host 版 SBOMHub と組み合わせて利用する。

## Supported Formats

- CycloneDX 1.4, 1.5, 1.6
- SPDX 2.2, 2.3

## インストール

### Homebrew (macOS/Linux)

```bash
brew tap youichi-uda/sbomhub https://github.com/youichi-uda/homebrew-sbomhub
brew install sbomhub
```

### Shell script

```bash
curl -fsSL https://sbomhub.app/install.sh | sh
```

### Go install

```bash
go install github.com/youichi-uda/sbomhub-cli/cmd/sbomhub@latest
```

### Windows (Scoop)

```bash
scoop bucket add sbomhub https://github.com/youichi-uda/scoop-sbomhub
scoop install sbomhub
```

## 使い方

### 初期設定

```bash
# 推奨: self-host SBOMHub に接続 (対話式に API Key と API URL を入力)
sbomhub login
#   API Key: sbh_xxxxx
#   API URL [https://api.sbomhub.app]: http://localhost:8080
# → 入力内容を ~/.sbomhub/config.yaml に保存

# 非対話 (CI 等) ではグローバルフラグまたは環境変数で渡せる:
#   sbomhub --api-url http://localhost:8080 --api-key sbh_xxxxx scan .
#   SBOMHUB_API_KEY=sbh_xxxxx sbomhub scan . --api-url http://localhost:8080

# SaaS 版 (sbomhub.app / api.sbomhub.app) は 2026-06 にサンセット済。
# 以降は self-host (Docker Compose) を前提とする。

# 設定確認
sbomhub config
```

### スキャン & アップロード

```bash
# カレントディレクトリをスキャン
sbomhub scan .

# プロジェクト指定
sbomhub scan . --project my-app

# コンテナイメージをスキャン
sbomhub scan ./image.tar

# 詳細オプション
sbomhub scan . \
  --project my-app \
  --tool syft \              # syft / trivy / cdxgen (default: auto-detect)
  --format cyclonedx \       # cyclonedx / spdx (default: cyclonedx)
  --output sbom.json \       # ローカルにも保存
  --fail-on critical         # Critical検出時にexit 1（CI用）
```

### 脆弱性チェック（アップロードせず）

```bash
sbomhub check .
sbomhub check ./sbom.json
```

### プロジェクト管理

```bash
sbomhub projects list
```

### LLM プロバイダ操作 (M4)

self-host SBOMHub に接続済の BYOK LLM プロバイダ (OpenAI / Anthropic /
Gemini / Azure OpenAI / Ollama) の疎通確認と品質ベンチマーク用コマンド群。
詳細は `sbomhub llm --help` および各 subcommand の `--help` を参照。

#### `sbomhub llm test` — 疎通確認

`sbomhub` API server の `/api/v1/health` を叩き、 接続性 +
(server が公開していれば) provider / model を表示する。

```bash
# 人間向け表示
sbomhub llm test

# JSON (CI / jq 用)
sbomhub llm test --json
```

Exit code:

| code | 意味 |
|------|------|
| 0 | 正常 |
| 3 | 恒久エラー (401/403/404、 BYOK 未設定 — `/settings/llm` で設定) |
| 4 | 一時エラー (429/5xx / network — retry 推奨) |

#### `sbomhub llm bench` — 品質ベンチマーク

既定 (`SBOMHUB_BENCH_MODE=binary`) では sbomhub GitHub Release から
pre-built `llm-bench` archive を download し、 checksum 検証後に cache して
直接 exec する。 operator は Go toolchain や sbomhub source checkout なしで
managed AI vs local LLM (Ollama) の VEX-triage 品質を 20 件の eval-set で
比較できる。

旧来の source build 経路は `SBOMHUB_BENCH_MODE=source` で維持している。
sbomhub upstream の pre-release を試す、 source patch 済み harness を使う、
または完全 offline の custom build を実行する場合に使う。

```bash
# default: binary mode。自身の CLI version または latest release の llm-bench を使う
sbomhub llm bench

# provider 限定 + 集計 markdown
sbomhub llm bench --providers ollama,gemini --markdown

# bench binary version を固定
SBOMHUB_BENCH_VERSION=v1.4.1 sbomhub llm bench --max-cases 10 --out result.jsonl

# offline / air-gapped: 手元の binary を直接実行し、download/cache を bypass
sbomhub llm bench --bench-binary /opt/sbomhub/llm-bench

# backward compat: source checkout から go build して実行
SBOMHUB_BENCH_MODE=source sbomhub llm bench --sbomhub-source ../sbomhub
```

**前提**:
- binary mode では GitHub Release へ HTTPS 接続できること
- `--bench-binary` 指定時は手元の binary と同じ directory 配下に `fixtures/llm-bench/cve-20-50.json` があること、または `--eval-set` で明示すること
- source mode では Go toolchain (1.22+) と sbomhub OSS source checkout があること (`--sbomhub-source` / 環境変数 `SBOMHUB_SOURCE` / 既定 `./sbomhub`)
- 比較したい provider の BYOK 環境変数が export 済 (下の表)

**binary mode の version / cache**:

| 設定 | 内容 |
|------|------|
| `SBOMHUB_BENCH_MODE=binary` | 既定。 release archive を download/cache して実行 |
| `SBOMHUB_BENCH_MODE=source` | 旧 source checkout + `go build` 経路 |
| `SBOMHUB_BENCH_VERSION=v1.4.1` | 使用する sbomhub release tag を固定 |
| `--bench-binary /path/to/llm-bench` | download/cache を bypass して指定 binary を直接実行 |

version 解決は `SBOMHUB_BENCH_VERSION` → sbomhub-cli 自身の release version
→ GitHub API `releases/latest` の順。 cache は
`~/.cache/sbomhub-cli/llm-bench/<version>-<os>-<arch>/llm-bench` に置く。
archive は同じ release の `checksums.txt` に載る SHA-256 と照合し、 cache
marker (`.archive.sha256`) が不一致なら warning を出して再 download する。

**BYOK 環境変数**:

CLI の API server 認証 ( `SBOMHUB_API_KEY` ) と LLM provider key
( `SBOMHUB_LLM_API_KEY` / provider-native env ) は別物。 LLM provider
key は canonical ( `SBOMHUB_LLM_API_KEY` ) を first precedence、
provider-native env を alias fallback として読む (M4 Codex review #F47)。

*sbomhub CLI 自身の API 認証* (LLM とは無関係):

| 環境変数 | 用途 |
|----------|------|
| `SBOMHUB_API_KEY` | sbomhub API server 認証 ( `sbomhub login` でも `~/.sbomhub/config.yaml` に保存可) |

*LLM provider API key* (canonical first、 provider-native alias fallback):

| Provider | Canonical | Alias |
|----------|-----------|-------|
| OpenAI | `SBOMHUB_LLM_API_KEY` | `OPENAI_API_KEY` |
| Anthropic | `SBOMHUB_LLM_API_KEY` | `ANTHROPIC_API_KEY` |
| Gemini | `SBOMHUB_LLM_API_KEY` | `GOOGLE_API_KEY` / `GEMINI_API_KEY` |
| Azure OpenAI | `SBOMHUB_LLM_API_KEY` | `AZURE_OPENAI_API_KEY` |
| Ollama | (不要 / not required) | — |

*Azure OpenAI 追加設定* (M4 Codex review #F52 + #F59):

Canonical (`SBOMHUB_LLM_*`) を first precedence、 Azure-native env を
alias fallback として読む。 deployment 名のみ Microsoft 公式ドキュメント間で
3 種類の Azure-native env name が混在するため、 4-layer precedence
ladder で順次解決する (#F59)。

| 環境変数 (canonical) | 用途 | Alias (precedence order) |
|----------------------|------|--------------------------|
| `SBOMHUB_LLM_AZURE_ENDPOINT` | Azure endpoint URL | `AZURE_OPENAI_ENDPOINT` |
| `SBOMHUB_LLM_AZURE_DEPLOYMENT` | deployment 名 | `AZURE_OPENAI_DEPLOYMENT` > `AZURE_OPENAI_DEPLOYMENT_NAME` > `AZURE_OPENAI_CHAT_DEPLOYMENT_NAME` |
| `SBOMHUB_LLM_AZURE_API_VERSION` | API version (省略時 azure_openai.go default) | `AZURE_OPENAI_API_VERSION` |

deployment alias の出典:
- `AZURE_OPENAI_DEPLOYMENT` — 多くの Azure code sample (F52)
- `AZURE_OPENAI_DEPLOYMENT_NAME` — Microsoft Learn の AKS OpenAI quickstart、 Azure SDK for JS / Python OpenAI library (F59)
- `AZURE_OPENAI_CHAT_DEPLOYMENT_NAME` — Azure Agent Framework ドキュメント (F59)

*Ollama 設定* (M4 Codex review #F47):

| 環境変数 (canonical) | 用途 | Alias |
|----------------------|------|-------|
| `SBOMHUB_LLM_OLLAMA_URL` | Ollama base URL (省略時 `http://localhost:11434`) | `OLLAMA_HOST` |

*bench 専用 model 上書き* ( `SBOMHUB_LLM_MODEL` を汚染せずに provider 別 model を bench 時のみ指定):

| 環境変数 | 用途 |
|----------|------|
| `SBOMHUB_LLM_BENCH_OPENAI_MODEL` | bench-only OpenAI model 上書き |
| `SBOMHUB_LLM_BENCH_ANTHROPIC_MODEL` | bench-only Anthropic model 上書き |
| `SBOMHUB_LLM_BENCH_GEMINI_MODEL` | bench-only Gemini model 上書き |
| `SBOMHUB_LLM_BENCH_AZURE_OPENAI_MODEL` | bench-only Azure OpenAI model 上書き |
| `SBOMHUB_LLM_BENCH_OLLAMA_MODEL` | bench-only Ollama model (Ollama では必須、 例 `qwen2.5-coder:7b`) |

Exit code (wrapper preflight + M4-3 typed pass-through):

| code | 意味 |
|------|------|
| 0 | 正常 |
| 2 | usage / flag validation (M4-3 から透過) |
| 3 | 恒久エラー (wrapper preflight: download/cache/checksum / sbomhub source / eval-set / Go 不在 / `go build` 失敗 / 起動失敗、 もしくは M4-3 の fixture / config validation、 もしくは M4-3 が contract 外の exit code を emit した場合の正規化 #F57) |
| 4 | no providers configured (M4-3 から透過 — BYOK env を設定 or `--providers` から外す)、 または subprocess signal-killed |
| 5 | execution failure (M4-3 から透過 — provider 一時障害の可能性、 retry 推奨) |

※ M4 Codex review #F61: M4-3 binary は `go build` でコンパイル後に直接 exec
されるため、 inner os.Exit(N) が wrapper の exit code にそのまま伝搬する
(`go run` 経由では `go` 自体が常に exit 1 を返し、 F42 typed contract が
silent にマスクされていた)。

**Docker で `llm bench` を実行する場合**: binary mode は default の slim
image でも動作する。 source mode が必要な場合だけ Go toolchain 入りの
variant image (`sbomhub-cli:bench`) を使う。

```bash
docker run --rm \
  -e OPENAI_API_KEY \
  -e ANTHROPIC_API_KEY \
  ghcr.io/youichi-uda/sbomhub-cli:latest \
  llm bench --providers openai,anthropic

docker run --rm \
  -v "$(pwd)/sbomhub:/workspace/sbomhub" \
  -e SBOMHUB_BENCH_MODE=source \
  -e OPENAI_API_KEY \
  ghcr.io/youichi-uda/sbomhub-cli:bench \
  llm bench --sbomhub-source /workspace/sbomhub
```

`sbomhub llm test` を含む他の subcommand は HTTP API call のみで動作するため
default slim image でも問題なく動く。

#### Docker image build 時間 (M5-4 sbomhub-cli #6)

`Dockerfile.bench` に BuildKit cache mount
(`RUN --mount=type=cache,target=/go/pkg/mod` / `target=/root/.cache/go-build`)
を追加し、 CI (`docker-smoke` job) は `docker buildx build
--cache-from=type=gha --cache-to=type=gha,mode=max` で GitHub Actions cache
backend を使う。 cache scope は smoke job と release publish job
(`docker-publish`) で別々 (`sbomhub-cli-smoke-bench` vs `sbomhub-cli-bench`)
に分離してあるので、 smoke 側 cache eviction が release 側を汚染しない。

| build | 実測予測 (cold) | 実測予測 (warm) | 計測場所 |
|-------|-----------------|-----------------|----------|
| `Dockerfile` (default, alpine slim) | ~30s | ~10s | CI `$GITHUB_STEP_SUMMARY` |
| `Dockerfile.bench` (`golang:1.25-alpine`) | 3-5 min | 30-60 s | CI `$GITHUB_STEP_SUMMARY` |

実数は push ごとに `Actions → CI → docker-smoke (Linux) → Summary` に
seconds 単位で出力される。 初回 push 後に cache が temper されると warm
build に切り替わる。 ※要確認: GitHub Actions cache backend は repo 全体で
10 GB 上限の LRU、 release 側 publish と同居しているので scope を切らずに
混ぜると steady state で取り合いになる。

#### Cross-OS docker-smoke 対応状況 (M5-4 sbomhub-cli #6)

| OS | runner | docker-smoke 同等 | release gate | 備考 |
|----|--------|-------------------|--------------|------|
| Linux | `ubuntu-latest` | 対応 (`docker-smoke`) | 対応 (`needs:` 参照) | GHCR publish もこの surface |
| macOS | `macos-15-intel` | 対応 (`docker-smoke-macos`, informational) | 非対応 | Colima + sidecar mock 経路 ※下記 |
| Windows | `windows-latest` | 非対応 (skip) | 非対応 | WSL2 cold start 15-30 分が高すぎる |

**macOS 注意点**:
- Apple Silicon の `macos-26` / `macos-latest` は nested virtualization が
  使えず Colima / Lima を起動できない (Colima #277/#902/#1427)。 現状
  `macos-15-intel` (Intel runner) に pin してある。 GitHub が ARM 側で
  nested virt を有効化したら `macos-latest` に切替予定。
- Colima では `--network=host` も
  `--add-host=host.docker.internal:host-gateway` も macOS host を指さない
  (Lima VM 内で完結する) ため、 mock `/api/v1/health` 用 python http.server
  を sidecar container として user-defined bridge network 上に立て、 CLI
  container が container-DNS hostname (`mock-health`) で到達する構造に
  している。
- `continue-on-error: true`。 macOS-only flake が tag release を block しない
  ように release gate からは外している (publish 先 image は Linux-only)。

**Windows skip 理由**:
GitHub Actions の Windows runner で Linux container を動かすには
Docker Desktop + WSL2 の cold start が必要で、 同じ `docker-smoke` を回すと
15-30 分かかる。 publish 先の `sbomhub-cli` / `sbomhub-cli:bench` image は
Linux-only (alpine ベース) で、 Windows 操作者は Docker Desktop / WSL2 経由で
そのまま Linux container を引いて使うため、 Linux smoke がカバーする surface
と同じ。 `build` job が native Windows binary build (`go build` on
`windows-latest`) を別途持っており、 native 配布は goreleaser
(`.goreleaser.yaml`) でカバーされている。 Windows-Docker 固有 regression
(entrypoint CRLF / NTFS exec-bit 等) が将来発覚した時は revisit する。

## Roadmap (M1 以降)

CRA 2026/9 期限対応に向け、 以下のコマンドを M1〜M2 で順次実装予定。 いずれも AI 下書き + 人間承認モデル (自動承認なし)。

- `sbomhub triage` — Critical/High 脆弱性のインタラクティブ triage、 AI VEX 下書きへのハンドオフ
- `sbomhub vex export` — 承認済 VEX statement を CycloneDX VEX / CSAF 形式でエクスポート (CRA 提出向け)
- `sbomhub cra draft` — SBOM + VEX + 監査ログから CRA 脆弱性報告書ドラフトを生成

詳細: [`sbomhub-internal/planning/PRODUCT_REBOOT_PLAN.md`](https://github.com/youichi-uda/sbomhub) (内部リンク、 公開時は M1 で external roadmap doc を整備)

## CI/CD連携

### GitHub Actions

```yaml
- name: Install sbomhub CLI
  run: curl -fsSL https://sbomhub.app/install.sh | sh

- name: Scan and upload SBOM
  env:
    SBOMHUB_API_URL: ${{ secrets.SBOMHUB_API_URL }}  # 例: https://sbomhub.internal.example.com
    SBOMHUB_API_KEY: ${{ secrets.SBOMHUB_API_KEY }}
  run: sbomhub scan . --project ${{ github.repository }} --fail-on critical
```

### GitLab CI

```yaml
sbom_scan:
  script:
    - curl -fsSL https://sbomhub.app/install.sh | sh
    - sbomhub scan . --project ${CI_PROJECT_NAME} --fail-on critical
  variables:
    SBOMHUB_API_URL: ${SBOMHUB_API_URL}  # 例: https://sbomhub.internal.example.com
    SBOMHUB_API_KEY: ${SBOMHUB_API_KEY}
```

## 設定ファイル

### グローバル設定 (~/.sbomhub/config.yaml)

```yaml
# self-host SBOMHub (Docker Compose) のデフォルト
api_url: http://localhost:8080
api_key: sbh_xxxxxxxxxxxxx
```

### プロジェクト設定 (.sbomhub.yaml)

```yaml
project: my-app
tool: syft
format: cyclonedx
fail_on: high
```

## 開発

### ビルド

```bash
go build -o sbomhub ./cmd/sbomhub
```

### テスト

```bash
go test ./...
```

### リリース

```bash
goreleaser release --snapshot --clean
```

## ライセンス

MIT License
