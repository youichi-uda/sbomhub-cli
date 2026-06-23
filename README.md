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
brew install sbomhub/tap/sbomhub
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
scoop bucket add sbomhub https://github.com/sbomhub/scoop-bucket
scoop install sbomhub
```

## 使い方

### 初期設定

```bash
# 推奨: self-host SBOMHub に接続
sbomhub login --url http://localhost:8080 --api-key sbh_xxxxx

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
