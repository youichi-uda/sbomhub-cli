# SBOMHub CLI

[![日本語](https://img.shields.io/badge/lang-日本語-red.svg)](./README.md) [![English](https://img.shields.io/badge/lang-English-blue.svg)](./README_en.md)

![License](https://img.shields.io/badge/license-MIT-green)
![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8)

SBOMHub用のコマンドラインツール。Syft/Trivy/cdxgen等のSBOM生成ツールをラップし、生成からSBOMHubへのアップロードまでを1コマンドで実行。

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
# ログイン（ブラウザ認証 or API Key入力）
sbomhub login

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

## CI/CD連携

### GitHub Actions

```yaml
- name: Install sbomhub CLI
  run: curl -fsSL https://sbomhub.app/install.sh | sh

- name: Scan and upload SBOM
  env:
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
    SBOMHUB_API_KEY: ${SBOMHUB_API_KEY}
```

## 設定ファイル

### グローバル設定 (~/.sbomhub/config.yaml)

```yaml
api_url: https://api.sbomhub.app
api_key: sk_xxxxxxxxxxxxx
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
