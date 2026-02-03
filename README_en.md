# SBOMHub CLI

[![日本語](https://img.shields.io/badge/lang-日本語-red.svg)](./README.md) [![English](https://img.shields.io/badge/lang-English-blue.svg)](./README_en.md)

![License](https://img.shields.io/badge/license-MIT-green)
![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8)

A command-line tool for SBOMHub. Wraps SBOM generation tools like Syft, Trivy, and cdxgen to generate and upload SBOMs to SBOMHub in a single command.

## Supported Formats

- CycloneDX 1.4, 1.5, 1.6
- SPDX 2.2, 2.3

## Installation

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

## Usage

### Initial Setup

```bash
# Login (browser auth or API key input)
sbomhub login

# Check configuration
sbomhub config
```

### Scan & Upload

```bash
# Scan current directory
sbomhub scan .

# Specify project
sbomhub scan . --project my-app

# Scan container image
sbomhub scan ./image.tar

# Advanced options
sbomhub scan . \
  --project my-app \
  --tool syft \              # syft / trivy / cdxgen (default: auto-detect)
  --format cyclonedx \       # cyclonedx / spdx (default: cyclonedx)
  --output sbom.json \       # Also save locally
  --fail-on critical         # Exit 1 on Critical findings (for CI)
```

### Vulnerability Check (without upload)

```bash
sbomhub check .
sbomhub check ./sbom.json
```

### Project Management

```bash
sbomhub projects list
```

## CI/CD Integration

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

## Configuration Files

### Global Configuration (~/.sbomhub/config.yaml)

```yaml
api_url: https://api.sbomhub.app
api_key: sk_xxxxxxxxxxxxx
```

### Project Configuration (.sbomhub.yaml)

```yaml
project: my-app
tool: syft
format: cyclonedx
fail_on: high
```

## Development

### Build

```bash
go build -o sbomhub ./cmd/sbomhub
```

### Test

```bash
go test ./...
```

### Release

```bash
goreleaser release --snapshot --clean
```

## License

MIT License
