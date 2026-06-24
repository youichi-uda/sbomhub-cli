# SBOMHub CLI

[![日本語](https://img.shields.io/badge/lang-日本語-red.svg)](./README.md) [![English](https://img.shields.io/badge/lang-English-blue.svg)](./README_en.md)

![License](https://img.shields.io/badge/license-MIT-green)
![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8)

SBOMHub CLI: a command-line tool that takes you from SBOM generation through upload — and, in upcoming releases, on to VEX export and CRA report drafting — in a single command, so you can meet the EU CRA 2026-09 deadline. Wraps SBOM generators (Syft, Trivy, cdxgen) and pairs with the self-host SBOMHub server.

## Supported Formats

- CycloneDX 1.4, 1.5, 1.6
- SPDX 2.2, 2.3

## Installation

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

## Usage

### Initial Setup

```bash
# Recommended: connect to your self-host SBOMHub (interactive prompts)
sbomhub login
#   API Key: sbh_xxxxx
#   API URL [https://api.sbomhub.app]: http://localhost:8080
# → writes the answers into ~/.sbomhub/config.yaml

# For non-interactive (CI) use, pass them as global flags or env vars:
#   sbomhub --api-url http://localhost:8080 --api-key sbh_xxxxx scan .
#   SBOMHUB_API_KEY=sbh_xxxxx sbomhub scan . --api-url http://localhost:8080

# The SaaS edition (sbomhub.app / api.sbomhub.app) was sunset in 2026-06.
# Self-host (Docker Compose) is the only supported deployment going forward.

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

## Roadmap (M1 and beyond)

The following commands are planned for M1–M2 to round out CRA 2026-09 readiness. Every one of them is built on an AI-drafts-with-human-approval model (no auto-approval).

- `sbomhub triage` — interactive triage of Critical/High vulnerabilities, with handoff to AI VEX drafts
- `sbomhub vex export` — export approved VEX statements as CycloneDX VEX / CSAF (for CRA submission)
- `sbomhub cra draft` — generate a CRA vulnerability report draft from SBOM + VEX + audit log

Details: [`sbomhub-internal/planning/PRODUCT_REBOOT_PLAN.md`](https://github.com/youichi-uda/sbomhub) (internal; an external roadmap doc will land in M1 when the plan goes public).

## CI/CD Integration

### GitHub Actions

```yaml
- name: Install sbomhub CLI
  run: curl -fsSL https://sbomhub.app/install.sh | sh

- name: Scan and upload SBOM
  env:
    SBOMHUB_API_URL: ${{ secrets.SBOMHUB_API_URL }}  # e.g. https://sbomhub.internal.example.com
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
    SBOMHUB_API_URL: ${SBOMHUB_API_URL}  # e.g. https://sbomhub.internal.example.com
    SBOMHUB_API_KEY: ${SBOMHUB_API_KEY}
```

## Configuration Files

### Global Configuration (~/.sbomhub/config.yaml)

```yaml
# Default for self-host SBOMHub (Docker Compose)
api_url: http://localhost:8080
api_key: sbh_xxxxxxxxxxxxx
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
