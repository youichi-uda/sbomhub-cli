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

### LLM Provider Operations (M4)

Connectivity check and quality benchmark commands for the BYOK LLM
providers (OpenAI / Anthropic / Gemini / Azure OpenAI / Ollama) that
your self-host SBOMHub server is wired up to. See `sbomhub llm --help`
and each subcommand's `--help` for the full flag set.

#### `sbomhub llm test` — connectivity probe

Probes `/api/v1/health` on the configured SBOMHub API server and
prints connectivity + (when published) provider / model.

```bash
# Human-readable output
sbomhub llm test

# JSON (for CI / jq)
sbomhub llm test --json
```

Exit codes:

| code | meaning |
|------|---------|
| 0 | success |
| 3 | permanent (401/403/404, BYOK not configured — set it in `/settings/llm`) |
| 4 | transient (429/5xx / network — retry recommended) |

#### `sbomhub llm bench` — quality benchmark

Wraps the `llm-bench` harness shipped in the sbomhub OSS source and
launches it via `go run`, comparing managed AI vs local LLM (Ollama)
VEX-triage quality across a 20-case eval-set.

```bash
# Default: source at ./sbomhub, all providers
sbomhub llm bench

# Subset of providers + aggregation table
sbomhub llm bench --providers ollama,gemini --markdown

# Source at a different path + reduced case count
sbomhub llm bench --sbomhub-source ../sbomhub --max-cases 10 --out result.jsonl
```

**Prerequisites**:
- A Go toolchain (1.22+) installed on the host
- The sbomhub OSS source checked out locally (`--sbomhub-source` /
  env `SBOMHUB_SOURCE` / default `./sbomhub`)
- BYOK env vars exported for each provider under test (see the table)

**BYOK environment variables**:

The CLI's API-server authentication ( `SBOMHUB_API_KEY` ) and the LLM
provider key ( `SBOMHUB_LLM_API_KEY` / provider-native env ) are
separate. LLM provider keys read the canonical
( `SBOMHUB_LLM_API_KEY` ) first and fall back to the provider-native
env names (M4 Codex review #F47).

*sbomhub CLI's own API auth* (unrelated to LLM):

| Variable | Purpose |
|----------|---------|
| `SBOMHUB_API_KEY` | sbomhub API server authentication (also savable via `sbomhub login` into `~/.sbomhub/config.yaml`) |

*LLM provider API key* (canonical first, provider-native alias fallback):

| Provider | Canonical | Alias |
|----------|-----------|-------|
| OpenAI | `SBOMHUB_LLM_API_KEY` | `OPENAI_API_KEY` |
| Anthropic | `SBOMHUB_LLM_API_KEY` | `ANTHROPIC_API_KEY` |
| Gemini | `SBOMHUB_LLM_API_KEY` | `GOOGLE_API_KEY` / `GEMINI_API_KEY` |
| Azure OpenAI | `SBOMHUB_LLM_API_KEY` | `AZURE_OPENAI_API_KEY` |
| Ollama | (not required) | — |

*Azure OpenAI additional config* (M4 Codex review #F52):

| Variable (canonical) | Purpose | Alias |
|----------------------|---------|-------|
| `SBOMHUB_LLM_AZURE_ENDPOINT` | Azure endpoint URL | `AZURE_OPENAI_ENDPOINT` |
| `SBOMHUB_LLM_AZURE_DEPLOYMENT` | Deployment name | `AZURE_OPENAI_DEPLOYMENT` |
| `SBOMHUB_LLM_AZURE_API_VERSION` | API version (defaults to `azure_openai.go`'s default when unset) | `AZURE_OPENAI_API_VERSION` |

*Ollama config* (M4 Codex review #F47):

| Variable (canonical) | Purpose | Alias |
|----------------------|---------|-------|
| `SBOMHUB_LLM_OLLAMA_URL` | Ollama base URL (default `http://localhost:11434`) | `OLLAMA_HOST` |

*bench-only model overrides* (let you target a specific managed-vs-local pair without polluting the runtime `SBOMHUB_LLM_MODEL`):

| Variable | Purpose |
|----------|---------|
| `SBOMHUB_LLM_BENCH_OPENAI_MODEL` | Bench-only OpenAI model override |
| `SBOMHUB_LLM_BENCH_ANTHROPIC_MODEL` | Bench-only Anthropic model override |
| `SBOMHUB_LLM_BENCH_GEMINI_MODEL` | Bench-only Gemini model override |
| `SBOMHUB_LLM_BENCH_AZURE_OPENAI_MODEL` | Bench-only Azure OpenAI model override |
| `SBOMHUB_LLM_BENCH_OLLAMA_MODEL` | Bench-only Ollama model (required for Ollama, e.g. `qwen2.5-coder:7b`) |

Exit codes (wrapper preflight + M4-3 typed pass-through):

| code | meaning |
|------|---------|
| 0 | success |
| 2 | usage / flag validation (forwarded from M4-3) |
| 3 | permanent (wrapper preflight: missing sbomhub source / eval-set / Go toolchain / launch failure, or M4-3 fixture / config validation) |
| 4 | no providers configured (forwarded from M4-3 — set BYOK env or drop the provider from `--providers`), or subprocess signal-killed |
| 5 | execution failure (forwarded from M4-3 — likely transient provider outage; retry recommended) |

**Running `llm bench` from Docker**: the default `sbomhub-cli` image
is slim (`alpine` + `ca-certificates`) and does not include a Go
toolchain. A `sbomhub-cli:bench` variant image ships Go for this
workflow:

```bash
docker run --rm \
  -v "$(pwd)/sbomhub:/workspace/sbomhub" \
  -e OPENAI_API_KEY \
  -e ANTHROPIC_API_KEY \
  ghcr.io/youichi-uda/sbomhub-cli:bench \
  llm bench --sbomhub-source /workspace/sbomhub
```

Every other subcommand — including `sbomhub llm test` — talks HTTP
only and works on the default slim image.

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
