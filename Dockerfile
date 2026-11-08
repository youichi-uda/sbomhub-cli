# SBOMHub CLI - Linux build and test
# M32: builder bumped 1.22 -> 1.25-alpine to satisfy go.mod `go 1.25.0`
# (raised by the vendored reachability analyzer's golang.org/x/tools v0.47.0
# minimum, which requires go >= 1.25).
# 2026-11: bumped 1.25 -> 1.26.10-alpine. golang.org/x/tools v0.52.0 /
# golang.org/x/mod v0.42.0 raise go.mod to `go 1.26.0`, and go.mod now pins
# `toolchain go1.26.10` (17 reachable stdlib vulns in go1.26.4 fixed there).
# Official golang images set GOTOOLCHAIN=local, so the toolchain directive is
# NOT auto-honoured inside the image — the base tag itself must carry the
# patched toolchain. Keep this tag in lockstep with go.mod's `toolchain` line
# (and Dockerfile.bench).
# 2026-11-08: bumped to golang:1.27.3-alpine with go.mod `toolchain go1.27.3`
# (Go 1.27 migration; the `go 1.26.0` floor is unchanged).
FROM golang:1.27.3-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy source
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build CLI
RUN CGO_ENABLED=0 GOOS=linux go build -o /sbomhub ./cmd/sbomhub

# Runtime image
FROM alpine:3.19

RUN apk add --no-cache ca-certificates

COPY --from=builder /sbomhub /usr/local/bin/sbomhub

# Create config directory
RUN mkdir -p /root/.sbomhub

ENTRYPOINT ["sbomhub"]
CMD ["--help"]
