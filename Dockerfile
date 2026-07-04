# SBOMHub CLI - Linux build and test
# M32: builder bumped 1.22 -> 1.25-alpine to satisfy go.mod `go 1.25.0`
# (raised by the vendored reachability analyzer's golang.org/x/tools v0.47.0
# minimum, which requires go >= 1.25). Matches Dockerfile.bench + CI go 1.25.
FROM golang:1.25-alpine AS builder

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
