# SBOMHub CLI - Linux build and test
FROM golang:1.22-alpine AS builder

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
