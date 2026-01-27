.PHONY: build clean test install

BINARY_NAME=sbomhub
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE?=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS=-ldflags "-s -w \
	-X github.com/youichi-uda/sbomhub-cli/cmd/sbomhub/commands.version=$(VERSION) \
	-X github.com/youichi-uda/sbomhub-cli/cmd/sbomhub/commands.commit=$(COMMIT) \
	-X github.com/youichi-uda/sbomhub-cli/cmd/sbomhub/commands.date=$(DATE)"

build:
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/sbomhub

clean:
	rm -f $(BINARY_NAME)
	rm -rf dist/

test:
	go test -v ./...

install: build
	cp $(BINARY_NAME) $(GOPATH)/bin/

# Development
dev: build
	./$(BINARY_NAME) version

# Release (requires goreleaser)
release:
	goreleaser release --clean

snapshot:
	goreleaser release --snapshot --clean

# Dependencies
deps:
	go mod download
	go mod tidy
