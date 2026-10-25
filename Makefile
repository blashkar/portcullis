VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test fuzz lint vuln fmt clean

build:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/portcullis ./cmd/portcullis
	go build -ldflags "-X main.version=$(VERSION)" -o bin/portcullis-agent ./cmd/portcullis-agent

test:
	go test -race ./...

# A short fuzzing pass over the JSON-RPC parser and line reader.
fuzz:
	go test -run '^$$' -fuzz FuzzParse -fuzztime 30s ./internal/jsonrpc
	go test -run '^$$' -fuzz FuzzReader -fuzztime 30s ./internal/jsonrpc
	go test -run '^$$' -fuzz FuzzDecodeArgs -fuzztime 30s ./internal/gateway
	go test -run '^$$' -fuzz FuzzTool -fuzztime 30s ./internal/scan
	go test -run '^$$' -fuzz FuzzRedact -fuzztime 30s ./internal/redact
	go test -run '^$$' -fuzz FuzzHeuristics -fuzztime 30s ./internal/inject

lint:
	golangci-lint run

# Known vulnerabilities in the code's dependencies, as far as it calls them.
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

fmt:
	golangci-lint fmt

clean:
	rm -rf bin

# Sandboxed MCP servers. Each is built from the official source at a pinned
# commit, fetched by Docker straight from GitHub, then given a made-up
# workspace by a Dockerfile built with no context. No host files go in.
# modelcontextprotocol/servers v2.1.0
UPSTREAM_REF := ef9808f71090d0db3eda99e2af2ba78f1086f4fb
UPSTREAM := https://github.com/modelcontextprotocol/servers.git\#$(UPSTREAM_REF)
SANDBOX_SERVERS := filesystem git everything

.PHONY: sandbox
sandbox:
	docker build -t portcullis-upstream/filesystem -f src/filesystem/Dockerfile "$(UPSTREAM)"
	docker build -t portcullis-upstream/everything -f src/everything/Dockerfile "$(UPSTREAM)"
	docker build -t portcullis-upstream/git "$(UPSTREAM):src/git"
	for s in $(SANDBOX_SERVERS); do \
		docker build -t portcullis-sandbox/$$s --build-arg BASE=portcullis-upstream/$$s - < sandbox/$$s.Dockerfile || exit 1; \
	done
