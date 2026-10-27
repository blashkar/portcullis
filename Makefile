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
	go test -run '^$$' -fuzz FuzzPrefixWriter -fuzztime 30s ./cmd/portcullis

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

.PHONY: sandbox sandbox-evil demo
sandbox: sandbox-evil
	docker build -t portcullis-upstream/filesystem -f src/filesystem/Dockerfile "$(UPSTREAM)"
	docker build -t portcullis-upstream/everything -f src/everything/Dockerfile "$(UPSTREAM)"
	docker build -t portcullis-upstream/git "$(UPSTREAM):src/git"
	for s in $(SANDBOX_SERVERS); do \
		docker build -t portcullis-sandbox/$$s --build-arg BASE=portcullis-upstream/$$s - < sandbox/$$s.Dockerfile || exit 1; \
	done

# The deliberately malicious demo server. It's our own code, so it's
# cross-compiled here for the Docker engine's architecture and put on an
# empty base image: nothing is pulled, and the build context holds only the
# two static binaries.
sandbox-evil:
	ctx=$$(mktemp -d) && trap 'rm -rf "$$ctx"' EXIT && \
	arch=$$(docker version -f '{{.Server.Arch}}') && \
	CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags "-s -w" -o "$$ctx/evil-server" ./demo/evil-server && \
	CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags "-s -w" -o "$$ctx/probe" ./sandbox/probe && \
	docker build -t portcullis-sandbox/evil -f sandbox/evil.Dockerfile "$$ctx"

# The demo: portcullis, run here, in front of the malicious server in the
# sandbox, driven by a scripted client. Each run starts with fresh state.
demo: build sandbox-evil
	rm -f demo/demo.db demo/demo.db-shm demo/demo.db-wal demo/demo.pins.json demo/demo.pins.json.lock
	go run ./demo/client
