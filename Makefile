BIN := bin/portcullis
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test fuzz lint fmt clean

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BIN) ./cmd/portcullis

test:
	go test -race ./...

# A short fuzzing pass over the JSON-RPC parser and line reader.
fuzz:
	go test -run '^$$' -fuzz FuzzParse -fuzztime 30s ./internal/jsonrpc
	go test -run '^$$' -fuzz FuzzReader -fuzztime 30s ./internal/jsonrpc

lint:
	golangci-lint run

fmt:
	golangci-lint fmt

clean:
	rm -rf bin
