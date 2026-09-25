# csp-validator - common development tasks.
# Requires: Go (see go.mod), golangci-lint (https://golangci-lint.run).

GO ?= go
BIN ?= bin/csp-validator

.PHONY: all build fmt fmt-check vet lint test race cover tidy vuln ci clean help

all: check

help:
	@grep -E '^[a-z-]+:.*?##' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-12s %s\n", $$1, $$2}'

build: ## build the CLI into bin/
	$(GO) build -o $(BIN) ./cmd/csp-validator

fmt: ## rewrite Go files with gofmt
	gofmt -w .

fmt-check: ## fail if any file is not gofmt-formatted
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then echo "gofmt would rewrite:"; echo "$$out"; exit 1; fi

vet: ## run go vet
	$(GO) vet ./...

lint: ## run golangci-lint with the project config
	golangci-lint run ./...

test: ## run unit tests
	$(GO) test ./...

race: ## run unit tests with the race detector
	$(GO) test -race ./...

cover: ## run unit tests with race detector and coverage
	$(GO) test -race -cover ./...

tidy: ## verify go.mod / go.sum are tidy (fails on drift)
	$(GO) mod tidy
	@git diff --quiet -- go.mod go.sum || { echo "go.mod/go.sum changed; commit the result"; exit 1; }

vuln: ## run govulncheck (advisory until csp-validator-dep-vulns is closed)
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

ci: fmt-check build vet lint cover ## everything the CI pipeline runs
	@echo "CI checks passed"

clean: ## remove build output
	rm -rf bin/