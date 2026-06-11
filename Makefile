GO ?= go

.PHONY: build
build:
	$(GO) build ./...

.PHONY: bin
bin:
	$(GO) build -o bin/goisisd ./cmd/goisisd
	$(GO) build -o bin/goisis ./cmd/goisis

.PHONY: test
test:
	$(GO) test -race -count=1 ./...

.PHONY: lint
lint:
	golangci-lint run

.PHONY: proto
proto:
	$(GO) tool -modfile=tools.mod buf generate

.PHONY: proto-lint
proto-lint:
	$(GO) tool -modfile=tools.mod buf lint

.PHONY: proto-check
proto-check: proto
	@status="$$(git status --porcelain gen/)"; \
	if [ -n "$$status" ]; then \
		echo "$$status"; \
		echo "gen/ is stale; run 'make proto' and commit the result" >&2; \
		exit 1; \
	fi

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: snapshot
snapshot:
	goreleaser release --snapshot --clean

.PHONY: install-dev-tools
install-dev-tools:
	./scripts/install_dev_tools.sh

.PHONY: clean
clean:
	rm -rf bin dist
