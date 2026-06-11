#!/usr/bin/env bash
set -euo pipefail

# Versions are pinned so local dev and CI agree (.github/workflows/lint.yaml
# pins the same golangci-lint version). Update deliberately.
GOLANGCI_LINT_VERSION="${GOLANGCI_LINT_VERSION:-v2.12.2}"
LEFTHOOK_VERSION="${LEFTHOOK_VERSION:-v1.13.6}"

# golangci-lint v2 lives under the /v2 module path (the v1 path is deprecated).
go install "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}"
go install "github.com/evilmartians/lefthook@${LEFTHOOK_VERSION}"

lefthook install
