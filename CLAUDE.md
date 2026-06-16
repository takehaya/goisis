# CLAUDE.md

Guidance for working in this repository.

## What this is

goisis is a from-scratch IS-IS routing protocol implementation in Go — "the
GoBGP of IS-IS". It is **library-first**: `pkg/server.IsisServer` is the
embeddable instance, and the `goisisd` daemon is a thin wrapper. A `goisis` CLI
talks to the daemon over Connect RPC. Features: dual-stack (IPv4/IPv6) IGP with
wide metrics, SPF/RIB and a pluggable FIB, SRv6 locators (RFC 9352), and Flexible
Algorithm (RFC 9350).

## Build / test / lint

The Go toolchain is **not on `PATH` by default**. Prefix it:

```bash
export PATH="$HOME/.local/toolchains/go/bin:$HOME/go/bin:$PATH"
```

- `make build` / `go build ./...`
- `make test` / `go test ./...` — unit + in-process protocol tests (no root needed)
- `make lint` — `golangci-lint` (v2) lives in `~/go/bin`
- `make proto` — regenerate `gen/` from `proto/` via `go tool -modfile=tools.mod buf generate`
- `make proto-check` — CI gate: regenerate and fail if `gen/` is stale (commit `gen/`)
- always `gofmt -l` before committing; the linter is strict (`unparam`, `errcheck`, `gosec`, staticcheck `unused`)

buf plugins are pinned in `tools.mod` (kept out of `go.mod` so library consumers
don't inherit the toolchain graph). Codegen is reproducible offline.

## Architecture

- **Single management loop** (GoBGP-style): `IsisServer.Serve` is the only
  goroutine that mutates protocol state (circuits, adjacencies, the LSDB). Every
  public read method and protocol event is serialized onto it via `mgmtOperation`
  / `eventCh`. Per-circuit reader goroutines only decode frames and forward events.
- **Event-driven SPF**: mutations call `markDirty()`; the loop runs `updateRIB`
  after any change rather than on a fixed timer.
- **Pluggable sinks** (same pattern, keep core dependency-free):
  - `pkg/fib.FIB` — `Noop` default; `Netlink` (Linux) programs `proto isis`
    routes and seg6local End SIDs. Wired via `WithFIB`.
  - `pkg/server.Metrics` — `NoopMetrics` default; `pkg/metrics.Prometheus`
    adapter (only it links `client_golang`). Wired via `WithMetrics`.
- **Codec** (`pkg/packet`): pure functions, no I/O, fuzzed. Three-level
  registry (TLV → sub-TLV → sub-sub-TLV); the same number means different things
  per parent context (`SubTLVContext*`). Unknown TLVs/sub-TLVs are preserved
  opaquely for byte-exact round-trip. Decoders that feed routing **mask prefixes**
  so RIB/FIB/sweep keys agree.

### Package layout

```
pkg/packet/    PDU/TLV codec (fuzzed, byte-exact vs FRR golden fixtures)
pkg/datalink/  Circuit transport: AF_PACKET (Linux) + race-safe mock
pkg/server/    IsisServer: mgmt loop, adjacency FSM, LSDB/flooding, SPF, RIB,
               origination, Connect handlers, Flex-Algo, metrics
pkg/fib/       FIB interface + netlink implementation
pkg/config/    YAML config -> server options
pkg/metrics/   Prometheus adapter for server.Metrics
cmd/goisisd/   daemon   cmd/goisis/  CLI
proto/ gen/    Connect RPC API (v1) and generated code
test/interop/  containerized FRR interop (root + docker; skips otherwise)
test/fixturegen/  scripts to capture FRR golden PDUs (need docker)
```

## Testing notes

- In-process protocol tests use `datalink` mock transports linked with
  `datalink.Link`; no privileges needed. White-box tests inject LSPs with the
  `injectLSP` helper and call `computeSPF`/`flexAlgoState` directly.
- A few broadcast/DIS timing tests (e.g. `TestRIBWithdrawsOnPeerLoss`,
  `TestWatchEmitsAdjacencyAndRoute`) can flake under heavy parallel load; they
  pass in isolation. Re-run the single test before assuming a regression.
- **FRR interop** (`test/interop`) and **golden-fixture capture**
  (`test/fixturegen/*.sh`) require `docker` + root, so they run in CI, not in a
  sandbox without docker. They are written to run there.
- FRR LAN LSP regeneration takes ~40s (a FRR characteristic); interop route
  tests use P2P for fast convergence.

## Conventions

- Commits: Conventional Commits. Author is the repo's git user; committer is
  `Claude <noreply@anthropic.com>`; include a `Co-Authored-By: Claude` trailer.
  One commit per milestone. No links in commit messages.
- Match surrounding code: comment density, naming, explicit per-case style.
- Scope: L2 single-area MVP; wide metrics only (narrow parsed, never originated).
  Multi-topology (RFC 5120), graceful restart (RFC 5306), and BFD are deferred.
  Flex-Algo computes the IGP metric only (constraint sub-sub-TLVs are preserved
  on the wire for a later ASLA-aware computation).

## Status

M0–M8 implemented: codec, data-link + adjacency, LSP flooding/LSDB sync, SPF +
RIB + netlink FIB, Connect API + CLI, SRv6 locators, Flex-Algo, plus hardening
(overload-on-startup, clean-shutdown purge, Prometheus metrics, HMAC
authentication of hellos and LSPs/SNPs — MD5 per RFC 5304 and SHA-1/256/384/512
per RFC 5310). All interop tests pass against FRR 10.6.1 (run with docker +
root); FRR's IS-IS auth is MD5-only so the SHA variants are validated
goisis↔goisis. The management API is promoted to `v1` with runtime
Add/Delete RPCs for SRv6 locators and Flex-Algos; buf breaking-change
detection gates further schema changes.
