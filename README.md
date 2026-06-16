# goisis

IS-IS routing protocol implementation in Go — the IS-IS counterpart of
[GoBGP](https://github.com/osrg/gobgp).

[日本語版 README はこちら](README.ja.md) · [Configuration reference](docs/configuration.md) · [Library guide](docs/library.md)

goisis is **library-first**: embed an IS-IS instance in your Go program with
`pkg/server.IsisServer`, and the `goisisd` daemon is a thin wrapper around it.
A `goisis` CLI talks to the daemon over [Connect RPC](https://connectrpc.com/)
(gRPC, gRPC-Web, and Connect on one port).

## Features

- **Dual-stack IGP** — IPv4 and IPv6, wide metrics, per-level SPF, ECMP, the
  overload bit, and a kernel FIB (`proto isis`) via netlink
- **L1/L2** single-area routing (LAN with DIS election, and point-to-point)
- **SRv6 locators** (RFC 9352) — SRv6 Locator TLV with a local End SID
  programmed as a `seg6local` route, plus a TLV 236 mirror for legacy interop
- **Flexible Algorithm** (RFC 9350) — FAD advertisement, winner election, and
  per-algorithm SPF over a pruned topology (IGP metric)
- **Connect RPC API + CLI** — inspect circuits, adjacencies, the LSDB, routes,
  SRv6 locators, and Flex-Algo state; stream changes with `WatchEvent`
- **HMAC-MD5 authentication** (RFC 5304) of hellos and LSPs/SNPs, wire-compatible
  with FRR's `isis password md5` / `area-password md5` / `domain-password md5`
- **Prometheus metrics** at `/metrics`
- **Continuous FRR interop** — every PR runs containerized topologies against
  FRR isisd

> Scope: an L2 single-area MVP. Multi-topology (RFC 5120), graceful restart
> (RFC 5306), and BFD integration are deferred; narrow metrics are parsed but
> never originated. See the [milestones](#status).

## Install

```console
$ go install github.com/takehaya/goisis/cmd/goisisd@latest
$ go install github.com/takehaya/goisis/cmd/goisis@latest
```

Or build from source:

```console
$ git clone https://github.com/takehaya/goisis && cd goisis
$ make bin            # builds bin/goisisd and bin/goisis
```

`goisisd` needs `CAP_NET_RAW` to open AF_PACKET sockets, and `CAP_NET_ADMIN`
to program the FIB:

```console
$ sudo setcap cap_net_raw,cap_net_admin+ep bin/goisisd
```

## Quickstart

```console
$ sudo goisisd -f examples/goisisd.yaml      # run the daemon
$ goisis neighbor                            # adjacencies
$ goisis database                            # the link-state database
$ goisis route                               # computed routes (with ALGO column)
$ goisis locator                             # advertised SRv6 locators
$ goisis flex-algo                           # Flex-Algo definitions / participants
$ goisis monitor                             # stream adjacency/route changes
```

The API is also reachable with `grpcurl`/`buf curl` (gRPC reflection and health
are enabled). Metrics are at `http://127.0.0.1:50051/metrics`.

## Configuration

A minimal `goisisd.yaml`:

```yaml
net: 49.0001.0000.0000.0001.00   # area address + system ID (NSEL must be 00)
hostname: r1
fib: true                        # program the kernel FIB (needs CAP_NET_ADMIN)
circuits:
  - interface: eth0
    level: "12"                  # "1", "2", or "12"
prefixes:
  - 10.1.1.1/32
  - 2001:db8:1::1/128
srv6:
  locators:
    - fc00:0:1::/48
flex-algo:
  - algo: 128
    metric-type: igp
    priority: 100
    advertise: true
    locator: fc00:0:128::/48
```

See [`examples/goisisd.yaml`](examples/goisisd.yaml) for every option and the
[configuration reference](docs/configuration.md) for details. A systemd unit is
provided in [`packaging/goisisd.service`](packaging/goisisd.service).

## Library usage

```go
s, err := server.NewIsisServer(
    server.WithSystemID(sysID),
    server.WithAreaAddresses(area),
    server.WithCircuit(server.CircuitConfig{Name: "eth0", Transport: tr, Level2: true}),
    server.WithAdvertisedPrefix(prefix, 10),
    server.WithFIB(fib.NewNetlink(unix.RT_TABLE_MAIN)), // or your own FIB / WatchEvent
)
if err != nil { log.Fatal(err) }
go s.Serve(ctx)
```

Supply your own `fib.FIB` or `server.Metrics` implementation to plug goisis into
a custom dataplane or telemetry pipeline. [`examples/watchroutes`](examples/watchroutes)
embeds goisis and reacts to route changes instead of programming the kernel —
the pattern for feeding an eBPF dataplane. The [library guide](docs/library.md)
covers the full embedding API.

## Development

```console
$ mise install               # pinned Go toolchain (mise.toml)
$ make install-dev-tools     # golangci-lint, lefthook
$ make build test lint
$ make proto                 # regenerate gen/ from proto/ (buf via tools.mod)
```

FRR interop and golden-fixture capture (`test/interop`, `test/fixturegen`)
require `docker` and root; they run in CI. See [CLAUDE.md](CLAUDE.md) for the
architecture and contributor notes.

## Status

| Milestone | Scope |
|-----------|-------|
| M0–M1 | Scaffold, CI/CD, PDU/TLV codec (fuzzed, FRR golden) |
| M2–M3 | Data-link + adjacency FSM, DIS election, LSP flooding, LSDB sync |
| M4 | SPF + RIB + prefix origination + netlink FIB |
| M5 | Connect RPC API + CLI + `WatchEvent` |
| M6 | SRv6 locator advertisement, learning, End SID programming |
| M7 | Flex-Algo definition, election, per-algorithm SPF |
| M8 | Overload-on-startup, clean-shutdown purge, Prometheus metrics, HMAC-MD5 authentication (hellos + LSPs/SNPs) |

Remaining: HMAC-SHA (RFC 5310), plus mutable-config RPCs (before promoting
the API from `v1alpha1` to `v1`).

## Naming

Unrelated to [choppsv1/goisis](https://github.com/choppsv1/goisis); the module
path is `github.com/takehaya/goisis`.

## License

Apache-2.0
