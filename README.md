# goisis

IS-IS routing protocol implementation in Go — the IS-IS counterpart of
[GoBGP](https://github.com/osrg/gobgp). **Library-first**: embed it via
`pkg/server.IsisServer`; `goisisd` is a thin daemon and `goisis` a CLI over
[Connect RPC](https://connectrpc.com/).

[日本語](README.ja.md) · [Getting started](docs/getting-started.md) · [Configuration](docs/configuration.md) · [Library guide](docs/library.md) · [Design](docs/design.md)

## Features

- Dual-stack (IPv4/IPv6) L1/L2 routing — wide metrics, per-level SPF, ECMP, overload bit, netlink FIB
- SRv6 locators (RFC 9352) and Flexible Algorithm (RFC 9350)
- Connect RPC API + CLI, with `WatchEvent` streaming
- HMAC authentication (RFC 5304/5310) of hellos and LSPs/SNPs
- Prometheus metrics, and continuous interop against FRR

> L2 single-area MVP; multi-topology, graceful restart, and BFD are deferred.

## Install

```console
$ go install github.com/takehaya/goisis/cmd/goisisd@latest
$ go install github.com/takehaya/goisis/cmd/goisis@latest
```

`goisisd` needs `CAP_NET_RAW` (AF_PACKET) and `CAP_NET_ADMIN` (FIB) — run as
root or grant them with `setcap cap_net_raw,cap_net_admin+ep`.

## Quickstart

```console
$ sudo goisisd -f examples/goisisd.yaml   # run the daemon
$ goisis neighbor                         # also: database, route, locator, flex-algo, monitor
```

A minimal `goisisd.yaml`:

```yaml
net: 49.0001.0000.0000.0001.00   # area + system ID (NSEL 00)
fib: true
circuits:
  - interface: eth0
    level: "12"
prefixes:
  - 10.1.1.1/32
```

[Getting started](docs/getting-started.md) walks through a two-node setup;
[`examples/goisisd.yaml`](examples/goisisd.yaml) and the
[configuration reference](docs/configuration.md) cover SRv6, Flex-Algo, auth,
and route policy.

## Library usage

```go
s, _ := server.NewIsisServer(
    server.WithSystemID(sysID),
    server.WithAreaAddresses(area),
    server.WithCircuit(server.CircuitConfig{Name: "eth0", Transport: tr, Level2: true}),
    server.WithAdvertisedPrefix(prefix, 10),
    server.WithFIB(fib.NewNetlink(unix.RT_TABLE_MAIN)), // or your own FIB / WatchEvent
)
go s.Serve(ctx)
```

Plug in your own `fib.FIB` or `server.Metrics` for a custom dataplane or
telemetry pipeline. See the [library guide](docs/library.md) and
[`examples/watchroutes`](examples/watchroutes).

## Development

```console
$ make build test lint
$ make proto      # regenerate gen/ from proto/
```

See [CLAUDE.md](CLAUDE.md) for architecture and contributor notes. FRR interop
(`test/interop`) needs docker + root and runs in CI.

## License

Apache-2.0
