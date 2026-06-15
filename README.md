# goisis

IS-IS routing protocol implementation in Go — aiming to be the IS-IS counterpart of [GoBGP](https://github.com/osrg/gobgp).

> **Status: early development.** Nothing here speaks IS-IS yet; the protocol implementation lands milestone by milestone.

## Goals

- **Library first**: embed an IS-IS instance in your Go program (`pkg/server.IsisServer`), the daemon is a thin wrapper
- **`goisisd` + `goisis`**: a daemon and a CLI talking [Connect RPC](https://connectrpc.com/) (gRPC/gRPC-Web/Connect on one port)
- **IGP prefix advertisement** (IPv4/IPv6 dual stack, wide metrics only)
- **SRv6**: locator advertisement per RFC 9352
- **Flex-Algo**: FAD advertisement and per-algorithm SPF over the LSDB per RFC 9350
- **Continuous interop with FRR**: every PR runs containerlab topologies against FRR isisd

## Non-goals (for now)

Multi-topology (RFC 5120), graceful restart (RFC 5306), and BFD integration are explicitly deferred. Narrow metrics are parsed but never originated.

## Development

```console
$ mise install          # Go toolchain (see mise.toml)
$ make install-dev-tools
$ make build test lint
```

Protobuf codegen is reproducible offline: plugins are pinned via `go.mod` tool directives and driven by `go tool buf generate` (`make proto`).

## Running

```console
$ sudo goisisd -f examples/goisisd.yaml      # the daemon (needs CAP_NET_RAW, +CAP_NET_ADMIN for the FIB)
$ goisis neighbor                            # adjacencies
$ goisis database                            # the link-state database
$ goisis route                               # computed routes
$ goisis monitor                             # stream adjacency/route changes
```

The daemon exposes a [Connect RPC](https://connectrpc.com/) API (Connect,
gRPC, and gRPC-Web on one port), so `grpcurl` and `buf curl` work against it
too. To embed goisis as a library and consume routes directly (e.g. to program
an eBPF dataplane), see [`examples/watchroutes`](examples/watchroutes).

## Naming

This project is unrelated to [choppsv1/goisis](https://github.com/choppsv1/goisis). The module path is `github.com/takehaya/goisis`.

## License

Apache-2.0
