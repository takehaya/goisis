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

## Naming

This project is unrelated to [choppsv1/goisis](https://github.com/choppsv1/goisis). The module path is `github.com/takehaya/goisis`.

## License

Apache-2.0
