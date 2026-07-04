# goisis

Go で書かれた IS-IS ルーティングプロトコル実装 —
[GoBGP](https://github.com/osrg/gobgp) の IS-IS 版です。**ライブラリファースト**で、
`pkg/server.IsisServer` で組み込めます。`goisisd` は薄いデーモン、`goisis` は
[Connect RPC](https://connectrpc.com/) 越しの CLI です。

[English](README.md) · [はじめに](docs/getting-started.ja.md) · [設定](docs/configuration.ja.md) · [ライブラリ](docs/library.ja.md) · [設計](docs/design.ja.md)

## 機能

- デュアルスタック(IPv4/IPv6)L1/L2 ルーティング — ワイドメトリック、レベル別 SPF、ECMP、オーバーロードビット、netlink FIB
- SRv6 locator(RFC 9352)と Flexible Algorithm(RFC 9350)
- Connect RPC API + CLI、`WatchEvent` ストリーミング
- hello と LSP/SNP の HMAC 認証(RFC 5304/5310)
- Prometheus メトリクス、FRR との常時相互運用

> L2 シングルエリアの MVP。マルチトポロジ・graceful restart・BFD は見送り。

## インストール

```console
$ go install github.com/takehaya/goisis/cmd/goisisd@latest
$ go install github.com/takehaya/goisis/cmd/goisis@latest
```

`goisisd` は `CAP_NET_RAW`(AF_PACKET)と `CAP_NET_ADMIN`(FIB)が必要です。root で
実行するか、`setcap cap_net_raw,cap_net_admin+ep` で付与してください。

## クイックスタート

```console
$ sudo goisisd -f examples/goisisd.yaml   # デーモン起動
$ goisis neighbor                         # 他に: database, route, locator, flex-algo, monitor
```

最小限の `goisisd.yaml`:

```yaml
net: 49.0001.0000.0000.0001.00   # エリア + システム ID(NSEL は 00)
fib: true
circuits:
  - interface: eth0
    level: "12"
prefixes:
  - 10.1.1.1/32
```

2 ノード構成の手順は[はじめに](docs/getting-started.ja.md)に、SRv6・Flex-Algo・
認証・経路ポリシーは [`examples/goisisd.yaml`](examples/goisisd.yaml) と
[設定リファレンス](docs/configuration.ja.md)にあります。

## ライブラリとしての利用

```go
s, _ := server.NewIsisServer(
    server.WithSystemID(sysID),
    server.WithAreaAddresses(area),
    server.WithCircuit(server.CircuitConfig{Name: "eth0", Transport: tr, Level2: true}),
    server.WithAdvertisedPrefix(prefix, 10),
    server.WithFIB(fib.NewNetlink(unix.RT_TABLE_MAIN)), // 独自 FIB や WatchEvent でも可
)
go s.Serve(ctx)
```

独自の `fib.FIB` や `server.Metrics` を渡せば、独自データプレーンやテレメトリ基盤に
組み込めます。[ライブラリガイド](docs/library.ja.md)と
[`examples/watchroutes`](examples/watchroutes) を参照してください。

## 開発

```console
$ make build test lint
$ make proto      # proto/ から gen/ を再生成
```

アーキテクチャと貢献メモは [CLAUDE.md](CLAUDE.md) を参照。FRR 相互運用
(`test/interop`)は docker + root が必要で CI で実行されます。

## ライセンス

Apache-2.0
