# goisis

Go で書かれた IS-IS ルーティングプロトコル実装 —
[GoBGP](https://github.com/osrg/gobgp) の IS-IS 版を目指しています。

[English README](README.md) · [はじめに](docs/getting-started.ja.md) · [設定リファレンス](docs/configuration.ja.md) · [ライブラリガイド](docs/library.ja.md)

goisis は **ライブラリファースト** です。`pkg/server.IsisServer` で自分の Go
プログラムに IS-IS インスタンスを組み込めて、デーモン `goisisd` はその薄い
ラッパーにすぎません。CLI `goisis` は
[Connect RPC](https://connectrpc.com/)(gRPC / gRPC-Web / Connect を 1 ポートで)
でデーモンと会話します。

## 機能

- **デュアルスタック IGP** — IPv4 / IPv6、ワイドメトリック、レベル別 SPF、
  ECMP、オーバーロードビット、netlink によるカーネル FIB(`proto isis`)書き込み
- **L1/L2** シングルエリアルーティング(DIS 選出のある LAN、ポイントツーポイント)
- **SRv6 locator**(RFC 9352)— SRv6 Locator TLV と、ローカル End SID の
  `seg6local` ルート設置、レガシー相互運用向けの TLV 236 ミラー
- **Flexible Algorithm**(RFC 9350)— FAD 広報、勝者選出、prune したトポロジ上での
  アルゴリズム別 SPF(IGP メトリック)
- **Connect RPC API + CLI** — サーキット / 隣接 / LSDB / 経路 / SRv6 locator /
  Flex-Algo 状態の参照、`WatchEvent` による変更ストリーミング
- **HMAC 認証** — hello と LSP/SNP の両方。HMAC-MD5(RFC 5304、FRR の
  `isis password`/`area-password`/`domain-password md5` と相互運用可能)と
  HMAC-SHA-1/256/384/512(RFC 5310)
- **Prometheus メトリクス**(`/metrics`)
- **FRR との常時相互運用** — 全 PR でコンテナトポロジを FRR isisd 相手に実行

> スコープは L2 シングルエリアの MVP です。マルチトポロジ(RFC 5120)、
> graceful restart(RFC 5306)、BFD 連携は見送り。ナローメトリックは受信パースのみで
> 生成はしません。

## インストール

```console
$ go install github.com/takehaya/goisis/cmd/goisisd@latest
$ go install github.com/takehaya/goisis/cmd/goisis@latest
```

ソースからビルドする場合:

```console
$ git clone https://github.com/takehaya/goisis && cd goisis
$ make bin            # bin/goisisd と bin/goisis を生成
```

`goisisd` は AF_PACKET ソケットを開くため `CAP_NET_RAW` を、FIB を書き込むため
`CAP_NET_ADMIN` を必要とします:

```console
$ sudo setcap cap_net_raw,cap_net_admin+ep bin/goisisd
```

## クイックスタート

```console
$ sudo goisisd -f examples/goisisd.yaml      # デーモン起動
$ goisis neighbor                            # 隣接
$ goisis database                            # リンクステートデータベース
$ goisis route                               # 計算済み経路(ALGO 列付き)
$ goisis locator                             # 広報中の SRv6 locator
$ goisis flex-algo                           # Flex-Algo 定義 / 参加ノード
$ goisis monitor                             # 隣接 / 経路変更のストリーミング
```

API は `grpcurl` / `buf curl` からも叩けます(gRPC reflection と health は有効)。
メトリクスは `http://127.0.0.1:50051/metrics` で取得できます。

## 設定

最小限の `goisisd.yaml`:

```yaml
net: 49.0001.0000.0000.0001.00   # エリアアドレス + システム ID(NSEL は 00)
hostname: r1
fib: true                        # カーネル FIB に書き込む(CAP_NET_ADMIN が必要)
circuits:
  - interface: eth0
    level: "12"                  # "1" / "2" / "12"
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

全オプションは [`examples/goisisd.yaml`](examples/goisisd.yaml) を、詳細は
[設定リファレンス](docs/configuration.ja.md) を参照してください。systemd ユニットは
[`packaging/goisisd.service`](packaging/goisisd.service) にあります。

## ライブラリとしての利用

```go
s, err := server.NewIsisServer(
    server.WithSystemID(sysID),
    server.WithAreaAddresses(area),
    server.WithCircuit(server.CircuitConfig{Name: "eth0", Transport: tr, Level2: true}),
    server.WithAdvertisedPrefix(prefix, 10),
    server.WithFIB(fib.NewNetlink(unix.RT_TABLE_MAIN)), // 独自 FIB や WatchEvent でも可
)
if err != nil { log.Fatal(err) }
go s.Serve(ctx)
```

独自の `fib.FIB` や `server.Metrics` 実装を渡せば、goisis を独自データプレーンや
テレメトリ基盤に組み込めます。[`examples/watchroutes`](examples/watchroutes) は
カーネルへ書く代わりに経路変更へ反応する例で、eBPF データプレーンへ流す際の
パターンです。組み込み API の詳細は [ライブラリガイド](docs/library.ja.md) に
あります。

## 開発

```console
$ mise install               # 固定された Go ツールチェーン(mise.toml)
$ make install-dev-tools     # golangci-lint, lefthook
$ make build test lint
$ make proto                 # proto/ から gen/ を再生成(tools.mod 経由の buf)
```

FRR 相互運用と golden フィクスチャ採取(`test/interop`、`test/fixturegen`)は
`docker` と root が必要で、CI で実行されます。アーキテクチャと貢献メモは
[CLAUDE.md](CLAUDE.md) を参照してください。

## ライセンス

Apache-2.0
