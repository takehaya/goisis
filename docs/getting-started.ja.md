# はじめに

ハンズオン形式のツアーです。2 ノードの IS-IS ネットワークを立ち上げ、goisis を
ライブラリとして組み込み、主要機能を試し、FRR と相互接続します。
([English](getting-started.md))

あわせて[設定リファレンス](configuration.ja.md)と
[ライブラリガイド](library.ja.md)も参照してください。

## 前提

- ソースからビルドするなら Go(バージョンは `go.mod` 参照)、またはリリースを取得。
- デーモンは Linux 専用(AF_PACKET ソケットと netlink FIB)。ライブラリとユニット
  テストは Go が動く環境ならどこでも。
- 下記の network namespace 手順に `iproute2`、FRR 相互接続の節にのみ Docker。

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

`goisisd` は AF_PACKET ソケット(`CAP_NET_RAW`)を開き、FIB(`CAP_NET_ADMIN`)を
書きます。root で実行するか、`setcap` で権限を付与するか、下記のように
network namespace 内(その中では root)で実行します。

```console
$ sudo setcap cap_net_raw,cap_net_admin+ep bin/goisisd
```

## 1. ゼロから 2 ノードネットワーク

veth ペアで背中合わせに繋いだ 2 台のルータを、2 つの network namespace で構築
します — 実機もコンテナも不要。namespace 内ではすべて root で動くので `setcap`
も不要です。

### namespace を配線

```console
$ sudo ip netns add ns1
$ sudo ip netns add ns2
$ sudo ip link add veth1 netns ns1 type veth peer name veth2 netns ns2

# ns1: リンク側 10.0.0.1、広報用ループバック 10.1.1.1/32
$ sudo ip netns exec ns1 sh -c '
    ip addr add 10.0.0.1/24 dev veth1
    ip addr add 10.1.1.1/32 dev lo
    ip link set veth1 up; ip link set lo up'

# ns2: リンク側 10.0.0.2、広報用ループバック 10.2.2.2/32
$ sudo ip netns exec ns2 sh -c '
    ip addr add 10.0.0.2/24 dev veth2
    ip addr add 10.2.2.2/32 dev lo
    ip link set veth2 up; ip link set lo up'
```

### デーモンを設定して起動

`r1.yaml`:

```yaml
net: 49.0001.0000.0000.0001.00   # エリア 49.0001、システム ID ...0001
hostname: r1
fib: true
circuits:
  - interface: veth1
    level: "2"
prefixes:
  - 10.1.1.1/32
```

`r2.yaml` はシステム ID を `...0002`、`veth2`、`10.2.2.2/32` にした同じ内容。

```console
$ sudo ip netns exec ns1 goisisd -f r1.yaml &
$ sudo ip netns exec ns2 goisisd -f r2.yaml &
```

### 収束を確認

`goisis` CLI は同じ namespace 内のデーモンに接続します。

```console
$ sudo ip netns exec ns1 goisis neighbor
SYSTEM-ID       INTERFACE  LEVEL  STATE  SNPA            HOLD
0000.0000.0002  veth1      L2     Up     b209.c4e9.0791  30

$ sudo ip netns exec ns1 goisis database
LSP-ID                LEVEL  SEQ         LIFETIME  CHECKSUM  OWN
0000.0000.0001.00-00  L2     0x00000002  1160      0x571a    *
0000.0000.0001.01-00  L2     0x00000001  1160      0x903b    *
0000.0000.0002.00-00  L2     0x00000002  1164      0xd09b

$ sudo ip netns exec ns1 goisis route
PREFIX       LEVEL  ALGO  METRIC  NEXT-HOPS
10.2.2.2/32  L2     0     20      10.0.0.2 (veth1)

$ sudo ip netns exec ns1 ip route show proto isis
10.2.2.2 via 10.0.0.2 dev veth1

$ sudo ip netns exec ns1 ping -c2 10.2.2.2
64 bytes from 10.2.2.2: icmp_seq=1 ttl=64 time=0.027 ms
64 bytes from 10.2.2.2: icmp_seq=2 ttl=64 time=0.020 ms
```

`goisis monitor` は隣接・経路の変化をストリーミングします(別端末で `veth1` を
フラップさせながら見ると分かりやすい)。

### 後始末

```console
$ sudo ip netns del ns1; sudo ip netns del ns2   # デーモンも停止する
```

## 2. ライブラリとして組み込む

goisis はライブラリファーストで、`pkg/server.IsisServer` が制御プレーン本体、
フォワーディングは利用者が持ちます。最小の組み込みはカーネルに書く代わりに
経路変更へ反応する形で、eBPF データプレーンへ流す際のパターンです。

```go
package main

import (
	"context"
	"log"

	"github.com/takehaya/goisis/pkg/packet"
	"github.com/takehaya/goisis/pkg/server"
	"golang.org/x/sys/unix"
)

func main() {
	tr, err := /* datalink.OpenLinux("eth0") */ openTransport()
	if err != nil {
		log.Fatal(err)
	}
	s, err := server.NewIsisServer(
		server.WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		server.WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		server.WithCircuit(server.CircuitConfig{Name: "eth0", Transport: tr, Level2: true}),
		server.WithAdvertisedPrefix(netipMustPrefix("10.1.1.1/32"), 10),
		// WithFIB を渡さない: コントロールプレーンのみ、経路は自分で処理。
	)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	go s.Serve(ctx)

	sub, err := s.Subscribe(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer sub.Unsubscribe()
	for ev := range sub.Events {
		switch {
		case ev.Route != nil && !ev.Withdrawn:
			log.Printf("route + %s via %v", ev.Route.Prefix, ev.Route.NextHops)
		case ev.Route != nil && ev.Withdrawn:
			log.Printf("route - %s", ev.Route.Prefix)
		case ev.Adjacency != nil:
			log.Printf("adj %s %s", ev.Adjacency.SystemID, ev.Adjacency.State)
		}
	}
	_ = unix.RT_TABLE_MAIN // カーネルに書くなら WithFIB(fib.NewNetlink(...)) を使う
}
```

動く版は [`examples/watchroutes`](../examples/watchroutes) にあります。カーネルに
書くなら `server.WithFIB(fib.NewNetlink(unix.RT_TABLE_MAIN))` を渡します。
全オプション・独自 FIB・メトリクスは[ライブラリガイド](library.ja.md)に。

## 3. 主要機能ツアー

いずれもデーモンの YAML 例ですが、ライブラリには対応する `With…` オプションが
あります([ライブラリガイド](library.ja.md))。

### SRv6 locator(RFC 9352)

```yaml
srv6:
  locators:
    - fc00:0:1::/48
```

SRv6 Locator TLV で広報し、base アドレスにローカル End SID を置きます。
`fib: true` ならその End SID は `seg6local` ルートとして設置されます。
`goisis locator` で一覧。

### Flexible Algorithm(RFC 9350)

```yaml
flex-algo:
  - algo: 128
    metric-type: igp
    priority: 100
    advertise: true
    locator: fc00:0:128::/48   # algo 128 のトポロジで計算される locator
```

`goisis flex-algo` で勝者定義と参加ノードを表示。Flex-Algo はアルゴリズム別の
「独立 RIB」を得る IGP 的な手段でもあります。

### 経路ポリシー(フィルタ)

IS-IS はフラッディングされる LSDB をフィルタしません(エリアが壊れる)。
ポリシーは境界にのみ、prefix-list として適用します:

```yaml
policy:
  fib:                # どの計算経路をカーネルに入れるか
    default: permit
    rules:
      - deny: 0.0.0.0/0
        le: 32        # コントロールプレーンのみ:RIB には残しカーネルには入れない
```

`advertise` は広報する prefix、`fib` は FIB に入れる経路を制御します。拒否された
`fib` 経路も RIB には残ります(`goisis route` / `WatchEvent` で見える)。
[設定リファレンス](configuration.ja.md#policy)参照。

### 認証(RFC 5304 / 5310)

```yaml
area-password: s3cret          # Level-1 LSP/SNP の HMAC-MD5(FRR と相互運用可)
domain-password: s3cret        # ... Level-2
# area-auth-algorithm: sha256  # MD5 でなく HMAC-SHA(RFC 5310)
circuits:
  - interface: veth1
    hello-password: s3cret     # hello の HMAC-MD5
```

## 4. FRR との相互接続

goisis は FRR の isisd と相互運用できます。ポイントツーポイントリンクの最小
`/etc/frr/frr.conf`:

```
hostname frr1
!
interface eth0
 ip router isis 1
 isis network point-to-point
!
router isis 1
 net 49.0001.0000.0000.00ff.00
 is-type level-2-only
```

リンクの反対側に goisis を `p2p: true` で向けます:

```yaml
net: 49.0001.0000.0000.0001.00
circuits:
  - interface: eth0
    level: "2"
    p2p: true
prefixes:
  - 10.1.1.1/32
```

双方向で隣接が上がり経路が交換されます。goisis は FRR 10.6.1 と常時テストされて
います — 完全なコンテナトポロジ(LAN/p2p 隣接、LSDB 同期、経路、SRv6、Flex-Algo、
認証)は [`test/interop`](../test/interop) を参照。なお FRR の IS-IS 認証は MD5 のみ
なので、HMAC-SHA は goisis 同士で検証しています。

## 次のステップ

- [設定リファレンス](configuration.ja.md) — 全 YAML キー。
- [ライブラリガイド](library.ja.md) — 組み込み、独自 FIB、メトリクス、実行時再構成。
- [`examples/watchroutes`](../examples/watchroutes) — 動くライブラリ利用例。
- `CLAUDE.md` — アーキテクチャと貢献メモ。
