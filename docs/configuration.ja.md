# 設定リファレンス

`goisisd -f <file>` は YAML 設定を読み込み、サーバオプションへ変換します。
([English](configuration.md))

## トップレベルのキー

| キー | 型 | 説明 |
|-----|------|-------------|
| `net` | string(必須) | Network Entity Title: エリアアドレス + 6 オクテットのシステム ID。末尾オクテット(NSEL)は `00` であること。例: `49.0001.0000.0000.0001.00`。 |
| `hostname` | string | LSP で広報する動的ホスト名(RFC 5301)。 |
| `fib` | bool | 計算した経路を `proto isis` タグでカーネル FIB に書き込む。`CAP_NET_ADMIN` が必要。デフォルト `false`(コントロールプレーンのみ)。 |
| `overload-on-startup` | duration | 起動後この時間だけオーバーロードビットを立て、その後解除する(例 `30s`)。立っている間、ピアはこのノードを経由する中継トラフィックを流さない。 |
| `circuits` | list(必須) | IS-IS を動かすインターフェース。下記参照。 |
| `prefixes` | CIDR のリスト | 追加で広報する prefix。サーキットの接続サブネットは自動で広報される。 |
| `srv6` | object | SRv6 locator。下記参照。 |
| `flex-algo` | list | Flexible Algorithm 定義。下記参照。 |

## `circuits[]`

| キー | 型 | 説明 |
|-----|------|-------------|
| `interface` | string(必須) | インターフェース名(AF_PACKET)。 |
| `level` | string | `"1"` / `"2"` / `"12"`(デフォルト `"12"`)。 |
| `p2p` | bool | ブロードキャスト/DIS の代わりにポイントツーポイント手順(RFC 5303 three-way)。 |
| `priority` | uint8 | LAN での DIS 選出プライオリティ、0–127(デフォルト 64)。 |
| `metric` | uint32 | サーキットのワイドメトリック(デフォルト 10)。 |
| `hello-password` | string | HMAC-MD5 による hello 認証(RFC 5304)を有効化。hello はこの鍵で署名され、受信 hello は一致する digest を持たないと破棄される。FRR の `isis password md5` と相互運用可能。 |

インターフェースに設定された IPv4 アドレスとリンクローカル IPv6 アドレスは
hello(TLV 132/232)で広報され、ネクストホップに使われます。その接続サブネットは
自動で広報されます(カーネルの接続経路を上書きすることはありません)。

## `srv6`

```yaml
srv6:
  locators:
    - fc00:0:1::/48
```

各 locator は SRv6 Locator TLV(27)で広報され、locator のベースアドレスに End SID を、
Router Capability TLV(242)に SRv6 Capabilities sub-TLV を載せます。TLV 27 を解さない
ピア向けに IPv6 到達性(TLV 236)へもミラーされます。`fib: true` のとき End SID は
`seg6local` End ルートとして設置されます。

Flexible Algorithm に紐づく locator はここではなく `flex-algo` 配下の `locator` で
設定します(下記)。`srv6.locators` はアルゴリズム 0 の locator です。

## `flex-algo[]`

```yaml
flex-algo:
  - algo: 128
    metric-type: igp     # igp(デフォルト)/ delay / te
    priority: 100
    advertise: true
    locator: fc00:0:128::/48
```

| キー | 型 | 説明 |
|-----|------|-------------|
| `algo` | uint8(必須) | Flexible Algorithm 番号、128–255。 |
| `metric-type` | string | `igp`(デフォルト)/ `delay` / `te`。goisis は IGP メトリックのみ計算し、他はピアと定義・選出を合わせるために広報のみ。 |
| `priority` | uint8 | 選出プライオリティ(大きいほど勝ち、同値はシステム ID が大きい方)。 |
| `advertise` | bool | 参加だけでなく定義(FAD)も広報する。エリア内の少なくとも 1 ノードが広報する必要がある。 |
| `locator` | CIDR | このアルゴリズムに紐づく SRv6 locator(任意)。経路はそのアルゴリズムの prune 済みトポロジで計算される。 |

ノードは列挙した各アルゴリズムに参加します(SR-Algorithm sub-TLV 19 で広報)。
参加していないアルゴリズムに紐づく locator は到達不能になるため、起動時に拒否されます。

## ケーパビリティ

`goisisd` は `CAP_NET_RAW`(AF_PACKET)を、`fib: true` のとき `CAP_NET_ADMIN` を
必要とします:

```console
$ sudo setcap cap_net_raw,cap_net_admin+ep goisisd
```

同梱の [`packaging/goisisd.service`](../packaging/goisisd.service) はこれらだけを
ambient capability として付与します。

## CLI

CLI `goisis`(`--addr`、デフォルト `http://127.0.0.1:50051`)のサブコマンド:
`global` / `circuit` / `neighbor` / `database` / `route` / `locator` /
`flex-algo` / `monitor`(`WatchEvent` をストリーミング)。

## メトリクス

`goisisd` は `/metrics` で Prometheus メトリクスを公開します:
`goisis_adjacency_transitions_total` / `goisis_spf_duration_seconds` /
`goisis_lsdb_lsps` / `goisis_flooding_lsp_tx_total`。
