# 設定リファレンス

`goisisd -f <file>` は YAML 設定を読み込み、サーバオプションへ変換します。
([English](configuration.md))

## トップレベルのキー

| キー | 型 | 説明 |
|-----|------|-------------|
| `net` | string(必須) | Network Entity Title: エリアアドレス + 6 オクテットのシステム ID。末尾オクテット(NSEL)は `00` であること。例: `49.0001.0000.0000.0001.00`。 |
| `hostname` | string | LSP で広報する動的ホスト名(RFC 5301)。 |
| `fib` | bool | 計算した経路を `proto isis` タグでカーネル FIB に書き込む。`CAP_NET_ADMIN` が必要。デフォルト `false`(コントロールプレーンのみ)。 |
| `fib-table` | int | `fib` 有効時に経路を書き込むルーティングテーブル。デフォルト `254`(main)。 |
| `overload-on-startup` | duration | 起動後この時間だけオーバーロードビットを立て、その後解除する(例 `30s`)。立っている間、ピアはこのノードを経由する中継トラフィックを流さない。 |
| `lsp-mtu` | int | このノードが生成する LSP の最大サイズ。デフォルトは最小のサーキット MTU から LLC ヘッダを引いた値(上限 1492)。 |
| `lsdb-entry-limit` | int | レベルごとに保持する LSP 数の上限。LSDB の枯渇に対する防御で、エリア本来の LSP 数より十分大きく取る。デフォルト `0`(上限なし)。 |
| `area-password` | string | Level-1 の LSP/SNP をこの鍵で認証。 |
| `area-accept-passwords` | string のリスト | 受信した Level-1 LSP/SNP で追加で受け付ける鍵(アルゴリズムと鍵 ID は同じ)。署名には使わない。[鍵のローテーション](#鍵のローテーション)を参照。 |
| `area-auth-algorithm` | string | `md5`(デフォルト、RFC 5304、FRR の `area-password md5`)/ `sha1`/`sha256`/`sha384`/`sha512`(RFC 5310)。 |
| `area-key-id` | uint16 | RFC 5310 の鍵 ID(SHA のみ)。 |
| `domain-password` / `domain-accept-passwords` / `domain-auth-algorithm` / `domain-key-id` | | Level-2 用に同じ。 |

> FRR の IS-IS 認証は HMAC-MD5 のみなので、SHA 系(RFC 5310)は FRR とではなく
> goisis 同士で相互運用します。
| `circuits` | list(必須) | IS-IS を動かすインターフェース。下記参照。 |
| `prefixes` | list | 追加で広報する prefix。各要素は CIDR 文字列(`10.1.1.1/32`、メトリック 10)か、マッピング `{prefix: 10.1.1.1/32, metric: 20}`。サーキットの接続サブネットは自動で広報される。 |
| `srv6` | object | SRv6 locator。下記参照。 |
| `flex-algo` | list | Flexible Algorithm 定義。下記参照。 |
| `policy` | object | 広報と FIB 書き込みを制御する prefix-list。[`policy`](#policy) を参照。 |

## `circuits[]`

| キー | 型 | 説明 |
|-----|------|-------------|
| `interface` | string(必須) | インターフェース名(AF_PACKET)。 |
| `level` | string | `"1"` / `"2"` / `"12"`(デフォルト `"12"`)。 |
| `p2p` | bool | ブロードキャスト/DIS の代わりにポイントツーポイント手順(RFC 5303 three-way)。 |
| `priority` | uint8 | LAN での DIS 選出プライオリティ、0–127(デフォルト 64)。 |
| `metric` | uint32 | サーキットのワイドメトリック(デフォルト 10)。 |
| `hello-interval` | duration | hello の送出間隔。例 `1s`、`500ms`(デフォルト `3s`)。 |
| `hold-multiplier` | int | 広報する holding time は `hello-interval x hold-multiplier`(デフォルト 10)。 |
| `padding` | bool | MTU 不一致を検出するため hello を MTU までパディングする(ISO 10589、デフォルト `true`)。 |
| `hello-password` | string | HMAC による hello 認証を有効化。hello はこの鍵で署名され、受信 hello は一致する digest を持たないと破棄される。 |
| `hello-auth-algorithm` | string | `md5`(デフォルト、RFC 5304、FRR の `isis password md5`)/ HMAC-SHA 系(RFC 5310)。 |
| `hello-accept-passwords` | string のリスト | 受信 hello で追加で受け付ける鍵。署名には使わない。[鍵のローテーション](#鍵のローテーション)を参照。 |
| `hello-key-id` | uint16 | RFC 5310 の鍵 ID(SHA のみ)。 |

インターフェースに設定された IPv4 アドレスとリンクローカル IPv6 アドレスは
hello(TLV 132/232)で広報され、ネクストホップに使われます。その接続サブネットは
自動で広報されます(カーネルの接続経路を上書きすることはありません)。

## 鍵のローテーション

ノードは 1 つの鍵で署名し、複数の鍵を受け入れます。これにより一斉切り替えなしに鍵を
更新できます。1. 新しい鍵を全ノードの `*-accept-passwords` に追加する。2. `*-password`
をノードごとに新しい鍵へ切り替える。3. 全ノードが新しい鍵で署名するようになったら、
accept のリストから古い鍵を削除する。

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

各隣接には locator ごとに End.X SID も割り当てます。値は locator の function 空間の 1 番から取り、
隣接の IS reachability エントリに載せます(RFC 9352 §8)。`fib: true` なら各 End.X SID は
その隣接向けの `seg6local` End.X 経路になります。設定項目はありません。

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

## `policy`

IS-IS はエリアごとに 1 つの一貫した LSDB をフラッディングするため、フラッディング
されるリンクステートにはポリシーがありません(フィルタすると収束が壊れる)。
ポリシーは境界にのみ、prefix-list として適用します:

```yaml
policy:
  advertise:          # このノードが LSP に載せる prefix
    default: permit
    rules:
      - deny: 10.0.0.0/8
        le: 32
  fib:                # FIB に入れる計算経路
    default: permit
    rules:
      - deny: 0.0.0.0/0
        le: 32        # コントロールプレーンのみ:RIB には残しカーネルには入れない
```

| キー | 型 | 説明 |
|-----|------|-------------|
| `advertise` | prefix-list | export ポリシー:広報する prefix(TLV 135/236)。 |
| `fib` | prefix-list | FIB ポリシー:フォワーディングプレーンに入れる経路。拒否分も RIB には残り `ListRoutes`/`WatchEvent` で見える。 |
| `<list>.default` | string | `deny`(デフォルト)/ `permit`。どのルールにもマッチしないときに適用。 |
| `<list>.rules[]` | list | 順序付き。最初のマッチが勝つ。各ルールは `permit:`/`deny:` の CIDR + 任意の `ge`/`le` 長範囲。 |

ルールは、その CIDR に含まれ長さが `[ge, le]` の prefix にマッチします(両方省略で
完全長一致)。フラッディングされる LSDB には一切影響しません。トポロジ別 /
アルゴリズム別の独立 RIB(BGP の複数テーブルに相当)が欲しい場合はフィルタでなく
Flexible Algorithm を使ってください。

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
`global` / `circuit` / `neighbor` / `database` / `route` / `prefix` /
`overload` / `locator` / `flex-algo` / `monitor`(`WatchEvent` をストリーミング。
`--initial` を付けると変化を追う前に現在の隣接と経路を出力)。

`-o json` を付けると、一覧・表示系コマンドは表の代わりに RPC のレスポンスを
JSON で出力します(スクリプトや `jq` 向け)。`goisis database --detail` は各 LSP
の行の下にその TLV を並べるので、パケットキャプチャなしで対向の広告内容を読めます。

`--addr` は `unix:///絶対パス` も取り、`goisisd -api-listen
unix:///run/goisis/goisisd.sock` で起動したデーモンに接続します。API は無認証
なので、共有ホストでは unix ソケットが最も手軽な保護手段です。ソケットはモード
`0660` で作られ、接続できる範囲はその置き場所のディレクトリで決まります。

`prefix` / `overload` / `neighbor clear` / `locator` / `flex-algo` は実行時に
デーモンを再構成もできます:

```console
$ goisis flex-algo add 128 --priority 100 --advertise
$ goisis locator add fc00:0:128::/48 --algo 128
$ goisis locator delete fc00:0:128::/48
$ goisis flex-algo delete 128
$ goisis prefix add 10.9.9.0/24 --metric 10   # 削除は goisis prefix delete 10.9.9.0/24
$ goisis overload on                          # 保守用。"off" で解除
$ goisis neighbor clear --interface eth0      # --system-id で 1 隣接のみ
```

## メトリクス

`goisisd` は `/metrics` で Prometheus メトリクスを公開します:
`goisis_adjacency_transitions_total` / `goisis_spf_duration_seconds` /
`goisis_lsdb_lsps` / `goisis_flooding_lsp_tx_total` /
`goisis_pdu_rx_total{circuit,type}` / `goisis_pdu_drops_total{circuit,reason}`
(reason は `decode` / `auth` / `no_adjacency` / `checksum` / `lsdb_limit` /
`unknown_purge` / `own_sysid_purge`, `own_lsp_reclaimed`) / `goisis_adjacencies{circuit,level}` /
`goisis_routes{level,algorithm}` / `goisis_fib_errors_total{op}` (op は
`update` / `withdraw` / `add_sid` / `remove_sid`) / `goisis_event_queue_depth`。
