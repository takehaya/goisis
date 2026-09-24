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
| `circuits` | list(必須) | IS-IS を動かすインターフェース。下記参照。 |
| `prefixes` | list | 追加で広報する prefix。各要素は CIDR 文字列(`10.1.1.1/32`、メトリック 10)か、マッピング `{prefix: 10.1.1.1/32, metric: 20}`。サーキットの接続サブネットは自動で広報される。同じサブネットをここに書いても二重広報にはならず、広報時のメトリックだけが決まる。 |
| `srv6` | object | SRv6 locator。下記参照。 |
| `flex-algo` | list | Flexible Algorithm 定義。下記参照。 |
| `policy` | object | 広報・FIB 書き込み・L2→L1 リークを制御する prefix-list。[`policy`](#policy) を参照。 |

再起動が要るもののうち、運用中に繰り返し触るのは `policy` です。prefix-list の
変更はリロードでは反映されません。ランタイムで変えるには管理 API にフィルタの
RPC が要りますが、現状ありません。


> FRR の IS-IS 認証は HMAC-MD5 のみなので、SHA 系(RFC 5310)は FRR とではなく
> goisis 同士で相互運用します。

スキーマにないキーはエラーです。`goisisd` は起動を拒否し、`SIGHUP` はそのファイルを
拒否します。0.4.0 までは未知のキーを黙って捨てていたため、`area-pasword` のように
一文字入れ替わっただけで、そのノードは何の報告もないまま認証なしで動いていました。
**goisisd が定義していないキーを含むファイルは読み込めなくなります**。コメントアウト
するか削除してください。

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
| `adjacency-limit` | int | このサーキットが受け入れる隣接数の上限。上限に達すると、隣接を持たない System ID からの hello は破棄され(`adjacency_limit` として計上)、既存の隣接はそのまま維持される。デフォルト 128、`0` で上限なし。 |
| `hello-password` | string | HMAC による hello 認証を有効化。hello はこの鍵で署名され、受信 hello は一致する digest を持たないと破棄される。 |
| `hello-auth-algorithm` | string | `md5`(デフォルト、RFC 5304、FRR の `isis password md5`)/ HMAC-SHA 系(RFC 5310)。 |
| `hello-accept-passwords` | string のリスト | 受信 hello で追加で受け付ける鍵。署名には使わない。[鍵のローテーション](#鍵のローテーション)を参照。 |
| `hello-key-id` | uint16 | RFC 5310 の鍵 ID(SHA のみ)。 |

インターフェースに設定された IPv4 アドレスとリンクローカル IPv6 アドレスは
hello(TLV 132/232)で広報され、ネクストホップに使われます。グローバル IPv6
アドレスは hello には載せず(RFC 5308 3 が IIH をリンクローカルに限る)、自ノードの
LSP の TLV 232 で広報します。ピアが End.X SID の転送先となる on-link アドレスを
探すのはそこだからです。接続サブネットは自動で広報されます(カーネルの接続経路を
上書きすることはありません)。

## 鍵のローテーション

ノードは 1 つの鍵で署名し、複数の鍵を受け入れます。これにより一斉切り替えなしに鍵を
更新できます。1. 新しい鍵を全ノードの `*-accept-passwords` に追加する。2. `*-password`
をノードごとに新しい鍵へ切り替える。3. 全ノードが新しい鍵で署名するようになったら、
accept のリストから古い鍵を削除する。

対応する `*-password` のない accept リストは設定エラーです。そのスコープは何も署名せず
何も受け付けないため、認証なしで動き出す代わりに goisisd は起動を拒否します。

## `srv6`

```yaml
srv6:
  locators:
    - fc00:0:1::/48
```

各 locator は SRv6 Locator TLV(27)で広報され、locator のベースアドレスに End SID を、
Router Capability TLV(242)に SRv6 Capabilities sub-TLV を載せます。TLV 27 を解さない
ピア向けに IPv6 到達性(TLV 236)へもミラーされます。`fib: true` のとき End SID は
`isis-srv6` 上の `seg6local` End ルートとして設置されます。`isis-srv6` はローカル
SID 用にデーモンが作る dummy デバイスで、最後の SID が消えると削除します
(ループバックを出力デバイスにした `seg6local` 経路は Linux が encap を落とすため)。

隣接には locator ごとに End.X SID も割り当てます。値は locator の function 空間の 1 番から取り、
隣接の IS reachability エントリに載せます(RFC 9352 §8)。`fib: true` なら各 End.X SID は
その隣接向けの `seg6local` End.X 経路になります。設定項目はありません。

ただし**隣接がその回線の connected subnet 内にグローバル IPv6 アドレスを持つこと**が条件です。
アドレスは隣接の fragment 0 LSP の TLV 232 から取ります(goisis も FRR もそこに載せます)。
hello に載せてくるピアがいればそちらも使います。Linux の End.X は次ホップをパケットの入力
インタフェース側で解決するため、link-local を次ホップにすると hairpin 以外は落ちます。
該当アドレスが分からない間は割り当ても広報も FIB 投入もせず、その隣接について
`no on-link global IPv6 address for neighbor` を 1 回だけ記録します。そのため End.X SID が
付かないのは、リンクにリンクローカルしか無い場合だけです。

Flexible Algorithm に紐づく locator はここではなく `flex-algo` 配下の `locator` で
設定します(下記)。`srv6.locators` はアルゴリズム 0 の locator です。そちらの End.X
には追加の条件があります(`flex-algo[].locator` 参照)。

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

End.X SID は取り出し元 locator のアルゴリズムを持ちます(RFC 9352 §8.1)。そのため
アルゴリズムに紐づく locator が End.X を配るのは、**同じアルゴリズム**を自分の
SR-Algorithm sub-TLV に載せている隣接に対してだけです。これは SPF がそのアルゴリズムの
トポロジに隣接を残すかどうかの判定と同じ参加情報です。アルゴリズム外の隣接は
アルゴリズム 0 の End.X はそのまま持ち、Flex-Algo locator からは 1 つも受け取りません。
SID は隣接の fragment 0 LSP がそのアルゴリズムを載せ始めた時点で付き、載せなくなれば
解放されます。

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
  leak-l2-to-l1:      # L1L2 ノードがエリアへリークする Level-2 prefix
    rules:
      - permit: 203.0.113.0/24
```

| キー | 型 | 説明 |
|-----|------|-------------|
| `advertise` | prefix-list | export ポリシー:広報する prefix(TLV 135/236)。自身の prefix に加え、L1L2 ノードが Level-2 LSP へ伝搬する Level-1 prefix にも適用される。 |
| `fib` | prefix-list | FIB ポリシー:フォワーディングプレーンに入れる経路。拒否分も RIB には残り `ListRoutes`/`WatchEvent` で見える。 |
| `leak-l2-to-l1` | prefix-list | リークポリシー:L1L2 ノードが up/down ビット付きで Level-1 LSP に載せる Level-2 prefix。省略すると何もリークしない。 |
| `<list>.default` | string | `deny`(デフォルト)/ `permit`。どのルールにもマッチしないときに適用。 |
| `<list>.rules[]` | list | 順序付き。最初のマッチが勝つ。各ルールは `permit:`/`deny:` の CIDR + 任意の `ge`/`le` 長範囲。 |

ルールは、その CIDR に含まれ長さが `[ge, le]` の prefix にマッチします(両方省略で
完全長一致)。フラッディングされる LSDB には一切影響しません。トポロジ別 /
アルゴリズム別の独立 RIB(BGP の複数テーブルに相当)が欲しい場合はフィルタでなく
Flexible Algorithm を使ってください。

`leak-l2-to-l1` はリークの有効化と対象指定を兼ねます。Level-2 テーブルを丸ごと
各エリアへ流すのは既定値にすべきではないため、このセクションを書くことが
リークするという判断そのものです。エリアが Level-1 で既に到達できる prefix は
リークしません。リーク対象を絞るのはこのリストだけで、`advertise` は自ノードの
prefix と Level-2 へ伝搬する Level-1 prefix を受け持ちます。したがって `advertise` を
ループバックだけの許可リストにしても、リークが黙って空になることはありません。
広報するメトリックは自ノードの Level-2 経路メトリックで、受け取る Level-1 ノードが
自分からの距離をそれに加算します。

## 設定のリロード

`goisisd` は `SIGHUP` で `-f` のファイルを読み直し、ランタイム API で表現できる
差分だけを反映します。それ以外の差分は反映せず、何を無視したかをログに名指し
します。黙って設定の半分だけが効く状態にはなりません:

```console
$ systemctl reload goisisd         # または kill -HUP $(pidof goisisd)
WARN configuration reload: this change needs a restart and was not applied key="circuits: eth1 added"
```

| キー | `SIGHUP` での扱い |
|------|-------------------|
| `prefixes` | 反映。メトリックの変更は取り下げと再広報になります。 |
| `srv6.locators` | 反映。各 locator の End SID も追従します。 |
| `flex-algo` | 反映。定義の変更は削除と再追加で行い、束ねられた locator も一度外して付け直します。 |
| `circuits` | **要再起動**。増減には transport と受信ゴルーチンの生成・破棄が必要で、level・メトリック・タイマ・鍵の変更も同じ作り直しになります。インターフェイスのアドレスとキャリアは実時間で追従するので、どちらも不要です。 |
| `net` | **要再起動**。System ID とエリアアドレスは、このノードが出した全 LSP の identity です。 |
| `hostname` | **要再起動**。自 LSP で広報するため、下にある System ID ごと作り直さずに名前だけ変えることはできません。 |
| `area-*` / `domain-*` のパスワード・アルゴリズム・鍵 ID | **要再起動**。[鍵のローテーション](#鍵のローテーション)により、一斉切り替えではなくローリング再起動で済みます。 |
| `fib` / `fib-table` / `lsp-mtu` / `lsdb-entry-limit` / `overload-on-startup` / `policy` | **要再起動**。 |

パースできないファイル、および再起動なら弾かれるファイルは、デーモンを一切
変えません。最初の呼び出しを出す前に、サーバ自身の検査まで含めてファイル全体を
検証するからです。Flex-Algo の番号範囲と重複、locator のアドレスファミリと束ねる
アルゴリズム、prefix の形とメトリックの上限がそれに当たります。リロードが検査
できないのはソケットが要るもの、つまりインタフェースの存在と MTU が自 LSP を
通すかどうかで、これは再起動が回線を開くときに決まります。リロードは回線のキーを
そもそも適用しないので、失うものはありません。`-f` なしで起動したデーモンへの
`SIGHUP` は致命的にせず無視します。オーバーロードビットはそもそもファイルのキー
ではなく、実行時に `goisis overload on` で設定します。

検証で先回りできないのはノード自身の状態です。比較するのは動作中のファイルと
新しいファイルであってノードではないため、実行時に `goisis` で足した prefix や
locator は見えません。両者が同じものを指すときはファイルが優先で、ノードが
すでに持っているものを同じ値で書いてあるなら、それは衝突ではなくリロードが
その呼び出しに成功した状態です。実行時の変更を永続化する手順もこれです。
`goisis` で足し、同じものをファイルに書けば、次の `SIGHUP` はすでにあるものに
触れないままファイルを採用します。*違う値*で書いた場合は拒否されます。ノードが
持っていない値をファイルが要求しており、prefix・locator・Flexible Algorithm の
いずれにも更新操作がないためです。`goisis` で取り下げるか、動作中の値をファイルに
書いてから、もう一度シグナルを送ってください。

リロードにロールバックはない(全呼び出しの逆操作が要る)ので、拒否された時点で
止まり、そのことをログに出します。ファイルを適用済みとして記録することはしません:

```console
ERROR configuration reload was refused part way; the node is not in the state the file describes; fix the file and send SIGHUP again
```

Flexible Algorithm や locator の変更は取り下げと再広報の組なので、そこで拒否されると
リソースが取り下げられたまま残ることがあります。リロードは baseline を進めないため、
次の `SIGHUP` は変更一式をもう一度出します。ノードが採用しなかったファイルを、
動作中の設定として扱うことはありません。この再送が修復手段です。前回すでに通った
呼び出しは二度目も拒否されるのではなく成功として扱われるので、ファイルを直せば
その次の 1 回でノードはそれを動かします。それでも拒否が報告されるなら、直しきれて
いないものがあるということで(エラーがそのリソースを名指しします)、シグナルを
繰り返すだけでは解決しません。

ファイルは `SIGHUP` のたびに読み直されるので、その所有者とモードは次回起動時では
なく動作中のルーティング状態に対するアクセス制御です。書き込める人は、このノードに
デフォルト経路をエリア全体へ広報させられます。同梱ユニットの `ExecReload=` により
同じ経路が `systemctl reload goisisd` からも届き、polkit は root を渡さずにこれを
許可できます。root 所有・モード `0640` 以下で配置してください。届かないのは認証で、
`area-*` と `domain-*` の鍵はいずれも再起動が必要です。つまり書き込み権限で得られる
のはこのノードが広報する到達性であって、HMAC を無効化する手段ではありません。

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
`--initial` を付けると変化を追う前に現在の隣接と経路を出力)/ `version`。

`-o json` を付けると、一覧・表示系コマンドは表の代わりに RPC のレスポンスを
JSON で出力します(スクリプトや `jq` 向け)。`goisis database --detail` は各 LSP
の行の下にその TLV を並べるので、パケットキャプチャなしで対向の広告内容を読めます。

`database` の `LIFETIME` 列は生成元の値ではなく、このノード自身の値です。受信した
LSP は、MaxAge 未満で届いた場合 MaxAge からエージングされる(RFC 7987、
[メトリクス](#メトリクス)参照)ため、この列が示すのは「このノードがあと何秒
保持するか」です。「この LSP はもうすぐエージアウトするか」に答えられるのは、
`*` の付いた生成元のノードだけです。

`goisisd -api-listen` の既定は `127.0.0.1:50051` で、ホスト外から届くアドレスに
バインドするには `-api-allow-remote` の明示が必要です。`:50051` のようにホスト部
を空にした指定もこれに当たります。空のホストは `0.0.0.0` と同じく全インターフェ
イスにバインドします。

`--addr` は `unix:///絶対パス` も取り、`goisisd -api-listen
unix:///run/goisis/goisisd.sock` で起動したデーモンに接続します。API は無認証
なので、共有ホストでは unix ソケットが最も手軽な保護手段です。ソケットは umask
を掛けて bind するので生成された瞬間からモード `0660` で、接続できる範囲はその
置き場所のディレクトリで決まります。

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

`prefix add` とファイルの `prefixes` は同じものを拒否します。起動できるファイルと
リロードできるファイルを一致させるためです。拒否するのは、そもそも経路にならない
もの、すなわちマルチキャスト、unspecified、リンクローカル、IPv4-mapped の prefix と、
RFC 5305 の到達不能しきい値 (`0xfe000000`) 以上のメトリックです。デフォルトルートは拒否しません。広報自体
は正当な手段で、抑止するなら `policy.advertise` を使います。

`prefix delete` が取り下げられるのは `prefixes` か `prefix add` が広報している
ものだけです。インターフェイスの接続サブネットは、どのインターフェイスで直結して
いるかを示して拒否されます。アドレスを外すか `policy.advertise` で抑止してください。

## メトリクス

`goisisd` は `/metrics` で Prometheus メトリクスを公開します:
`goisis_adjacency_transitions_total{circuit,level,state}` /
`goisis_spf_duration_seconds{level}` / `goisis_lsdb_lsps{level}` /
`goisis_flooding_lsp_tx_total{circuit}` /
`goisis_flooding_lsp_drops_total{circuit,reason}` (reason は `oversize`) /
`goisis_fib_pending` /
`goisis_pdu_rx_total{circuit,type}` / `goisis_pdu_drops_total{circuit,reason}`
(reason は `decode` / `auth` / `link_down` / `no_adjacency` / `checksum` /
`lsdb_limit` / `adjacency_limit` / `hello_invalid` / `hello_mismatch` /
`duplicate_system_id` / `unknown_purge` / `own_sysid_purge` /
`own_fragment_purge` / `own_lsp_reclaimed` / `own_seq_wrap`) /
`goisis_pdu_tx_errors_total{circuit,reason}` (reason は `serialize` / `auth` /
`send`) / `goisis_pdu_rx_errors_total{circuit}` /
`goisis_adjacencies{circuit,level}` / `goisis_routes{level,algorithm}` /
`goisis_fib_errors_total{op}` (op は `update` / `withdraw` / `add_sid` /
`remove_sid`) / `goisis_event_queue_depth` /
`goisis_config_reloads_total{outcome}` (outcome は `applied` / `refused` /
`partial`) / `goisis_lsp_lifetime_floored_total{circuit}` /
`goisis_inter_level_prefixes{direction}` (direction は `l2_to_l1` /
`l1_to_l2`)。

隣接が上がらないときの drop 理由は 3 つに分かれる。`hello_invalid` はこのサーキット
では使えない hello で、ポイントツーポイントに LAN hello が来た (逆も同様)、holding
time が 0、そのサーキットで有効でないレベル、のいずれか。`hello_mismatch` は自分が
属していないネットワークからの hello で、Level 1 でエリアアドレスが一致しないか、
共通レベルがない。`duplicate_system_id` は自分と同じ System ID を使うルータがいる。
どの分岐かは Debug レベルの `drop hello` 行に出る。

送受信エラーはプロトコルの不一致ではなく、サーキットがプロトコルを運べない状態を
示す。いずれも次の tick で再試行し、ログは障害の立ち上がりでしか出さないため、
継続しているかどうかはレートでしか分からない:

```
rate(goisis_pdu_tx_errors_total[5m]) > 0
rate(goisis_pdu_rx_errors_total[5m]) > 0
```

`own_*` の 4 つは「自分の System ID を持つ PDU を受けて再生成または purge した」
記録で、破棄ではない。再起動直後に自分の古いコピーが残っている場合や DIS 交代で
通常発生するため、アラートは除外し、別途監視する。定常的に出ているときは他ノードが
こちらの名前で LSP を出している:

```
rate(goisis_pdu_drops_total{reason!~"own_.*"}[5m]) > 0
rate(goisis_pdu_drops_total{reason=~"own_.*"}[15m]) > 0
```

`oversize` の flood drop は、隣接のデータベースが永久に追いつけない状態を示す。
サーキット MTU を超える LSP は、他ノードの LSP を中継ノードが再フラグメントできない
(ISO 10589 7.3.3) ため送れず、PSNP で要求されるたびに捨て続ける。継続的に出ている
ときは、発信元の LSP MTU を小さくする必要がある:

```
rate(goisis_flooding_lsp_drops_total[5m]) > 0
```

リロードの outcome でアラートすべきは `partial` である。`refused` は誰かが書いた
設定のままノードが動いている状態だが、`partial` はどちらの設定でもない状態で、
以降の信号だけでは元に戻らない:

```
increase(goisis_config_reloads_total{outcome="partial"}[1h]) > 0
```

`goisis_lsp_lifetime_floored_total` は、受信 LSP の remaining lifetime を
RFC 7987 が MaxAge まで引き上げた回数を数える。このフィールドはチェックサムの
対象外かつ認証ハッシュの対象外で、化けた値で LSP が早期にパージされるのを
止めているのがこの下限だが、同時に破損の唯一の症状も消している。再フラッディング
では古い lifetime が来るのが普通なので、1 件の発生は正常である。リンクが値を
書き換えていると分かるのは、1 サーキットのレートを隣接サーキットと比べたときだ。

`goisis_inter_level_prefixes` は、`goisis_routes` が学習した経路数であるのに対し、
このノードがレベル境界をまたいで注入しているプレフィックス数である。
`policy.leak-l2-to-l1` の変更で動くのはこのゲージで、Level-2 のテーブル全体が
Level-1 エリアへ流れ込んでいることを、Level-1 LSP が oversize になる前に示す。
