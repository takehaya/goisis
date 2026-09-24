# ライブラリガイド

goisis は組み込み利用を前提に作られています。`pkg/server.IsisServer` が IS-IS
コントロールプレーンを動かし、フォワーディング(カーネル FIB、eBPF データプレーン、
あるいは単に観測するだけ)は利用側が持ちます。([English](library.md))

## ライフサイクル

```go
s, err := server.NewIsisServer(opts...)   // 設定を検証
if err != nil { return err }
go s.Serve(ctx)                            // ctx がキャンセルされるまで動作
```

`Serve` は全プロトコル状態を所有する唯一の goroutine です。各読み取りメソッドは
このループへ直列化されるため並行呼び出しが安全です。`ctx` をキャンセルすると、
自ノードの LSP を purge し、ローカル SID を削除し、トランスポートを閉じて返ります。

## オプション

| オプション | 用途 |
|--------|---------|
| `WithSystemID(packet.SystemID)` | 6 オクテットのシステム ID(必須)。 |
| `WithAreaAddresses(...packet.AreaAddress)` | NET から得たエリアアドレス。 |
| `WithHostname(string)` | 動的ホスト名(RFC 5301)。 |
| `WithCircuit(CircuitConfig)` | サーキットを追加(下記)。 |
| `WithAdvertisedPrefix(netip.Prefix, metric)` | prefix を広報(TLV 135/236)。 |
| `WithConnectedPrefix(netip.Prefix)` | 接続 prefix として印を付け、FIB へは入れない。 |
| `WithSRv6Locator(netip.Prefix)` | アルゴリズム 0 の SRv6 locator を広報(End SID と、隣接ごとの End.X SID 付き)。 |
| `WithSRv6LocatorForAlgo(netip.Prefix, algo)` | Flex-Algo locator を広報。 |
| `WithFlexAlgo(FlexAlgoConfig)` | Flexible Algorithm に参加 / 定義を広報。 |
| `WithOverloadOnStartup(time.Duration)` | 起動後一定時間だけ OL ビットを立てる。 |
| `WithLSPMTU(int)` | 自ノードが生成する LSP の上限サイズ。0(デフォルト)はサーキット MTU から導出(上限 1492)。512 未満は拒否。 |
| `WithLSDBEntryLimit(int)` | レベルごとに保持する LSP 数の上限(LSDB 枯渇への多層防御)。0(デフォルト)で無制限。 |
| `WithAreaAuth` / `WithDomainAuth(AuthConfig)` | L1 / L2 の LSP・SNP の HMAC 認証。`AuthConfig.AcceptSecrets`(hello では `CircuitConfig.HelloAcceptPasswords`)は受信時のみ追加で受け付ける鍵で、署名には使わないため、鍵をノードごとにローテーションできる。`WithAreaPassword` / `WithDomainPassword(string)` は HMAC-MD5 の簡易版。 |
| `WithFIB(fib.FIB)` | フォワーディングシンク(デフォルト `fib.Noop`)。 |
| `WithAdvertiseFilter(func(AdvertisedPrefix) bool)` | export ポリシー:どの prefix を広報するか。 |
| `WithL2LeakFilter(func(AdvertisedPrefix) bool)` | リークポリシー:L1L2 ノードが up/down ビット付きで Level-1 LSP に載せる Level-2 prefix。省略すると何もリークしない。 |
| `WithFIBFilter(func(RouteInfo) bool)` | FIB ポリシー:どの経路を FIB に入れるか(拒否分は RIB に残る)。 |
| `WithMetrics(server.Metrics)` | テレメトリシンク(デフォルト `NoopMetrics`)。 |
| `WithClock(server.Clock)` | サーバが時刻を読む先(デフォルトは実時刻)。模擬時刻でインスタンスを動かしたいときに渡す。リーダー goroutine の再試行待ちと SPF の実行時間計測は実時刻のまま。 |
| `WithLogger(*slog.Logger)` | 構造化ロガー。 |

`CircuitConfig` は `Name`、注入する `datalink.Transport`(Linux では
`datalink.OpenLinux(ifname)`、テストではモック)、`P2P`、`Level1`/`Level2`、
`Priority`、`Metric`、`HelloInterval`、`HoldingMultiplier`、`Padding`、
`IPv4Addrs`/`IPv6Addrs`(インターフェースの全アドレス。下記参照)、
`ConnectedPrefixes`(サーキットの直結サブネット。
アドレス変更時にサーキットごと取り下げられる)、および hello 認証の鍵
(`HelloPassword`、`HelloAcceptPasswords`、`HelloAuthAlgorithm`、`HelloKeyID`)
を持ちます。

`IPv4Addrs`/`IPv6Addrs` にはインターフェースの全アドレスを渡してください。goisis が
用途ごとに振り分けます。`IPv4Addrs` とリンクローカル IPv6 アドレスは hello
(TLV 132/232)に載り、隣接はこれを自ノード向けのネクストホップに使います。RFC 5308 3
が IIH をリンクローカルに限るため、グローバル IPv6 アドレスは hello からは除かれ、
自ノードの LSP の TLV 232 で広報されます。ピアが End.X SID の転送先となる on-link の
グローバルアドレスを探すのはそこです(リンクローカルでは hairpin しか転送できません)。
実行中の差し替えは `SetCircuitAddresses` で同じ 2 つのリストを渡します。

## 状態の参照

いずれも `context.Context` を取り、型付きスナップショットを返します:
`GetGlobal` / `ListCircuits` / `ListAdjacencies` / `ListLSDB` / `ListRoutes` /
`ListLocators` / `ListFlexAlgos`。`ListLSDB` は `LSPInfo.TLVs` を空のままにします。
描画するのは `ListLSDBDetail` で、大規模な LSDB ではスナップショット本体より
はるかに高くつきます。`LocatorInfo` は locator の End SID に加えて
`EndXSIDs` を持ちます — グローバルな on-link アドレスを持ち、Flexible Algorithm に
紐づく locator ならそのアルゴリズムにも参加している Up の隣接ごとに 1 つの End.X SID
で、その隣接のシステム ID と、隣接が乗っているサーキットが付きます。
`FlexAlgoInfo.Definition` は勝者 FAD の `Constraints`、すなわち受信したままの
制約 sub-sub-TLV(RFC 9350 §6)を持ちます。goisis はこれで枝刈りはしませんが
報告はするので、admin group や SRLG の制約を要求しているエリアが、何も要求して
いないエリアと同じには見えません。

## 経路ポリシー

IS-IS は IGP です。エリア内の全ノードが 1 つの LSDB を共有し同じ SPF 結果に
収束する必要があるため、フラッディングされるリンクステートに BGP 的な
import/export ポリシーは存在しません(フィルタすると一貫性が壊れる)。ポリシーは
境界にのみ適用でき、goisis は 3 つのフックを提供します:

- **export**(`WithAdvertiseFilter`):自ノードが LSP に載せる prefix を制御。
  フラッディングと LSDB は不変。
- **leak**(`WithL2LeakFilter`):L1L2 ノードが up/down ビット付きで Level-1 LSP に
  載せる Level-2 prefix を制御。このオプションを渡すことがリークの有効化で、
  渡さなければ何もリークしない。Level-2 テーブルを丸ごとエリアへ流すのは
  運用者の判断だから。
- **FIB**(`WithFIBFilter`):計算経路のうちフォワーディングプレーンに入れるものを
  制御。拒否された経路も RIB には残り(`ListRoutes`/`WatchEvent` で見える)、
  watch-only の利用者が処理できる。IS-IS 版「RIB にはあるが FIB に入れない」。

```go
server.WithFIBFilter(func(r server.RouteInfo) bool {
    return r.Prefix.Addr().Is6()   // IPv6 経路だけ FIB に入れ、v4 は RIB に残す
}),
```

トポロジ別 / アルゴリズム別の独立 RIB(BGP の複数テーブルに相当する IGP 版)が
欲しい場合はフィルタではなく Flexible Algorithm(`WithFlexAlgo`)を使います。

## 実行時の再構成

SRv6 locator と Flexible Algorithm は再起動なしで追加・削除できます。各呼び出しは
`Serve` ループ上で直列化され、自ノードの LSP を再生成し、(locator の場合は)
ローカル End SID をインストール/削除します:

```go
s.AddFlexAlgo(ctx, server.FlexAlgoConfig{Algo: 128, Priority: 100, AdvertiseDefinition: true})
s.AddLocator(ctx, server.SRv6LocatorConfig{Prefix: netip.MustParsePrefix("fc00:0:128::/48"), Algo: 128})
s.DeleteLocator(ctx, netip.MustParsePrefix("fc00:0:128::/48"))
s.DeleteFlexAlgo(ctx, 128)
```

検証はコンストラクタと同じです(locator は IPv6 のみ、Flex-Algo は 128-255、
非ゼロ algo の locator はその algo に参加していること、重複不可)。
`DeleteFlexAlgo` は locator が algo にバインドされている間は拒否されます —
先に locator を削除してください。

広告プレフィックス、オーバーロードビット、隣接も同様に変更できます。
`AddPrefix` / `DeletePrefix` はプレフィックスの生成・取り下げ(マスク後の形で照合)、
`SetOverload` は保守用にオーバーロードビットを手動で設定・解除(起動時ウィンドウとは独立)、
`ClearAdjacency` はサーキットの隣接(全部、または指定した 1 つ)を落として
hello による再形成を促します:

```go
s.AddPrefix(ctx, server.AdvertisedPrefix{Prefix: netip.MustParsePrefix("10.9.9.0/24"), Metric: 10})
s.DeletePrefix(ctx, netip.MustParsePrefix("10.9.9.0/24"))
s.SetOverload(ctx, true)
s.ClearAdjacency(ctx, "eth0", nil) // nil: サーキット上の全隣接
```

プレフィックスの所有者は、設定とこの 2 つの API か、そのサブネットを直結している
サーキットのいずれか一方で、両方になることはありません。既にサーキットが直結して
いるサブネットへの `AddPrefix` は受け付けられ、広報時のメトリックを決めます
(広報されるエントリは 1 つのままです)。`DeletePrefix` はそれをサーキットの
メトリックに戻します。サーキットだけが持つサブネットの削除は拒否されます —
次のアドレスイベントで復活してしまうため、アドレスを外すか
`WithAdvertiseFilter` で広報を抑止してください。直結サブネットは誰が広報していても
directly-connected マーカーを保つので、同じプレフィックスを広報するピアがいても
カーネルの直結経路を上書きすることはありません。

サーキットのアドレスも変更できます。`SetCircuitAddresses` は hello の送信元
アドレス(TLV 132 / 232)と、そのサーキットの直結サブネット
(`CircuitConfig.ConnectedPrefixes` で与えたもの)を置き換え、次の hello を待たず
に即座に hello を送ります。`WithAdvertisedPrefix` / `WithConnectedPrefix` 由来の
プレフィックスや、他のサーキットがまだ直結しているものはそのまま残ります。
`SetCircuitLinkState` はリンクが通信可能かを伝えます。down はそのサーキットの
隣接を即座に落として送信を止め、up は hello を再開します。どちらも変化が
なければ何もしないので、イベント源は差分を取らずそのまま流し込めます。

```go
s.SetCircuitAddresses(ctx, "eth0", v4, linkLocalV6, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")})
s.SetCircuitLinkState(ctx, "eth0", false)
```

イベント源は利用者側のものです。`goisisd` は netlink を購読します
(`config.WatchInterfaces`、Linux のみ)。コア自体は netlink をリンクしません。

サーキットそのものを削除することもできます。`DeleteCircuit` はそのサーキットの
隣接を落として報告し、保持していた pseudonode LSP を purge して MaxAge を待たず
にピアから消させ、直結サブネットのマークを外し、トランスポートを閉じます
(トランスポートの所有権は `Serve` 以降インスタンス側にあります)。サーキットの
リーダ goroutine は待ちません。1 秒以内に自分で終了し、既にキューに入っていた
フレームは捨てられ、`Metrics` シンクのラベル系列も引退させます
(`ForgetCircuit`)。設定に無いサーキットの削除は `server.ErrAlreadyInState` と
して拒否するので、バッチを再送する呼び出し側はノードを別の状態に残した拒否と
区別できます。

対になるのが `AddCircuit` です。トランスポートは呼び出し側で開いて
`CircuitConfig` に入れて渡します。管理ループ上で開くと、その syscall の裏で他の
全サーキットの hello と LSP の老化が止まるからです。渡した時点で、トランスポート
の所有権はどの経路でもインスタンス側に移ります。サーキットがその上で動くか、この
呼び出しが閉じるかのどちらかで、呼び出し側が閉じてはいけません。context が切れた
呼び出しでもキューに残っていて、これからその上にサーキットを作ることがあるから
です。サーキットは集合の末尾に加わります。この順序が End.X SID の function
値を決めるので、追加が変化していないリンクの SID を振り直すことはありません。
最初の hello は即座に送られ、戻る前に再 originate するので、MTU のより小さい
サーキットなら自 LSP の再フラグメントが、どのサーキットも居なかったレベルなら
その node LSP が、制御が戻った時点で済んでいます。既に設定済みの名前は置き換え
ではなく拒否されます。動作中のサーキットが要求どおりのものなら
`server.ErrAlreadyInState`、そうでなければ食い違うフィールドを名指しするエラー
です。これにより、古い hello 鍵のまま動くサーキットに対してリロードが成功を報告
することはありません。比較するのはトランスポート以外の全フィールドで、
トランスポートだけは開いたソケットであり、渡されたものと等しくなりえません。

```go
s.AddCircuit(ctx, server.CircuitConfig{Name: "eth1", Transport: tr, Level2: true})
s.DeleteCircuit(ctx, "eth0")
```

## 変更の監視

```go
sub, err := s.Subscribe(ctx)
if err != nil { return err }
defer sub.Unsubscribe()
for _, ev := range sub.Initial {  // 現在の隣接、続いて経路
    // 以下のイベントと同じ形。ここでは ev.Withdrawn は立たない
}
for ev := range sub.Events {
    switch {
    case ev.Adjacency != nil:               // 隣接の状態変化
    case ev.Route != nil && !ev.Withdrawn:  // 経路の追加 / 変更
    case ev.Route != nil && ev.Withdrawn:   // 経路の削除
    }
}
```

`sub.Initial` は watcher を登録するのと同じ管理オペレーションで撮った隣接と
経路のスナップショットです。したがってスナップショットと `Events` の間に隙間は
なく、`ListRoutes` のあとに `Subscribe` する場合と違って途中の変化を取りこぼし
ません。RPC では `WatchEventRequest.include_initial`(`goisis monitor
--initial`)で要求します。

サブスクリプションのバッファは有限で、追いつけない購読者は(コントロールプレーンを
止める代わりに)切断されます(チャネルがクローズし `sub.Lagged()` が true を返す)。
再購読して回復します。

## 独自 FIB

独自データプレーンを駆動するには `fib.FIB` を実装します:

```go
type FIB interface {
    Update(prefix netip.Prefix, nexthops []Nexthop) error
    Withdraw(prefix netip.Prefix) error
    Sweep(keep func(netip.Prefix) bool) error // 起動時に古い経路を削除
    AddLocalSID(sid LocalSID) error            // SRv6 End / End.X SID
    RemoveLocalSID(sid netip.Addr) error
}
```

`LocalSID.Behavior` はどの endpoint behavior を実体化するかを指し
(`BehaviorEnd` / `BehaviorEndX` / `BehaviorEndDT4`・`DT6`・`DT46`)、`Table` は
デカプセル系のルックアップテーブル、`Nexthop`(隣接のグローバルな
on-link IPv6 アドレス)と `Interface` は `BehaviorEndX` SID が転送する隣接を表します。同梱の `fib.Netlink` は Linux の
`proto isis` 経路と `seg6local` End / End.X SID を設定します。`fib.Noop` は全て捨てます(`Subscribe` と組み合わせて自分で経路を
処理する — [`examples/watchroutes`](../examples/watchroutes) を参照)。

## 独自メトリクス

テレメトリ基盤へ流すには `server.Metrics` を実装するか、Prometheus アダプタを
使います。`server.NoopMetrics` を埋め込んで必要なイベントだけを上書きすれば、
後からインターフェースにメソッドが増えてもビルドは壊れません:

```go
import "github.com/takehaya/goisis/pkg/metrics"

reg := prometheus.NewRegistry()
s, _ := server.NewIsisServer(server.WithMetrics(metrics.NewPrometheus(reg)), ...)
```
