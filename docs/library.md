# Library guide

goisis is built to be embedded: `pkg/server.IsisServer` runs the IS-IS control
plane, and you own forwarding (the kernel FIB, an eBPF dataplane, or just
observing). ([日本語](library.ja.md))

## Lifecycle

```go
s, err := server.NewIsisServer(opts...)   // validates config
if err != nil { return err }
go s.Serve(ctx)                            // runs until ctx is cancelled
```

`Serve` is the single goroutine that owns all protocol state; every read method
is safe to call concurrently (it is serialized onto that loop). Cancelling `ctx`
purges this node's own LSPs, removes local SIDs, closes transports, and returns.

## Options

| Option | Purpose |
|--------|---------|
| `WithSystemID(packet.SystemID)` | 6-octet system ID (required). |
| `WithAreaAddresses(...packet.AreaAddress)` | Area address(es) from the NET. |
| `WithHostname(string)` | Dynamic hostname (RFC 5301). |
| `WithCircuit(CircuitConfig)` | Add a circuit (see below). |
| `WithAdvertisedPrefix(netip.Prefix, metric)` | Originate a prefix (TLV 135/236). |
| `WithConnectedPrefix(netip.Prefix)` | Mark a prefix connected — never installed into the FIB. |
| `WithSRv6Locator(netip.Prefix)` | Advertise an algorithm-0 SRv6 locator. |
| `WithSRv6LocatorForAlgo(netip.Prefix, algo)` | Advertise a Flex-Algo locator. |
| `WithFlexAlgo(FlexAlgoConfig)` | Participate in / advertise a Flexible Algorithm. |
| `WithOverloadOnStartup(time.Duration)` | Set the OL bit for a window after startup. |
| `WithFIB(fib.FIB)` | Forwarding sink (default `fib.Noop`). |
| `WithMetrics(server.Metrics)` | Telemetry sink (default `NoopMetrics`). |
| `WithLogger(*slog.Logger)` | Structured logger. |

`CircuitConfig` carries `Name`, an injected `datalink.Transport` (use
`datalink.OpenLinux(ifname)` on Linux, or a mock in tests), `P2P`, `Level1`/
`Level2`, `Priority`, `Metric`, `IPv4Addrs`/`IPv6Addrs`, and `Padding`.

## Reading state

All take a `context.Context` and return typed snapshots:
`GetGlobal`, `ListCircuits`, `ListAdjacencies`, `ListLSDB`, `ListRoutes`,
`ListLocators`, `ListFlexAlgos`.

## Reconfiguring at runtime

SRv6 locators and Flexible Algorithms can be added and removed without a
restart; each call is serialized onto the `Serve` loop, re-originates this
node's LSPs, and (for locators) installs or removes the local End SID:

```go
s.AddFlexAlgo(ctx, server.FlexAlgoConfig{Algo: 128, Priority: 100, AdvertiseDefinition: true})
s.AddLocator(ctx, server.SRv6LocatorConfig{Prefix: netip.MustParsePrefix("fc00:0:128::/48"), Algo: 128})
s.DeleteLocator(ctx, netip.MustParsePrefix("fc00:0:128::/48"))
s.DeleteFlexAlgo(ctx, 128)
```

They apply the same validation as the constructor (IPv6-only locators,
Flex-Algo range 128-255, a non-zero locator algorithm must be participated in,
no duplicates). `DeleteFlexAlgo` is refused while a locator is still bound to
the algorithm — delete the locator first.

## Watching changes

```go
sub, err := s.Subscribe(ctx)
if err != nil { return err }
defer sub.Unsubscribe()
for ev := range sub.Events {
    switch {
    case ev.Adjacency != nil:           // adjacency state change
    case ev.Route != nil && !ev.Withdrawn: // route added/changed
    case ev.Route != nil && ev.Withdrawn:  // route removed
    }
}
```

The subscription has a bounded buffer; a consumer that falls behind is dropped
(the channel closes and `sub.Lagged()` reports true) rather than stalling the
control plane. Resubscribe to recover.

## Custom FIB

Implement `fib.FIB` to drive your own dataplane:

```go
type FIB interface {
    Update(prefix netip.Prefix, nexthops []Nexthop) error
    Withdraw(prefix netip.Prefix) error
    Sweep(keep func(netip.Prefix) bool) error // drop stale routes at startup
    AddLocalSID(sid LocalSID) error            // SRv6 End SID
    RemoveLocalSID(sid netip.Addr) error
}
```

The bundled `fib.Netlink` programs Linux `proto isis` routes and `seg6local`
End SIDs. `fib.Noop` discards everything (pair it with `Subscribe` to consume
routes yourself — see [`examples/watchroutes`](../examples/watchroutes)).

## Custom metrics

Implement `server.Metrics` (`AdjacencyTransition`, `SPFRun`, `LSDBSize`,
`FloodTx`) to feed your telemetry pipeline, or use the Prometheus adapter:

```go
import "github.com/takehaya/goisis/pkg/metrics"

reg := prometheus.NewRegistry()
s, _ := server.NewIsisServer(server.WithMetrics(metrics.NewPrometheus(reg)), ...)
```
