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
| `WithSRv6Locator(netip.Prefix)` | Advertise an algorithm-0 SRv6 locator (with an End SID, and an End.X SID per adjacency). |
| `WithSRv6LocatorForAlgo(netip.Prefix, algo)` | Advertise a Flex-Algo locator. |
| `WithFlexAlgo(FlexAlgoConfig)` | Participate in / advertise a Flexible Algorithm. |
| `WithOverloadOnStartup(time.Duration)` | Set the OL bit for a window after startup. |
| `WithLSPMTU(int)` | Cap the size of the LSPs this node originates; 0 (default) derives it from the circuit MTUs, capped at 1492. Rejected below 512. |
| `WithLSDBEntryLimit(int)` | Cap the LSPs held per level as defense in depth against LSDB exhaustion; 0 (default) disables it. |
| `WithAreaAuth` / `WithDomainAuth(AuthConfig)` | HMAC authentication of L1 / L2 LSPs and SNPs. `AuthConfig.AcceptSecrets` (and `CircuitConfig.HelloAcceptPasswords` for hellos) are extra keys accepted on receive but never used to sign, so a key can be rotated node by node. `WithAreaPassword` / `WithDomainPassword(string)` are the HMAC-MD5 shorthands. |
| `WithFIB(fib.FIB)` | Forwarding sink (default `fib.Noop`). |
| `WithAdvertiseFilter(func(AdvertisedPrefix) bool)` | Export policy: which prefixes to originate. |
| `WithFIBFilter(func(RouteInfo) bool)` | FIB policy: which computed routes to program (rejected ones stay in the RIB). |
| `WithMetrics(server.Metrics)` | Telemetry sink (default `NoopMetrics`). |
| `WithLogger(*slog.Logger)` | Structured logger. |

`CircuitConfig` carries `Name`, an injected `datalink.Transport` (use
`datalink.OpenLinux(ifname)` on Linux, or a mock in tests), `P2P`, `Level1`/
`Level2`, `Priority`, `Metric`, `HelloInterval`, `HoldingMultiplier`,
`Padding`, `IPv4Addrs`/`IPv6Addrs`, `ConnectedPrefixes` (the circuit's directly
connected subnets, withdrawn with the circuit when its addresses change), and
the hello authentication keys (`HelloPassword`, `HelloAcceptPasswords`,
`HelloAuthAlgorithm`, `HelloKeyID`).

## Reading state

All take a `context.Context` and return typed snapshots:
`GetGlobal`, `ListCircuits`, `ListAdjacencies`, `ListLSDB`, `ListRoutes`,
`ListLocators`, `ListFlexAlgos`. Each `LocatorInfo` carries the locator's End
SID and its `EndXSIDs` — one End.X SID per Up adjacency, with that neighbor's
System ID and the circuit it sits on.

## Route policy

IS-IS is an IGP: every node in an area shares one LSDB and must converge on the
same SPF result, so there is no BGP-style import/export policy on the flooded
link state — filtering it would break consistency. Policy applies only at the
edges, where goisis exposes two hooks:

- **Export** (`WithAdvertiseFilter`): gate which configured prefixes this node
  originates into its own LSP. Flooding and the LSDB are untouched.
- **FIB** (`WithFIBFilter`): gate which computed routes reach the forwarding
  plane. A rejected route stays in the RIB — `ListRoutes` and `WatchEvent` still
  report it — so a watch-only consumer can act on it. This is the IS-IS
  equivalent of "in the RIB, not the FIB".

```go
server.WithFIBFilter(func(r server.RouteInfo) bool {
    return r.Prefix.Addr().Is6()   // program only IPv6 routes; keep v4 in the RIB
}),
```

For per-topology / per-algorithm separate RIBs (the IGP analogue of multiple
BGP tables), use Flexible Algorithm (`WithFlexAlgo`) rather than a filter.

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

Advertised prefixes, the overload bit and adjacencies are equally mutable:
`AddPrefix`/`DeletePrefix` originate or withdraw a prefix (matched on its
masked form; deleting one that came from a connected subnet keeps its
directly-connected marker), `SetOverload` sets or clears the overload bit by
hand for maintenance (independently of the startup window), and
`ClearAdjacency` tears down a circuit's adjacencies — all of them, or one
neighbor's — so hellos re-form them:

```go
s.AddPrefix(ctx, server.AdvertisedPrefix{Prefix: netip.MustParsePrefix("10.9.9.0/24"), Metric: 10})
s.DeletePrefix(ctx, netip.MustParsePrefix("10.9.9.0/24"))
s.SetOverload(ctx, true)
s.ClearAdjacency(ctx, "eth0", nil) // nil: every adjacency on the circuit
```

A circuit's addresses can change too. `SetCircuitAddresses` replaces the hello
source addresses (TLV 132 / 232) and the circuit's connected subnets — the ones
given as `CircuitConfig.ConnectedPrefixes` — then sends a hello at once instead
of waiting for the next one; prefixes that came from `WithAdvertisedPrefix` /
`WithConnectedPrefix`, or that another circuit still has connected, are left
alone. `SetCircuitLinkState` reports whether the link can carry traffic: down
tears the circuit's adjacencies down immediately and silences it, up resumes
hellos. Both are no-ops when nothing changed, so an event source may push on
every notification rather than diffing first.

```go
s.SetCircuitAddresses(ctx, "eth0", v4, linkLocalV6, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")})
s.SetCircuitLinkState(ctx, "eth0", false)
```

You own that event source. `goisisd` subscribes to netlink
(`config.WatchInterfaces`, Linux only); the core links no netlink of its own.

## Watching changes

```go
sub, err := s.Subscribe(ctx)
if err != nil { return err }
defer sub.Unsubscribe()
for _, ev := range sub.Initial {     // adjacencies, then routes, as they are now
    // same shape as the events below; ev.Withdrawn is never set here
}
for ev := range sub.Events {
    switch {
    case ev.Adjacency != nil:           // adjacency state change
    case ev.Route != nil && !ev.Withdrawn: // route added/changed
    case ev.Route != nil && ev.Withdrawn:  // route removed
    }
}
```

`sub.Initial` is a snapshot of the adjacencies and routes taken in the same
management operation that registers the watcher, so the snapshot followed by
`Events` is gap-free: unlike `ListRoutes` then `Subscribe`, no change can slip
through in between. Ask for it over RPC with `WatchEventRequest.include_initial`
(`goisis monitor --initial`).

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
    AddLocalSID(sid LocalSID) error            // SRv6 End / End.X SID
    RemoveLocalSID(sid netip.Addr) error
}
```

`LocalSID.Behavior` says which endpoint behavior to instantiate
(`BehaviorEnd`, `BehaviorEndX`, `BehaviorEndDT4`/`DT6`/`DT46`); `Table` is the
lookup table for the decapsulating ones, and `Nexthop` (the neighbor's IPv6
address, normally link-local) and `Interface` carry the adjacency a
`BehaviorEndX` SID forwards to. The bundled
`fib.Netlink` programs Linux `proto isis` routes and `seg6local` End and End.X
SIDs. `fib.Noop` discards everything (pair it with `Subscribe` to consume
routes yourself — see [`examples/watchroutes`](../examples/watchroutes)).

## Custom metrics

Implement `server.Metrics` (`AdjacencyTransition`, `SPFRun`, `LSDBSize`,
`FloodTx`, `FIBPending`, `PDURx`, `PDUDrop`, `AdjacencyCount`, `RouteCount`,
`FIBError`, `EventQueueDepth`) to feed your telemetry pipeline, or use the
Prometheus adapter:

```go
import "github.com/takehaya/goisis/pkg/metrics"

reg := prometheus.NewRegistry()
s, _ := server.NewIsisServer(server.WithMetrics(metrics.NewPrometheus(reg)), ...)
```
