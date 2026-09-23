# Configuration reference

`goisisd -f <file>` loads a YAML configuration and translates it into server
options. ([日本語](configuration.ja.md))

## Top-level keys

| Key | Type | Description |
|-----|------|-------------|
| `net` | string (required) | Network Entity Title: area address + 6-octet system ID. The last octet (NSEL) must be `00`, e.g. `49.0001.0000.0000.0001.00`. |
| `hostname` | string | Dynamic hostname advertised in LSPs (RFC 5301). |
| `fib` | bool | Program computed routes into the Linux kernel FIB tagged `proto isis`. Requires `CAP_NET_ADMIN`. Default `false` (control-plane only). |
| `fib-table` | int | Routing table the routes are programmed into when `fib` is set. Default `254` (main). |
| `overload-on-startup` | duration | Set the overload bit for this long after startup, then clear it (e.g. `30s`). While set, peers route no transit traffic through this node. |
| `lsp-mtu` | int | Maximum size of LSPs this node originates; defaults to the smallest circuit MTU minus the LLC header, capped at 1492. |
| `lsdb-entry-limit` | int | Cap on the LSPs held per level, guarding against LSDB exhaustion. Size it well above the area's legitimate LSP count. Default `0` (no cap). |
| `area-password` | string | Authenticate Level-1 LSPs and SNPs with this key. |
| `area-accept-passwords` | list of string | Extra keys accepted on received Level-1 LSPs and SNPs (same algorithm and key ID); never used to sign. See [Key rotation](#key-rotation). |
| `area-auth-algorithm` | string | `md5` (default, RFC 5304; FRR's `area-password md5`), or `sha1`/`sha256`/`sha384`/`sha512` (RFC 5310). |
| `area-key-id` | uint16 | RFC 5310 key ID (SHA only). |
| `domain-password` / `domain-accept-passwords` / `domain-auth-algorithm` / `domain-key-id` | | The same, for Level-2. |
| `circuits` | list (required) | Interfaces to run IS-IS on; see below. |
| `prefixes` | list | Extra prefixes to originate, each a bare CIDR (`10.1.1.1/32`, metric 10) or a mapping `{prefix: 10.1.1.1/32, metric: 20}`. Connected subnets of the circuits are advertised automatically; naming one here does not advertise it twice, it only sets the metric it is advertised at. |
| `srv6` | object | SRv6 locators; see below. |
| `flex-algo` | list | Flexible Algorithm definitions; see below. |
| `policy` | object | Prefix-lists gating origination and FIB programming; see [`policy`](#policy). |

> FRR's IS-IS authentication is HMAC-MD5 only, so the SHA variants (RFC 5310)
> interop goisis↔goisis, not with FRR.

## `circuits[]`

| Key | Type | Description |
|-----|------|-------------|
| `interface` | string (required) | Interface name (AF_PACKET). |
| `level` | string | `"1"`, `"2"`, or `"12"` (default `"12"`). |
| `p2p` | bool | Point-to-point procedures (RFC 5303 three-way) instead of broadcast/DIS. |
| `priority` | uint8 | DIS election priority on a LAN, 0–127 (default 64). |
| `metric` | uint32 | Circuit wide metric (default 10). |
| `hello-interval` | duration | Time between hellos, e.g. `1s`, `500ms` (default `3s`). |
| `hold-multiplier` | int | Advertised holding time is `hello-interval x hold-multiplier` (default 10). |
| `padding` | bool | Pad hellos toward the MTU to detect MTU mismatches, per ISO 10589 (default `true`). |
| `hello-password` | string | Enables HMAC hello authentication. Hellos are signed with it and received hellos must carry a matching digest or they are dropped. |
| `hello-auth-algorithm` | string | `md5` (default, RFC 5304; FRR's `isis password md5`), or an HMAC-SHA variant (RFC 5310). |
| `hello-accept-passwords` | list of string | Extra keys accepted on received hellos; never used to sign. See [Key rotation](#key-rotation). |
| `hello-key-id` | uint16 | RFC 5310 key ID (SHA only). |

IPv4 and link-local IPv6 addresses configured on the interface are advertised in
hellos (TLV 132/232) and used as next hops; their connected subnets are
originated automatically (and never installed over the kernel's connected route).

## Key rotation

A node signs with one key and accepts several, so a key changes without a flag
day: 1. add the new key to `*-accept-passwords` on every node; 2. switch
`*-password` to the new key, node by node; 3. remove the old key from the accept
lists once every node signs with the new one.

An accept list without the matching `*-password` is a configuration error: the
scope would sign nothing and accept nothing, so goisisd refuses to start rather
than run unauthenticated.

## `srv6`

```yaml
srv6:
  locators:
    - fc00:0:1::/48
```

Each locator is advertised in the SRv6 Locator TLV (27) with an End SID at the
locator's base address and the SRv6 Capabilities sub-TLV in the Router
Capability TLV (242). It is also mirrored into IPv6 reachability (TLV 236) for
peers that don't parse TLV 27. With `fib: true` the End SID is installed as a
`seg6local` End route on `isis-srv6`, a dummy device the daemon creates for its
local SIDs and removes again with the last one (Linux drops the encapsulation
of a `seg6local` route whose device is the loopback).

An adjacency also gets an End.X SID per locator, taken from the locator's
function space starting at 1 and advertised in the neighbour's IS reachability
entry (RFC 9352 §8). With `fib: true` each one becomes a `seg6local` End.X
route towards that neighbour; there is nothing to configure.

That needs the neighbour to have a **global IPv6 address on one of the
circuit's connected subnets**: goisis takes it from the neighbour's hellos and
otherwise from TLV 232 of its fragment-0 LSP (FRR sends only link-locals in
hellos). Linux resolves an End.X next hop against the interface the packet
arrived on, so a link-local next hop would drop everything that is not a
hairpin. Where no such address is known, nothing is allocated, advertised or
programmed, and the circuit logs `no on-link global IPv6 address for neighbor`
once for that adjacency.

Today that address only ever comes from a peer that publishes one: FRR does, in
its LSP. `goisisd` itself publishes none — its hellos carry link-locals as RFC
5308 3 requires and its LSPs carry no TLV 232 — so a link between two goisis
nodes gets no End.X SIDs.

A locator bound to a Flexible Algorithm is configured under `flex-algo` instead
(see `locator` below), not here — `srv6.locators` are algorithm-0 locators.

## `flex-algo[]`

```yaml
flex-algo:
  - algo: 128
    metric-type: igp     # igp (default), delay, or te
    priority: 100
    advertise: true
    locator: fc00:0:128::/48
```

| Key | Type | Description |
|-----|------|-------------|
| `algo` | uint8 (required) | Flexible Algorithm number, 128–255. |
| `metric-type` | string | `igp` (default), `delay`, or `te`. goisis computes the IGP metric only; others are advertised so the definition and election match peers. |
| `priority` | uint8 | Election priority (higher wins; ties broken by higher System ID). |
| `advertise` | bool | Originate the definition (FAD), not just participate. At least one node in the area must advertise it. |
| `locator` | CIDR | Optional SRv6 locator bound to this algorithm; its route is computed over the algorithm's pruned topology. |

A node participates in every listed algorithm (advertised in the SR-Algorithm
sub-TLV, 19). A locator bound to an algorithm the node does not participate in
is rejected at startup, since it would be unreachable.

## `policy`

IS-IS floods one consistent LSDB per area, so there is no policy on the flooded
link state — filtering it would break convergence. Policy applies only at the
edges, as prefix-lists:

```yaml
policy:
  advertise:          # which prefixes this node originates into its LSP
    default: permit
    rules:
      - deny: 10.0.0.0/8
        le: 32
  fib:                # which computed routes are programmed into the FIB
    default: permit
    rules:
      - deny: 0.0.0.0/0
        le: 32        # control-plane only: keep routes in the RIB, not the kernel
```

| Key | Type | Description |
|-----|------|-------------|
| `advertise` | prefix-list | Export policy: prefixes the node originates (TLV 135/236). |
| `fib` | prefix-list | FIB policy: routes programmed into the forwarding plane. Rejected routes stay in the RIB — `ListRoutes` and `WatchEvent` still report them. |
| `<list>.default` | string | `deny` (default) or `permit`, applied when no rule matches. |
| `<list>.rules[]` | list | Ordered; the first match wins. Each rule is `permit:`/`deny:` a CIDR, with optional `ge`/`le` length bounds. |

A rule matches a prefix within its CIDR whose length is in `[ge, le]` (omit both
for an exact-length match). The flooded LSDB is never affected. For per-topology
or per-algorithm separate RIBs (the IGP analogue of multiple BGP tables), use
Flexible Algorithm rather than a filter.

## Capabilities

`goisisd` needs `CAP_NET_RAW` (AF_PACKET) and, with `fib: true`, `CAP_NET_ADMIN`:

```console
$ sudo setcap cap_net_raw,cap_net_admin+ep goisisd
```

The provided [`packaging/goisisd.service`](../packaging/goisisd.service) grants
exactly these as ambient capabilities.

## CLI

The `goisis` CLI (`--addr`, default `http://127.0.0.1:50051`) provides:
`global`, `circuit`, `neighbor`, `database`, `route`, `prefix`, `overload`,
`locator`, `flex-algo`, `monitor` (streams `WatchEvent`; `--initial` prints the
current adjacencies and routes before following changes), and `version`.

`-o json` prints the RPC response of any list or show command as JSON instead
of a table, for scripts and `jq`. `goisis database --detail` additionally prints
each LSP's TLVs under its row, so a peer's advertisement can be read without a
packet capture.

`goisisd -api-listen` binds `127.0.0.1:50051` by default; anything reachable
from off the host needs the `-api-allow-remote` opt-in. A bare `:50051` counts
as such: an empty host binds every interface, exactly as `0.0.0.0` does.

`--addr` also takes `unix:///absolute/path` to reach a daemon started with
`goisisd -api-listen unix:///run/goisis/goisisd.sock`. The API is
unauthenticated, so on a shared host a unix socket is the cheapest protection:
the socket is bound under a umask that makes it mode `0660` from the first
instant it exists, and its directory guards who may connect.

`prefix`, `overload`, `neighbor clear`, `locator` and `flex-algo` also
reconfigure the daemon at runtime:

```console
$ goisis flex-algo add 128 --priority 100 --advertise
$ goisis locator add fc00:0:128::/48 --algo 128
$ goisis locator delete fc00:0:128::/48
$ goisis flex-algo delete 128
$ goisis prefix add 10.9.9.0/24 --metric 10   # and: goisis prefix delete 10.9.9.0/24
$ goisis overload on                          # maintenance; "off" clears it
$ goisis neighbor clear --interface eth0      # add --system-id for one neighbor
```

`prefix add` refuses what could never be routed to: multicast, unspecified,
link-local and IPv4-mapped prefixes, and a metric at or above the RFC 5305
reachability ceiling (`0xfe000000`), which means "unreachable". A default route
is not refused — originating one is legitimate, and `policy.advertise` is the
knob that suppresses it.

`prefix delete` only withdraws what `prefixes` or `prefix add` originates. An
interface's connected subnet is refused, naming the interface it is connected
on: remove the address, or suppress it with `policy.advertise`.

## Metrics

`goisisd` serves Prometheus metrics at `/metrics`:
`goisis_adjacency_transitions_total{circuit,level,state}`,
`goisis_spf_duration_seconds{level}`, `goisis_lsdb_lsps{level}`,
`goisis_flooding_lsp_tx_total{circuit}`,
`goisis_flooding_lsp_drops_total{circuit,reason}` (reasons: `oversize`),
`goisis_fib_pending`,
`goisis_pdu_rx_total{circuit,type}`, `goisis_pdu_drops_total{circuit,reason}`
(reasons: `decode`, `auth`, `no_adjacency`, `checksum`, `lsdb_limit`,
`unknown_purge`, `own_sysid_purge`, `own_fragment_purge`, `own_lsp_reclaimed`,
`own_seq_wrap`),
`goisis_adjacencies{circuit,level}`, `goisis_routes{level,algorithm}`,
`goisis_fib_errors_total{op}` (ops: `update`, `withdraw`, `add_sid`,
`remove_sid`) and `goisis_event_queue_depth`.

The four `own_*` drop reasons are PDUs carrying this node's own System ID:
they drove a re-origination or a purge rather than being discarded, and they
occur in normal operation (a restart with a stale copy of ours still in the
area, a DIS handover). Alert on the rest, and watch those separately — a
steady rate means another node is originating LSPs in this node's name:

```
rate(goisis_pdu_drops_total{reason!~"own_.*"}[5m]) > 0
rate(goisis_pdu_drops_total{reason=~"own_.*"}[15m]) > 0
```

An `oversize` flood drop is a neighbor whose database can never catch up: the
LSP is larger than the circuit MTU and a transit node may not re-fragment a
foreign LSP (ISO 10589 7.3.3), so it is requested by PSNP and dropped again on
every retransmission. Any sustained rate means the originator must be told to
use a smaller LSP MTU:

```
rate(goisis_flooding_lsp_drops_total[5m]) > 0
```
