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
| `policy` | object | Prefix-lists gating origination, FIB programming and L2→L1 leaking; see [`policy`](#policy). |

> FRR's IS-IS authentication is HMAC-MD5 only, so the SHA variants (RFC 5310)
> interop goisis↔goisis, not with FRR.

A key the schema does not have is an error: `goisisd` refuses to start and a
`SIGHUP` refuses the file. Releases up to 0.4.0 dropped an unrecognised key in
silence, so `area-pasword` — one transposed letter — left the node
unauthenticated with nothing to report it. **A file carrying keys goisisd does
not define no longer loads**; comment them out or delete them.

The file holds one YAML document. A second one, after a `---` separator, is
refused rather than dropped: the check above only sees the document it decodes,
so a correctly spelled `area-password` appended by a template or a secrets tool
would have left the node unauthenticated in the same silence. A separator at
the top of the file is not a second document and still loads.

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
| `adjacency-limit` | int | Neighbors this circuit takes on. At the cap, a hello from a System ID it holds no adjacency for is dropped (counted as `adjacency_limit`) and the adjacencies it has keep working. Default 128; `0` removes the cap. |
| `hello-password` | string | Enables HMAC hello authentication. Hellos are signed with it and received hellos must carry a matching digest or they are dropped. |
| `hello-auth-algorithm` | string | `md5` (default, RFC 5304; FRR's `isis password md5`), or an HMAC-SHA variant (RFC 5310). |
| `hello-accept-passwords` | list of string | Extra keys accepted on received hellos; never used to sign. See [Key rotation](#key-rotation). |
| `hello-key-id` | uint16 | RFC 5310 key ID (SHA only). |

The IPv4 and link-local IPv6 addresses configured on the interface are
advertised in hellos (TLV 132/232) and used as next hops. Its global IPv6
addresses stay out of the hello — RFC 5308 3 keeps the IIH link-local — and are
advertised in TLV 232 of the node's own LSP instead, which is where a peer looks
for an on-link address to point an End.X SID at. Connected subnets are
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
circuit's connected subnets**. It comes from TLV 232 of the neighbour's
fragment-0 LSP — where goisis and FRR both publish theirs — or from its hellos
where a peer lists one there. Linux resolves an End.X next hop against the
interface the packet arrived on, so a link-local next hop would drop everything
that is not a hairpin. Where no such address is known, nothing is allocated,
advertised or programmed, and the circuit logs `no on-link global IPv6 address
for neighbor` once for that adjacency. An interface with only link-locals on it
is therefore the one case where a link carries no End.X SIDs.

A locator bound to a Flexible Algorithm is configured under `flex-algo` instead
(see `locator` below), not here — `srv6.locators` are algorithm-0 locators. Its
End.X SIDs are restricted further: see `flex-algo[].locator`.

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

An End.X SID carries the algorithm of the locator it comes from (RFC 9352
§8.1), so a locator bound to an algorithm hands one out only towards a
neighbour that advertises **that same algorithm** in its own SR-Algorithm
sub-TLV — the participation that decides whether SPF keeps the neighbour in the
algorithm's topology. A neighbour outside the algorithm keeps its algorithm-0
End.X SIDs and gets none from the Flex-Algo locator; the SID appears (and is
released again) as the neighbour's fragment-0 LSP starts and stops listing the
algorithm.

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
  leak-l2-to-l1:      # which Level-2 prefixes an L1L2 node leaks into its area
    rules:
      - permit: 203.0.113.0/24
```

| Key | Type | Description |
|-----|------|-------------|
| `advertise` | prefix-list | Export policy: prefixes the node originates (TLV 135/236) — its own, and on an L1L2 node the Level-1 prefixes it propagates into its Level-2 LSP. |
| `fib` | prefix-list | FIB policy: routes programmed into the forwarding plane. Rejected routes stay in the RIB — `ListRoutes` and `WatchEvent` still report them. |
| `leak-l2-to-l1` | prefix-list | Leak policy: the Level-2 prefixes an L1L2 node originates into its Level-1 LSP, with the up/down bit set. Absent, nothing is leaked. |
| `<list>.default` | string | `deny` (default) or `permit`, applied when no rule matches. |
| `<list>.rules[]` | list | Ordered; the first match wins. Each rule is `permit:`/`deny:` a CIDR, with optional `ge`/`le` length bounds. |

A rule matches a prefix within its CIDR whose length is in `[ge, le]` (omit both
for an exact-length match). The flooded LSDB is never affected. For per-topology
or per-algorithm separate RIBs (the IGP analogue of multiple BGP tables), use
Flexible Algorithm rather than a filter.

`leak-l2-to-l1` both switches leaking on and decides what it covers: writing the
section is the decision to leak, since pushing a whole Level-2 table into every
area is not a sensible default, and a prefix the area already reaches through
Level 1 is never leaked. It is the only gate on leaked prefixes — `advertise`
governs the node's own prefixes and the Level-1 ones it propagates up — so an
`advertise` allowlist of your loopbacks does not silently empty the leak too.
The metric advertised is this node's total Level-2 path metric, which the
receiving Level-1 node adds its own distance to us on top of.

## Reloading

`goisisd` re-reads its `-f` file on `SIGHUP` and applies the differences the
runtime API can express. Every other difference is left alone and named in the
log, so a reload is never half a file applied silently:

```console
$ systemctl reload goisisd         # or: kill -HUP $(pidof goisisd)
WARN configuration reload: this change needs a restart and was not applied key="circuits: eth1 added"
```

| Key | On `SIGHUP` |
|-----|-------------|
| `prefixes` | Applied. A changed metric is a withdrawal and a re-advertisement. |
| `srv6.locators` | Applied, with each locator's End SID. |
| `flex-algo` | Applied. A changed definition is deleted and re-added, and a locator bound to it steps aside and comes back with it. |
| `circuits` | **Restart.** Adding or removing one needs a transport and a reader goroutine to appear or go away; changing a level, metric, timer or key means rebuilding it the same way. An interface's addresses and carrier are followed live and need neither. |
| `net` | **Restart.** The System ID and area addresses identify every LSP this node has originated. |
| `hostname` | **Restart.** It is advertised in the node's own LSP, which a reload has no way to re-originate under a new name without the System ID beneath it. |
| `area-*` / `domain-*` passwords, algorithms and key IDs | **Restart** — a rolling one, not a flag day, via [Key rotation](#key-rotation). |
| `fib`, `fib-table`, `lsp-mtu`, `lsdb-entry-limit`, `overload-on-startup`, `policy` | **Restart.** |

Of those, `policy` is the one an operator iterates on, and it is the one a
reload cannot apply: a prefix-list change needs a restart. Reaching it at
runtime would mean an RPC for the filters, which the management API does not
have.


A file that will not parse, or that a restart would refuse, leaves the daemon
exactly as it was: the whole file is validated before the first call goes out,
the server's own checks included — the Flex-Algo range and duplicates, a
locator's address family and the algorithm it binds to, what a prefix may be
and what metric it may carry. What a reload cannot check is what needs a
socket: whether the interface is there and what its MTU admits is settled when
a restart opens the circuit, which costs the reload nothing, since it applies
no circuit key either. A `SIGHUP` to a daemon started without `-f` is ignored
rather than fatal. The overload bit is not a file key at all: `goisis overload
on` sets it at runtime.

What validation cannot foresee is the node's own state: the file is compared
with the file the daemon is running, never with the node, so a prefix or a
locator added with `goisis` at runtime is invisible to it. Where both name the
same thing, the file wins, and naming something the node already has with the
same values is the reload succeeding at it rather than a collision. That is how
a runtime change is made permanent: add it with `goisis`, write the same thing
into the file, and the next `SIGHUP` adopts the file without touching what is
already there. Naming it with *different* values is refused — the file asks for
something the node does not have, and neither the reload nor the runtime API has
an update for a prefix, a locator or a Flexible Algorithm. Withdraw it with
`goisis`, or write the running value into the file, and signal again.

A reload has no rollback — undoing it needs the inverse of every call — so it
stops where the refusal left it and says so, rather than recording the file as
applied:

```console
ERROR configuration reload was refused part way; the node is not in the state the file describes; fix the file and send SIGHUP again
```

Changing a Flexible Algorithm or a locator is a withdrawal followed by a
re-advertisement, so a refusal there can leave the resource withdrawn. The
reload keeps the baseline it had, so the next `SIGHUP` re-issues the whole
change instead of treating a file the node never adopted as what it runs. That
retry is the repair: the calls an earlier attempt already landed are satisfied
rather than refused a second time, so one signal after the file is corrected the
node is running it. A `SIGHUP` that still reports a refusal is naming something
the correction has not reached — the error names the resource — and repeating
the signal on its own will not settle it.

The file is read again on every `SIGHUP`, so its ownership and mode are access
control for live routing state, not just for the next restart: whoever can
write it can make this node originate a default route area-wide, and the
shipped unit's `ExecReload=` reaches the same path through `systemctl reload
goisisd`, which polkit can grant without granting root. Ship it root-owned and
`0640` at most. What that does not reach is authentication: every `area-*` and
`domain-*` key needs a restart, so a writable file buys the reachability this
node advertises, never the ability to turn HMAC off.

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

`goisis flex-algo`'s `CONSTRAINTS` column lists the elected definition's
constraint sub-sub-TLVs (RFC 9350 §6) — exclude and include admin groups as the
4-octet units RFC 7308 defines them in, the definition flags, excluded SRLGs.
goisis reports them but does not prune on them: the computation is
IGP-metric-only, so a constrained definition still yields a plain IGP-metric
path.

`database`'s `LIFETIME` column is this node's own view, not the originator's: a
received LSP is aged from MaxAge whenever it arrived with less (RFC 7987, see
[Metrics](#metrics)), so the column says how long *this* node will hold the
LSP. "Is this LSP about to age out?" is answerable only on the node that
originates it, where the row is marked `*`.

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

`prefix add` and the file's `prefixes` refuse the same thing, so that the
daemon starts and reloads on the same set of files: what could never be routed
to — multicast, unspecified, link-local and IPv4-mapped prefixes, and a metric
at or above the RFC 5305 reachability ceiling (`0xfe000000`), which means
"unreachable". A default route is not refused — originating one is legitimate,
and `policy.advertise` is the knob that suppresses it.

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
(reasons: `decode`, `auth`, `link_down`, `no_adjacency`, `checksum`,
`lsdb_limit`, `adjacency_limit`, `hello_invalid`, `hello_mismatch`,
`duplicate_system_id`, `unknown_purge`, `own_sysid_purge`,
`own_fragment_purge`, `own_lsp_reclaimed`, `own_seq_wrap`),
`goisis_pdu_tx_errors_total{circuit,reason}` (reasons: `serialize`, `auth`,
`send`), `goisis_pdu_rx_errors_total{circuit}`,
`goisis_adjacencies{circuit,level}`, `goisis_routes{level,algorithm}`,
`goisis_fib_errors_total{op}` (ops: `update`, `withdraw`, `add_sid`,
`remove_sid`), `goisis_event_queue_depth`,
`goisis_config_reloads_total{outcome}` (outcomes: `applied`, `refused`,
`partial`), `goisis_lsp_lifetime_floored_total{circuit}` and
`goisis_inter_level_prefixes{direction}` (directions: `l2_to_l1`, `l1_to_l2`).

An adjacency that will not come up is one of three drop reasons.
`hello_invalid` is a hello this circuit cannot use at all — sent as LAN on a
point-to-point circuit or the reverse, a zero holding time, or a level the
circuit does not run. `hello_mismatch` is a hello from a network we are not
part of: no area address in common on Level 1, or no level in common.
`duplicate_system_id` is another router using this node's System ID. The
branch behind each one is in the `drop hello` line at Debug level.

A transmit or receive error is a circuit that cannot carry the protocol, not
a protocol disagreement: both are retried on the next tick and both are
logged only on the edge of the outage, so only the rate shows an outage that
persists.

```
rate(goisis_pdu_tx_errors_total[5m]) > 0
rate(goisis_pdu_rx_errors_total[5m]) > 0
```

The four `own_*` drop reasons are PDUs carrying this node's own System ID:
they drove a re-origination or a purge rather than being discarded, and they
occur in normal operation (a restart with a stale copy of ours still in the
area, a DIS handover). Alert on the rest, and watch those separately — a
steady rate means another node is originating LSPs in this node's name:

```
rate(goisis_pdu_drops_total{reason!~"own_.*"}[5m]) > 0
rate(goisis_pdu_drops_total{reason=~"own_.*"}[15m]) > 0
```

A `partial` reload outcome is the one to alert on: `refused` left the node
running a configuration somebody wrote, `partial` left it in neither, and no
further signal repairs that by itself.

```
increase(goisis_config_reloads_total{outcome="partial"}[1h]) > 0
```

`goisis_lsp_lifetime_floored_total` counts received LSPs whose remaining
lifetime RFC 7987 raised to MaxAge. That field sits outside the checksum and
outside the authentication hash, and the floor is what stops a corrupted one
from purging the LSP early — which also removed the only symptom the corruption
used to produce.

The counter does not separate that corruption from ordinary aging, and no
absolute value of it means anything. Every LSP that has aged since it left its
originator is floored the same way, so the baseline is the circuit's LSP arrival
rate: an ordinary re-flood, a refresh, and the whole-database resync a new
adjacency triggers all count, the resync as one burst. The clean separation
would need how long the receiving adjacency has been Up (RFC 7987 §3.2's
false-positive filter), and the update process does not carry that down to the
LSP it is installing, so there is no threshold to alert on — including "greater
than zero".

Read it comparatively instead: one circuit's rate against the other circuits of
the same node, over a window with no adjacency change in it, allowing for how
much flooding each carries (a LAN with more neighbours receives more copies of
the same LSP than a point-to-point link does). A circuit that stands out and
stays out is the one to take a capture on; a spike that lines up with an
adjacency coming up is the resync.

```
rate(goisis_lsp_lifetime_floored_total[1h])   # compare circuits, not a threshold
```

`goisis_inter_level_prefixes` is what this node injects across the level
boundary, where `goisis_routes` is what it learned. It is the gauge a
`policy.leak-l2-to-l1` edit moves, and the one that shows a whole Level-2 table
entering a Level-1 area before the Level-1 LSP goes oversize.

An `oversize` flood drop is a neighbor whose database can never catch up: the
LSP is larger than the circuit MTU and a transit node may not re-fragment a
foreign LSP (ISO 10589 7.3.3), so it is requested by PSNP and dropped again on
every retransmission. Any sustained rate means the originator must be told to
use a smaller LSP MTU:

```
rate(goisis_flooding_lsp_drops_total[5m]) > 0
```
