# Configuration reference

`goisisd -f <file>` loads a YAML configuration and translates it into server
options. ([日本語](configuration.ja.md))

## Top-level keys

| Key | Type | Description |
|-----|------|-------------|
| `net` | string (required) | Network Entity Title: area address + 6-octet system ID. The last octet (NSEL) must be `00`, e.g. `49.0001.0000.0000.0001.00`. |
| `hostname` | string | Dynamic hostname advertised in LSPs (RFC 5301). |
| `fib` | bool | Program computed routes into the Linux kernel FIB tagged `proto isis`. Requires `CAP_NET_ADMIN`. Default `false` (control-plane only). |
| `overload-on-startup` | duration | Set the overload bit for this long after startup, then clear it (e.g. `30s`). While set, peers route no transit traffic through this node. |
| `area-password` | string | Authenticate Level-1 LSPs and SNPs with this key. |
| `area-auth-algorithm` | string | `md5` (default, RFC 5304; FRR's `area-password md5`), or `sha1`/`sha256`/`sha384`/`sha512` (RFC 5310). |
| `area-key-id` | uint16 | RFC 5310 key ID (SHA only). |
| `domain-password` / `domain-auth-algorithm` / `domain-key-id` | | The same, for Level-2. |

> FRR's IS-IS authentication is HMAC-MD5 only, so the SHA variants (RFC 5310)
> interop goisis↔goisis, not with FRR.
| `circuits` | list (required) | Interfaces to run IS-IS on; see below. |
| `prefixes` | list of CIDR | Extra prefixes to originate. Connected subnets of the circuits are advertised automatically. |
| `srv6` | object | SRv6 locators; see below. |
| `flex-algo` | list | Flexible Algorithm definitions; see below. |

## `circuits[]`

| Key | Type | Description |
|-----|------|-------------|
| `interface` | string (required) | Interface name (AF_PACKET). |
| `level` | string | `"1"`, `"2"`, or `"12"` (default `"12"`). |
| `p2p` | bool | Point-to-point procedures (RFC 5303 three-way) instead of broadcast/DIS. |
| `priority` | uint8 | DIS election priority on a LAN, 0–127 (default 64). |
| `metric` | uint32 | Circuit wide metric (default 10). |
| `hello-password` | string | Enables HMAC hello authentication. Hellos are signed with it and received hellos must carry a matching digest or they are dropped. |
| `hello-auth-algorithm` | string | `md5` (default, RFC 5304; FRR's `isis password md5`), or an HMAC-SHA variant (RFC 5310). |
| `hello-key-id` | uint16 | RFC 5310 key ID (SHA only). |

IPv4 and link-local IPv6 addresses configured on the interface are advertised in
hellos (TLV 132/232) and used as next hops; their connected subnets are
originated automatically (and never installed over the kernel's connected route).

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
`seg6local` End route.

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
`global`, `circuit`, `neighbor`, `database`, `route`, `locator`, `flex-algo`,
and `monitor` (streams `WatchEvent`).

`locator` and `flex-algo` also reconfigure the daemon at runtime:

```console
$ goisis flex-algo add 128 --priority 100 --advertise
$ goisis locator add fc00:0:128::/48 --algo 128
$ goisis locator delete fc00:0:128::/48
$ goisis flex-algo delete 128
```

## Metrics

`goisisd` serves Prometheus metrics at `/metrics`:
`goisis_adjacency_transitions_total`, `goisis_spf_duration_seconds`,
`goisis_lsdb_lsps`, `goisis_flooding_lsp_tx_total`.
