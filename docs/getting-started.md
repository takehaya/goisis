# Getting started

A hands-on tour: bring up a two-node IS-IS network, embed goisis as a library,
try the main features, and interoperate with FRR. ([日本語](getting-started.ja.md))

See also the [configuration reference](configuration.md) and the
[library guide](library.md).

## Prerequisites

- Go (see `go.mod` for the version) to build from source, or grab a release.
- Linux for the daemon (AF_PACKET sockets and the netlink FIB). The library and
  unit tests run anywhere Go does.
- `iproute2` for the network-namespace walkthrough below; Docker only for the
  FRR interop section.

## Install

```console
$ go install github.com/takehaya/goisis/cmd/goisisd@latest
$ go install github.com/takehaya/goisis/cmd/goisis@latest
```

Or build from source:

```console
$ git clone https://github.com/takehaya/goisis && cd goisis
$ make bin            # builds bin/goisisd and bin/goisis
```

`goisisd` opens AF_PACKET sockets (`CAP_NET_RAW`) and programs the FIB
(`CAP_NET_ADMIN`). Run it as root, grant the caps with `setcap`, or — as below —
run it inside a network namespace where you are already root.

```console
$ sudo setcap cap_net_raw,cap_net_admin+ep bin/goisisd
```

## 1. A two-node network from scratch

This builds two routers wired back-to-back with a veth pair in two network
namespaces — no hardware, no containers. Everything runs as root inside the
namespaces, so no `setcap` is needed.

### Wire up the namespaces

```console
$ sudo ip netns add ns1
$ sudo ip netns add ns2
$ sudo ip link add veth1 netns ns1 type veth peer name veth2 netns ns2

# ns1: 10.0.0.1 on the link, 10.1.1.1/32 as a loopback to advertise
$ sudo ip netns exec ns1 sh -c '
    ip addr add 10.0.0.1/24 dev veth1
    ip addr add 10.1.1.1/32 dev lo
    ip link set veth1 up; ip link set lo up'

# ns2: 10.0.0.2 on the link, 10.2.2.2/32 as a loopback to advertise
$ sudo ip netns exec ns2 sh -c '
    ip addr add 10.0.0.2/24 dev veth2
    ip addr add 10.2.2.2/32 dev lo
    ip link set veth2 up; ip link set lo up'
```

### Configure and run the daemons

`r1.yaml`:

```yaml
net: 49.0001.0000.0000.0001.00   # area 49.0001, system ID ...0001
hostname: r1
fib: true
circuits:
  - interface: veth1
    level: "2"
prefixes:
  - 10.1.1.1/32
```

`r2.yaml` is the same with system ID `...0002`, `veth2`, and `10.2.2.2/32`.

```console
$ sudo ip netns exec ns1 goisisd -f r1.yaml &
$ sudo ip netns exec ns2 goisisd -f r2.yaml &
```

### Watch it converge

The `goisis` CLI talks to the daemon in the same namespace.

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

`goisis monitor` streams adjacency and route changes as they happen (handy in a
second terminal while you flap `veth1`).

### Tear down

```console
$ sudo ip netns del ns1; sudo ip netns del ns2   # also stops the daemons
```

## 2. Embed goisis as a library

goisis is library-first: `pkg/server.IsisServer` is the whole control plane, and
you own forwarding. The minimal embedding reacts to route changes instead of
programming the kernel — the pattern for feeding an eBPF dataplane.

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
		// No WithFIB: keep it control-plane only and consume routes ourselves.
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
	_ = unix.RT_TABLE_MAIN // use fib.NewNetlink(...) with WithFIB to program the kernel instead
}
```

A runnable version is in [`examples/watchroutes`](../examples/watchroutes). To
program the kernel instead, pass `server.WithFIB(fib.NewNetlink(unix.RT_TABLE_MAIN))`.
The [library guide](library.md) covers every option, custom FIBs, and metrics.

## 3. Feature tour

All of these are YAML for the daemon; each has a `With…` option for the library
(see the [library guide](library.md)).

### SRv6 locators (RFC 9352)

```yaml
srv6:
  locators:
    - fc00:0:1::/48
```

Advertised in the SRv6 Locator TLV with a local End SID at the base address;
with `fib: true` that End SID is installed as a `seg6local` route. `goisis
locator` lists them.

### Flexible Algorithm (RFC 9350)

```yaml
flex-algo:
  - algo: 128
    metric-type: igp
    priority: 100
    advertise: true
    locator: fc00:0:128::/48   # a locator computed over algo 128's topology
```

`goisis flex-algo` shows the elected definition and participants. Flex-Algo is
also the IGP way to get per-algorithm "separate RIBs".

### Route policy (filters)

IS-IS never filters the flooded LSDB (that would break the area). Policy applies
only at the edges, as prefix-lists:

```yaml
policy:
  fib:                # which computed routes reach the kernel
    default: permit
    rules:
      - deny: 0.0.0.0/0
        le: 32        # control-plane only: keep IPv4 in the RIB, not the kernel
```

`advertise` gates which prefixes this node originates; `fib` gates which routes
are programmed. Rejected `fib` routes stay in the RIB (visible via `goisis route`
and `WatchEvent`). See the [configuration reference](configuration.md#policy).

### Authentication (RFC 5304 / 5310)

```yaml
area-password: s3cret          # HMAC-MD5 of Level-1 LSPs/SNPs (FRR-compatible)
domain-password: s3cret        # ... Level-2
# area-auth-algorithm: sha256  # HMAC-SHA (RFC 5310) instead of MD5
circuits:
  - interface: veth1
    hello-password: s3cret     # HMAC-MD5 of hellos
```

## 4. Interop with FRR

goisis interoperates with FRR's isisd. A minimal FRR `/etc/frr/frr.conf` for a
point-to-point link:

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

Point a goisis node at the other end of the link with `p2p: true`:

```yaml
net: 49.0001.0000.0000.0001.00
circuits:
  - interface: eth0
    level: "2"
    p2p: true
prefixes:
  - 10.1.1.1/32
```

The adjacency comes up both ways and routes are exchanged. goisis is tested
continuously against FRR 10.6.1 — see [`test/interop`](../test/interop) for the
full container topologies (LAN/p2p adjacency, LSDB sync, routes, SRv6, Flex-Algo,
and authentication). Note: FRR's IS-IS auth is MD5-only, so the HMAC-SHA variants
are validated goisis↔goisis.

## Where to next

- [Configuration reference](configuration.md) — every YAML key.
- [Library guide](library.md) — embedding, custom FIB, metrics, runtime
  reconfiguration.
- [`examples/watchroutes`](../examples/watchroutes) — a runnable library consumer.
- `CLAUDE.md` — architecture and contributor notes.
