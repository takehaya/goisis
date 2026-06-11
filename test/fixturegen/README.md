# fixturegen — golden codec fixtures from FRR

The byte-exact golden fixtures under `pkg/packet/testdata/frr_pdu_*.bin` are
real IS-IS PDUs captured from two interconnected FRR `isisd` routers. The
codec's golden test re-serializes each and asserts byte-for-byte agreement
with FRR, which is goisis's primary wire-format interop guarantee.

## Regenerating

Requires `sudo docker`, and host `tcpdump`/`nsenter`/`ip`.

```console
$ bash test/fixturegen/capture.sh /tmp/goisis-fixtures
$ go run ./test/fixturegen -out pkg/packet/testdata \
    /tmp/goisis-fixtures/cap_p2p.pcap \
    /tmp/goisis-fixtures/cap_broadcast.pcap
```

`capture.sh` brings up two FRR containers (`quay.io/frrouting/frr`) connected
by a veth pair — once as a broadcast LAN and once as a point-to-point link —
and captures ~35s of IS-IS traffic from each. `main.go` carves the IS-IS PDU
out of each 802.3/LLC frame and writes the largest PDU per fixture key.

Fixture names are `frr_pdu_<type>[_<discriminator>].bin`; the leading digits
are the PDU type. LSPs are split by LSP ID so per-router fragment-0 LSPs and
the DIS pseudonode LSP are all captured.

The capture is non-deterministic (timestamps, padding); the committed `.bin`
files are the golden data. The source `.pcap`s are kept under `captures/` for
offline reproducibility.
