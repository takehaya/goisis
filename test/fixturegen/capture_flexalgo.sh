#!/usr/bin/env bash
# Capture Flex-Algo IS-IS LSPs from two FRR routers, to ground the SR-Algorithm
# (sub-TLV 19) / Flexible Algorithm Definition (sub-TLV 26) codec and to verify
# the FRR flex-algo configuration used by the interop test.
set -euo pipefail
IMAGE="${FRR_IMAGE:-quay.io/frrouting/frr:10.6.1}"
OUT="${1:-/tmp/goisis-flexalgo}"
mkdir -p "$OUT"

cleanup() { sudo docker rm -f f1 f2 >/dev/null 2>&1 || true; sudo ip link del f1e >/dev/null 2>&1 || true; }
cleanup
trap cleanup EXIT

sudo docker run --rm --entrypoint cat "$IMAGE" /etc/frr/daemons | sed 's/^isisd=no/isisd=yes/' > "$OUT/daemons"

mkconf() { # $1 name, $2 sysid digit, $3 priority
  cat > "$OUT/$1.conf" <<EOF
hostname $1
!
interface eth0
 ip router isis 1
 ipv6 router isis 1
 isis network point-to-point
!
router isis 1
 net 49.0001.0000.0000.000$2.00
 is-type level-1-2
 metric-style wide
 flex-algo 128
  advertise-definition
  priority $3
 exit
!
EOF
}
mkconf f1 1 100
mkconf f2 2 200

for n in f1 f2; do
  sudo docker run -d --name "$n" --network none --privileged \
    -v "$OUT/daemons:/etc/frr/daemons:ro" -v "$OUT/$n.conf:/etc/frr/frr.conf:ro" "$IMAGE" >/dev/null
done
P1=$(sudo docker inspect -f '{{.State.Pid}}' f1); P2=$(sudo docker inspect -f '{{.State.Pid}}' f2)
sudo ip link add f1e type veth peer name f2e
sudo ip link set f1e netns "$P1"; sudo ip link set f2e netns "$P2"
sudo nsenter -t "$P1" -n ip link set f1e name eth0; sudo nsenter -t "$P1" -n ip link set eth0 up
sudo nsenter -t "$P1" -n ip addr add 2001:db8::1/64 dev eth0
sudo nsenter -t "$P2" -n ip link set f2e name eth0; sudo nsenter -t "$P2" -n ip link set eth0 up
sudo nsenter -t "$P2" -n ip addr add 2001:db8::2/64 dev eth0

echo "capturing 40s (waiting for Flex-Algo LSP origination)..."
sudo nsenter -t "$P1" -n timeout 40 tcpdump -i eth0 -s 0 -w "$OUT/flexalgo.pcap" 2>/dev/null || true
sudo chown "$(id -u):$(id -g)" "$OUT/flexalgo.pcap"
echo "=== FRR f1 flex-algo ==="
sudo docker exec f1 vtysh -c "show isis flex-algo" 2>/dev/null | head -30
echo "=== FRR f1 database detail (capability/flex-algo lines) ==="
sudo docker exec f1 vtysh -c "show isis database detail" 2>/dev/null | grep -iE 'algorithm|flex|capab|priority' | head -20
echo "done: $OUT/flexalgo.pcap"
