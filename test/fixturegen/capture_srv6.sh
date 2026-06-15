#!/usr/bin/env bash
# Capture SRv6-enabled IS-IS LSPs from two FRR routers, to ground the
# TLV 242 (Router Capability) / TLV 27 (SRv6 Locator) codec.
set -euo pipefail
IMAGE="${FRR_IMAGE:-quay.io/frrouting/frr:10.6.1}"
OUT="${1:-/tmp/goisis-srv6}"
mkdir -p "$OUT"

cleanup() { sudo docker rm -f s1 s2 >/dev/null 2>&1 || true; sudo ip link del s1e >/dev/null 2>&1 || true; }
cleanup
trap cleanup EXIT

sudo docker run --rm --entrypoint cat "$IMAGE" /etc/frr/daemons | sed 's/^isisd=no/isisd=yes/' > "$OUT/daemons"

mkconf() { # $1 name, $2 sysid digit, $3 locator prefix
  cat > "$OUT/$1.conf" <<EOF
hostname $1
!
segment-routing
 srv6
  locators
   locator loc1
    prefix $3 block-len 32 node-len 16 func-bits 16
   exit
  exit
 exit
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
 segment-routing srv6
  locator loc1
 exit
!
EOF
}
mkconf s1 1 fc00:0:1::/48
mkconf s2 2 fc00:0:2::/48

for n in s1 s2; do
  sudo docker run -d --name "$n" --network none --privileged \
    -v "$OUT/daemons:/etc/frr/daemons:ro" -v "$OUT/$n.conf:/etc/frr/frr.conf:ro" "$IMAGE" >/dev/null
done
P1=$(sudo docker inspect -f '{{.State.Pid}}' s1); P2=$(sudo docker inspect -f '{{.State.Pid}}' s2)
sudo ip link add s1e type veth peer name s2e
sudo ip link set s1e netns "$P1"; sudo ip link set s2e netns "$P2"
sudo nsenter -t "$P1" -n ip link set s1e name eth0; sudo nsenter -t "$P1" -n ip link set eth0 up
sudo nsenter -t "$P1" -n ip addr add 2001:db8::1/64 dev eth0
sudo nsenter -t "$P2" -n ip link set s2e name eth0; sudo nsenter -t "$P2" -n ip link set eth0 up
sudo nsenter -t "$P2" -n ip addr add 2001:db8::2/64 dev eth0

echo "capturing 40s (waiting for SRv6 LSP origination)..."
sudo nsenter -t "$P1" -n timeout 40 tcpdump -i eth0 -s 0 -w "$OUT/srv6.pcap" 2>/dev/null || true
sudo chown "$(id -u):$(id -g)" "$OUT/srv6.pcap"
echo "=== FRR s1 database detail ==="
sudo docker exec s1 vtysh -c "show isis database detail" 2>/dev/null | grep -iE 'srv6|locator|capab|fc00|s2\.|s1\.' | head -20
echo "done: $OUT/srv6.pcap"
