#!/usr/bin/env bash
# Capture real IS-IS PDUs from two interconnected FRR routers, for use as
# golden codec fixtures. Produces two pcaps under the output dir:
#   cap_broadcast.pcap  — LAN hellos (15/16) + LSP/CSNP/PSNP
#   cap_p2p.pcap        — P2P hellos (17) + LSP/CSNP/PSNP
#
# Requires: sudo docker, host tcpdump/nsenter/ip. Run from anywhere.
set -euo pipefail

IMAGE="${FRR_IMAGE:-quay.io/frrouting/frr:10.6.1}"
OUT="${1:-/tmp/goisis-fixtures}"
CAPTURE_SECS="${CAPTURE_SECS:-35}"

mkdir -p "$OUT"

cleanup() {
  sudo docker rm -f r1 r2 >/dev/null 2>&1 || true
}
cleanup
trap cleanup EXIT

# Daemons file: start from the image default so watchfrr settings are kept,
# just enable isisd.
sudo docker run --rm --entrypoint cat "$IMAGE" /etc/frr/daemons >"$OUT/daemons"
sed -i 's/^isisd=no/isisd=yes/' "$OUT/daemons"

mk_conf() {
  # $1 = router name, $2 = system id digit, $3 = extra interface lines
  local name="$1" d="$2" extra="$3"
  cat >"$OUT/$name.conf" <<EOF
hostname $name
!
interface eth0
 ip router isis 1
 ipv6 router isis 1
$extra
!
router isis 1
 net 49.0001.0000.0000.000$d.00
 is-type level-1-2
 metric-style wide
!
EOF
}

start_pair() {
  # $1 = extra interface config lines for the topology
  local extra="$1"
  cleanup
  mk_conf r1 1 "$extra"
  mk_conf r2 2 "$extra"
  for r in r1 r2; do
    sudo docker run -d --name "$r" --network none --privileged \
      -v "$OUT/daemons:/etc/frr/daemons:ro" \
      -v "$OUT/$r.conf:/etc/frr/frr.conf:ro" \
      "$IMAGE" >/dev/null
  done
  local p1 p2
  p1=$(sudo docker inspect -f '{{.State.Pid}}' r1)
  p2=$(sudo docker inspect -f '{{.State.Pid}}' r2)

  sudo ip link add r1e type veth peer name r2e
  sudo ip link set r1e netns "$p1"
  sudo ip link set r2e netns "$p2"
  sudo nsenter -t "$p1" -n ip link set r1e name eth0
  sudo nsenter -t "$p2" -n ip link set r2e name eth0
  sudo nsenter -t "$p1" -n ip addr add 10.0.0.1/24 dev eth0
  sudo nsenter -t "$p1" -n ip addr add 2001:db8::1/64 dev eth0
  sudo nsenter -t "$p2" -n ip addr add 10.0.0.2/24 dev eth0
  sudo nsenter -t "$p2" -n ip addr add 2001:db8::2/64 dev eth0
  sudo nsenter -t "$p1" -n ip link set eth0 up
  sudo nsenter -t "$p2" -n ip link set eth0 up
  echo "$p1"
}

capture() {
  # $1 = output pcap, $2 = r1 pid
  local pcap="$1" pid="$2"
  echo "capturing $pcap for ${CAPTURE_SECS}s ..."
  sudo nsenter -t "$pid" -n timeout "$CAPTURE_SECS" tcpdump -i eth0 -s 0 -w "$pcap" 2>/dev/null || true
}

echo "=== broadcast topology ==="
P1=$(start_pair "")
sleep 3
capture "$OUT/cap_broadcast.pcap" "$P1"

echo "=== point-to-point topology ==="
P1=$(start_pair " isis network point-to-point")
sleep 3
capture "$OUT/cap_p2p.pcap" "$P1"

sudo chown "$(id -u):$(id -g)" "$OUT"/*.pcap
echo "done: $OUT/cap_broadcast.pcap $OUT/cap_p2p.pcap"
