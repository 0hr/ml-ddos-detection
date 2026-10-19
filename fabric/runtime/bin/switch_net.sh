#!/usr/bin/env bash
# Build the OpenFlow 1.3 bridge on the switch node.
#   switch_net.sh <server_rate_mbit> <dev>...        first dev = server link (OpenFlow port 1)
# The bridge runs in secure fail mode: nothing is forwarded without the controller.
set -euo pipefail
rate="$1"; shift
sudo ovs-vsctl --if-exists del-br br0
sudo ovs-vsctl add-br br0 -- set bridge br0 protocols=OpenFlow13 fail-mode=secure \
    other-config:datapath-id=0000000000000001
port=1
for dev in "$@"; do
    sudo ip addr flush dev "$dev"
    sudo ip link set "$dev" up promisc on
    # Keep the tap packet-accurate: no receive coalescing into super-frames.
    sudo ethtool -K "$dev" gro off lro off >/dev/null 2>&1 || true
    sudo ovs-vsctl add-port br0 "$dev" -- set interface "$dev" ofport_request="$port"
    port=$((port + 1))
done
# Shape the server link like the emulated testbed (20 Mbit/s), so a flood that is not
# mitigated actually starves legitimate traffic (0 = leave unshaped).
srv_dev="$1"
sudo tc qdisc del dev "$srv_dev" root 2>/dev/null || true
if [ "$rate" != "0" ]; then
    sudo tc qdisc add dev "$srv_dev" root tbf rate "${rate}mbit" burst 64kb latency 50ms
fi
sudo ovs-vsctl set-controller br0 tcp:127.0.0.1:6653
sudo ovs-vsctl --columns=name,ofport list interface | paste - - - | grep -v br0 || true
