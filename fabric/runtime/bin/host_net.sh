#!/usr/bin/env bash
# Configure a host's data-plane interface.
#   host_net.sh <dev> <ip/prefix> <switch_port_mac> <rate_mbit> <peer_ip>...
# Every peer is reached through the switch node, so each peer IP gets a permanent
# neighbour entry pointing at the MAC of the switch port on this host's link. The switch
# port (an SR-IOV virtual function) only accepts frames addressed to its own MAC.
set -euo pipefail
dev="$1"; addr="$2"; gw_mac="$3"; rate="$4"; shift 4
sudo ip addr flush dev "$dev"
sudo ip addr add "$addr" dev "$dev"
sudo ip link set "$dev" up
for peer in "$@"; do
    sudo ip neigh replace "$peer" lladdr "$gw_mac" dev "$dev" nud permanent
done
# Shape egress like the emulated testbed's 10 Mbit/s edge links (0 = leave unshaped).
sudo tc qdisc del dev "$dev" root 2>/dev/null || true
if [ "$rate" != "0" ]; then
    sudo tc qdisc add dev "$dev" root tbf rate "${rate}mbit" burst 64kb latency 50ms
fi
ip -br addr show dev "$dev"
