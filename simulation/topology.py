r"""Campus-style Mininet topology for collecting a labelled flow dataset.

                         controller (OpenFlow 1.3)
                                 |
                              s1 core
              /            /           \             \
          s3 access    s4 access    s5 access       s2 data centre
         /  |  |  \     ...           ...              |
       h1  h2  h3  h4                                 srv  10.0.0.100
                                                      web service :80, UDP lookup :9053

Every access switch has the same mix of hosts: mostly normal clients plus a few attacker
hosts, so attack traffic does not all enter at one place and normal and attack flows share
the same paths, queues and congestion. The capture point is the data-centre switch's port
toward the server, which every flow to the server crosses.

The tree is loop-free (the controller floods unknown destinations) and every link is shaped,
so a flood congests the server link the way it would in a real network.
"""

from __future__ import annotations

from dataclasses import dataclass

SERVER_IP = "10.0.0.100"
SERVER_MAC = "00:00:00:00:00:64"
CORE, DATACENTRE = "s1", "s2"


@dataclass(frozen=True)
class HostSpec:
    name: str
    ip: str
    mac: str
    role: str    # client | attacker
    switch: str  # access switch it hangs off


def host_plan(access: int = 3, hosts_per_access: int = 4, attackers_per_access: int = 1) -> list[HostSpec]:
    """Hosts h1..hN; on every access switch the last `attackers_per_access` are attackers."""
    if not 0 <= attackers_per_access < hosts_per_access:
        raise ValueError("each access switch needs at least one normal client")
    if access * hosts_per_access > 99:
        raise ValueError("at most 99 hosts (addresses 10.0.0.1-99; .100 is the server)")
    hosts, n = [], 0
    for a in range(access):
        switch = f"s{3 + a}"
        for k in range(hosts_per_access):
            n += 1
            role = "attacker" if k >= hosts_per_access - attackers_per_access else "client"
            hosts.append(HostSpec(f"h{n}", f"10.0.0.{n}", f"00:00:00:00:00:{n:02x}", role, switch))
    return hosts


def build_net(hosts: list[HostSpec], controller_port: int = 6653, host_bw: float = 10,
              uplink_bw: float = 100, server_bw: float = 20, delay: str = "2ms"):
    """The Mininet network for `hosts` (imported lazily: Mininet needs root)."""
    from mininet.link import TCLink
    from mininet.net import Mininet
    from mininet.node import OVSSwitch, RemoteController
    from mininet.topo import Topo

    class CampusTopo(Topo):
        def build(self):
            core = self.addSwitch(CORE, protocols="OpenFlow13")
            dc = self.addSwitch(DATACENTRE, protocols="OpenFlow13")
            self.addLink(dc, core, bw=uplink_bw, delay="1ms")
            srv = self.addHost("srv", ip=f"{SERVER_IP}/24", mac=SERVER_MAC)
            self.addLink(srv, dc, bw=server_bw, delay="1ms")  # srv side first: srv-eth0
            for switch in sorted({h.switch for h in hosts}, key=lambda s: int(s[1:])):
                self.addSwitch(switch, protocols="OpenFlow13")
                self.addLink(switch, core, bw=uplink_bw, delay="1ms")
            for h in hosts:
                self.addHost(h.name, ip=f"{h.ip}/24", mac=h.mac)
                self.addLink(h.name, h.switch, bw=host_bw, delay=delay)

    return Mininet(
        topo=CampusTopo(),
        switch=lambda name, **kw: OVSSwitch(name, failMode="secure", **kw),
        controller=lambda name: RemoteController(name, ip="127.0.0.1", port=controller_port),
        link=TCLink, autoSetMacs=False, waitConnected=True,
    )


def describe(hosts: list[HostSpec]) -> str:
    lines = []
    for switch in sorted({h.switch for h in hosts}, key=lambda s: int(s[1:])):
        members = [h for h in hosts if h.switch == switch]
        lines.append(f"  {switch} access: " + "  ".join(f"{h.name}({h.role[0]})" for h in members))
    return "\n".join([f"  {CORE} core  ·  {DATACENTRE} data centre: srv {SERVER_IP}", *lines,
                      "  (c) = normal client, (a) = attacker"])
