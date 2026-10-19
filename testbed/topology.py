r"""Repeatable Mininet topology for the DDoS experiments.

    controller (remote, OpenFlow 1.3)
         |
        s1 ---- s2
       /  \      \
     srv  h1 ...  hN         (srv = protected web service, h* = client/attacker hosts)

A two-switch tree (loop-free, so controller flooding is safe). The server is on s1; the
hosts alternate between s1 (odd) and s2 (even). run_experiment.py makes the odd ones
attackers and the even ones normal clients, so normal traffic crosses the link between the
switches. All links are shaped (bandwidth + delay) so an unblocked flood really does slow
the service, which is what the experiments measure.

This module is imported by testbed/run_experiment.py; it can also be run standalone for
a CLI:  sudo python3 testbed/topology.py --hosts 6
"""

import argparse

from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

SERVER_IP = "10.0.0.100"
SERVER_MAC = "00:00:00:00:00:64"


class DDoSTopo(Topo):
    def build(self, n_hosts=6, link_bw=20, link_delay="2ms", edge_bw=10):
        s1 = self.addSwitch("s1", protocols="OpenFlow13")
        s2 = self.addSwitch("s2", protocols="OpenFlow13")
        self.addLink(s1, s2, bw=link_bw, delay=link_delay)
        # Protected server on s1.
        srv = self.addHost("srv", ip=f"{SERVER_IP}/24", mac=SERVER_MAC)
        self.addLink(srv, s1, bw=link_bw, delay=link_delay)
        # Client/attacker hosts h1.., split across the two switches.
        for i in range(1, n_hosts + 1):
            host = self.addHost(f"h{i}", ip=f"10.0.0.{i}/24", mac=f"00:00:00:00:00:{i:02x}")
            self.addLink(host, s1 if i % 2 else s2, bw=edge_bw, delay=link_delay)


def build_net(n_hosts=6, controller_port=6653, **kwargs) -> Mininet:
    topo = DDoSTopo(n_hosts=n_hosts, **kwargs)
    net = Mininet(
        topo=topo,
        # protocols is set per switch by addSwitch(...) via **kw; set only failMode here
        switch=lambda name, **kw: OVSSwitch(name, failMode="secure", **kw),
        controller=lambda name: RemoteController(name, ip="127.0.0.1", port=controller_port),
        link=TCLink,
        autoSetMacs=False,
        waitConnected=True,
    )
    return net


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", type=int, default=6)
    ap.add_argument("--controller-port", type=int, default=6653)
    args = ap.parse_args()
    setLogLevel("info")
    from mininet.cli import CLI

    net = build_net(args.hosts, args.controller_port)
    net.start()
    net.pingAll()
    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()
