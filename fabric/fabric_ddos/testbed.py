"""Build and drive the DDoS mitigation testbed on a FABRIC slice.

Topology (one site): a switch node running Open vSwitch, the OpenFlow controller and the
traffic monitor, with one point-to-point L2 network to every host.

                     switch  (OVS br0 + controller + monitor)
               /        |         |         \\         \\
            srv        h1        h3         h2        h4
        web service  attacker  attacker   client    client
        10.0.0.100   10.0.0.1  10.0.0.3   10.0.0.2  10.0.0.4

Forwarding is by destination IP with both MACs rewritten (the controller's static routes):
the switch ports are SR-IOV virtual functions that only accept and emit their own MAC, so a
learning bridge cannot be trusted. Each host therefore has a fixed neighbour entry sending
every peer's traffic to the switch port on its own link.

Only long-stable fablib calls are used: new_slice / add_node / add_component / add_l2network
/ submit / get_slice / get_node / get_interface / get_device_name / execute / upload_file /
download_file / delete.
"""

from __future__ import annotations

import json
import tarfile
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]   # the fabric/ folder: notebook, results, node scripts
PROJECT = REPO.parent                         # the repo: the code and model that get deployed
RUNTIME = REPO / "runtime"                    # node scripts and pinned requirements
# What the nodes need from the repo, uploaded as-is so the slice runs the code and model
# checked out here.
PAYLOAD = [
    "controller/ddos_controller.py",
    "ddos/__init__.py", "ddos/features.py", "ddos/flowmeter.py", "ddos/pcapio.py", "ddos/model_io.py",
    "traffic/monitor.py",
    "testbed/webapp.py", "testbed/client.py", "testbed/attack.py",
    "models/random_forest.joblib", "models/random_forest.schema.json",
]
SWITCH = "switch"
ATTACKING_PPS = 200.0


@dataclass
class Config:
    slice_name: str = "ddos-mitigation"
    site: str | None = None            # None = let FABRIC pick a site with free resources
    image: str = "default_ubuntu_24"   # Python 3.12, which the pinned libraries support
    nic_model: str = "NIC_Basic"
    n_attackers: int = 2
    n_clients: int = 2
    switch_cores: int = 4
    switch_ram: int = 8
    switch_disk: int = 20
    host_cores: int = 2
    host_ram: int = 4
    host_disk: int = 10
    server_ip: str = "10.0.0.100"
    prefix: int = 24
    server_rate_mbit: int = 20         # shaping of the server link (0 = none)
    host_rate_mbit: int = 10           # shaping of every host's uplink (0 = none)
    block_seconds: int = 20            # lifetime of a drop rule before renewal or expiry
    window: float = 6.0                # per-source vote window of the monitor
    min_flows: int = 5
    attack_threads: int = 8
    benign_rate: float = 2.0           # requests/s per client worker
    benign_workers: int = 2
    remote_dir: str = "ddos"           # under the login user's home on every node


@dataclass(frozen=True)
class Host:
    name: str
    ip: str
    role: str  # server | attacker | client

    @property
    def net(self) -> str:
        return f"net_{self.name}"


def hosts_for(cfg: Config) -> list[Host]:
    """Server first (it becomes OpenFlow port 1), attackers on odd IPs, clients on even."""
    net = cfg.server_ip.rsplit(".", 1)[0]
    hosts = [Host("srv", cfg.server_ip, "server")]
    hosts += [Host(f"h{2 * i + 1}", f"{net}.{2 * i + 1}", "attacker") for i in range(cfg.n_attackers)]
    hosts += [Host(f"h{2 * i + 2}", f"{net}.{2 * i + 2}", "client") for i in range(cfg.n_clients)]
    return hosts


class CommandError(RuntimeError):
    pass


class Testbed:
    def __init__(self, fablib, cfg: Config | None = None):
        self.fablib = fablib
        self.cfg = cfg or Config()
        self.hosts = hosts_for(self.cfg)
        self.slice = None
        self.links: dict[str, dict] = {}  # host name -> devices and MACs on both ends of its link

    # ------------------------------------------------------------------ slice
    def create(self) -> None:
        """Request the slice and wait until every node is up."""
        cfg = self.cfg
        site = cfg.site or self.fablib.get_random_site()
        print(f"creating slice {cfg.slice_name!r} at {site}: 1 switch node + {len(self.hosts)} hosts")
        sl = self.fablib.new_slice(name=cfg.slice_name)
        switch = sl.add_node(name=SWITCH, site=site, cores=cfg.switch_cores, ram=cfg.switch_ram,
                             disk=cfg.switch_disk, image=cfg.image)
        for h in self.hosts:
            node = sl.add_node(name=h.name, site=site, cores=cfg.host_cores, ram=cfg.host_ram,
                               disk=cfg.host_disk, image=cfg.image)
            host_if = node.add_component(model=cfg.nic_model, name="nic").get_interfaces()[0]
            switch_if = switch.add_component(model=cfg.nic_model, name=f"nic_{h.name}").get_interfaces()[0]
            sl.add_l2network(name=h.net, interfaces=[host_if, switch_if])
        sl.submit()
        self.attach()

    def attach(self) -> None:
        """Use an existing slice (after a kernel restart, or to continue later)."""
        self.slice = self.fablib.get_slice(name=self.cfg.slice_name)

    def node(self, name: str):
        return self.slice.get_node(name=name)

    def delete(self) -> None:
        self.fablib.get_slice(name=self.cfg.slice_name).delete()
        print(f"slice {self.cfg.slice_name!r} deleted")

    # ------------------------------------------------------------------ remote commands
    def sh(self, name: str, cmd: str, check: bool = True) -> str:
        """Run a shell command on a node; raise with its output if it fails."""
        out, err = self.node(name).execute(f"{cmd}\necho __rc=$?", quiet=True)
        body, _, rc = out.rpartition("__rc=")
        rc = rc.strip() or "?"
        if check and rc != "0":
            raise CommandError(f"[{name}] exit {rc}: {cmd.splitlines()[0][:120]}\n{body[-1500:]}\n{err[-1500:]}")
        return body

    def everywhere(self, fn, names=None) -> dict:
        """Run fn(node_name) on several nodes at once; returns {name: result}."""
        names = list(names or [SWITCH] + [h.name for h in self.hosts])
        with ThreadPoolExecutor(max_workers=len(names)) as pool:
            return dict(zip(names, pool.map(fn, names)))

    def put_text(self, name: str, path: str, text: str) -> None:
        self.sh(name, f"cat > {path} <<'__EOF__'\n{text}\n__EOF__")

    # ------------------------------------------------------------------ install
    def install(self) -> None:
        """Upload the code, model and node scripts to every node and install their
        dependencies (a few minutes)."""
        missing = [f for f in PAYLOAD if not (PROJECT / f).is_file()]
        if missing:
            raise FileNotFoundError(f"not found in {PROJECT}: {missing} - the fabric/ folder must stay "
                                    "inside the ML-DDoS repository, and the model must be trained")
        rd = self.cfg.remote_dir
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "runtime.tgz"
            with tarfile.open(archive, "w:gz") as tar:
                tar.add(RUNTIME, arcname=".")
                for f in PAYLOAD:
                    tar.add(PROJECT / f, arcname=f)

            def push(name: str) -> str:
                self.node(name).upload_file(str(archive), "runtime.tgz")
                self.sh(name, f"mkdir -p {rd} && tar -xzf runtime.tgz -C {rd} && chmod +x {rd}/bin/*.sh")
                script = "install_switch.sh" if name == SWITCH else "install_host.sh"
                return self.sh(name, f"bash {rd}/bin/{script}").strip().splitlines()[-1]

            for name, line in self.everywhere(push).items():
                print(f"  {name:7s} {line}")

    # ------------------------------------------------------------------ data plane
    def _dev(self, node: str, net: str) -> str:
        return self.node(node).get_interface(network_name=net).get_device_name()

    def _mac(self, node: str, dev: str) -> str:
        return self.sh(node, f"cat /sys/class/net/{dev}/address").strip()

    def configure_network(self) -> None:
        """Addresses, neighbour entries and shaping on the hosts; the OVS bridge and static
        routes on the switch node."""
        cfg, rd = self.cfg, self.cfg.remote_dir
        for h in self.hosts:
            host_dev, sw_dev = self._dev(h.name, h.net), self._dev(SWITCH, h.net)
            self.links[h.name] = {"host_dev": host_dev, "host_mac": self._mac(h.name, host_dev),
                                  "switch_dev": sw_dev, "switch_mac": self._mac(SWITCH, sw_dev)}
        routes = [{"ip": h.ip, "port": port, "eth_dst": self.links[h.name]["host_mac"],
                   "eth_src": self.links[h.name]["switch_mac"]}
                  for port, h in enumerate(self.hosts, start=1)]
        self.put_text(SWITCH, f"{rd}/routes.json", json.dumps(routes, indent=1))
        self.put_text(SWITCH, f"{rd}/server_ip", cfg.server_ip)
        devs = " ".join(self.links[h.name]["switch_dev"] for h in self.hosts)
        self.sh(SWITCH, f"bash {rd}/bin/switch_net.sh {cfg.server_rate_mbit} {devs}")

        def host_net(name: str) -> str:
            h = next(x for x in self.hosts if x.name == name)
            link = self.links[name]
            peers = " ".join(x.ip for x in self.hosts if x.name != name)
            rate = 0 if h.role == "server" else cfg.host_rate_mbit
            return self.sh(name, f"bash {rd}/bin/host_net.sh {link['host_dev']} {h.ip}/{cfg.prefix} "
                                 f"{link['switch_mac']} {rate} {peers}").strip()

        self.everywhere(host_net, [h.name for h in self.hosts])
        print(f"{'host':6s} {'role':9s} {'address':13s} {'device':10s} {'switch port':>11s}  switch device")
        for port, h in enumerate(self.hosts, start=1):
            link = self.links[h.name]
            print(f"{h.name:6s} {h.role:9s} {h.ip:13s} {link['host_dev']:10s} {port:>11d}  {link['switch_dev']}")

    def load_links(self) -> None:
        """Rebuild the device table after attach() without changing anything."""
        for h in self.hosts:
            host_dev, sw_dev = self._dev(h.name, h.net), self._dev(SWITCH, h.net)
            self.links[h.name] = {"host_dev": host_dev, "host_mac": self._mac(h.name, host_dev),
                                  "switch_dev": sw_dev, "switch_mac": self._mac(SWITCH, sw_dev)}

    # ------------------------------------------------------------------ controller API
    def status(self) -> dict:
        return json.loads(self.sh(SWITCH, "curl -s --max-time 3 http://127.0.0.1:8080/status") or "{}")

    def _post(self, path: str, body: dict) -> dict:
        out = self.sh(SWITCH, "curl -s --max-time 3 -H 'Content-Type: application/json' "
                              f"-d '{json.dumps(body)}' http://127.0.0.1:8080{path}")
        return json.loads(out or "{}")

    def set_mitigation(self, enabled: bool) -> dict:
        return self._post("/mitigation", {"enabled": enabled})

    def block(self, ip: str, duration: int = 20) -> dict:
        return self._post("/block", {"ip": ip, "duration": duration, "reason": "manual (notebook)"})

    def unblock(self, ip: str) -> dict:
        return self._post("/unblock", {"ip": ip})

    # ------------------------------------------------------------------ run
    def stop(self, everything: bool = True) -> None:
        arg = "all" if everything else ""
        self.everywhere(lambda n: self.sh(n, f"bash {self.cfg.remote_dir}/bin/stop.sh {arg}", check=False))

    def clock_offsets(self, tries: int = 5) -> dict:
        """Each node's clock minus this machine's clock, from the fastest of a few round
        trips. Client and attacker timestamps are shifted onto the switch node's clock with
        these, so events from different machines share one time axis."""
        def one(name: str) -> float:
            best = None
            for _ in range(tries):
                t0 = time.time()
                remote = float(self.sh(name, "date +%s.%N").strip())
                t1 = time.time()
                if best is None or t1 - t0 < best[0]:
                    best = (t1 - t0, remote - (t0 + t1) / 2)
            return round(best[1], 4)
        return self.everywhere(one)

    def run_scenario(self, name: str, mitigation: bool = True, duration: float = 45,
                     attack_delay: float = 10, attack: str | None = "udp", renew: bool = True,
                     results_dir: str = "results", poll_s: float = 2.0) -> Path:
        """One run: normal clients for `duration` seconds, a flood from the attackers after
        `attack_delay`, with the detector running throughout. Prints the controller's view
        every `poll_s` seconds and returns the local directory with the collected logs."""
        if not self.links:
            self.load_links()
        cfg, rd = self.cfg, self.cfg.remote_dir
        run = f"{rd}/runs/{name}"
        attackers = [h for h in self.hosts if h.role == "attacker"]
        clients = [h for h in self.hosts if h.role == "client"]
        self.stop()
        self.everywhere(lambda n: self.sh(n, f"rm -rf {run} && mkdir -p {run}"))

        print(f"[{name}] starting controller (mitigation {'on' if mitigation else 'off'}) and monitor")
        self.sh(SWITCH, f"bash {rd}/bin/start_controller.sh {run} {int(mitigation)} {int(renew)}")
        self.sh("srv", f"sudo setsid nohup python3 {rd}/testbed/webapp.py --port 80 > {run}/webapp.log 2>&1 < /dev/null &")
        probe = (f"for i in $(seq 20); do curl -sf --max-time 2 http://{cfg.server_ip}/health >/dev/null "
                 f"&& exit 0; sleep 0.5; done; exit 1")
        try:
            self.sh(clients[0].name, probe)
        except CommandError:
            raise CommandError(
                "the web service is not reachable through the switch. If `ovs-ofctl -O OpenFlow13 "
                "dump-flows br0` on the switch node shows the priority-10 routes but their packet "
                f"counters stay at 0, the {cfg.nic_model} ports are filtering frames: see the README, "
                "'If hosts cannot reach each other'.") from None
        self.sh(SWITCH, f"bash {rd}/bin/start_monitor.sh {run} {self.links['srv']['switch_dev']} "
                        f"{cfg.block_seconds} {cfg.window} {cfg.min_flows}")
        offsets = self.clock_offsets()

        t_start = time.time()
        self.everywhere(lambda n: self.sh(
            n, f"setsid nohup python3 {rd}/testbed/client.py --server {cfg.server_ip} --rate {cfg.benign_rate} "
               f"--workers {cfg.benign_workers} --duration {duration} --name {n} --seed {sum(map(ord, n))} "
               f"--log {run}/client_{n}.jsonl > {run}/client.err 2>&1 < /dev/null &"), [h.name for h in clients])
        print(f"[{name}] {len(clients)} benign clients running; attack in {attack_delay:.0f} s" if attack
              else f"[{name}] {len(clients)} benign clients running, no attack")

        attacking = False
        while (elapsed := time.time() - t_start) < duration + 2:
            if attack and not attacking and elapsed >= attack_delay:
                attacking = True
                self.everywhere(lambda n: self.sh(
                    n, f"date +%s.%N > {run}/attack_start; setsid nohup python3 {rd}/testbed/attack.py "
                       f"--type {attack} --target {cfg.server_ip} --threads {cfg.attack_threads} "
                       f"--duration {duration - attack_delay} --seed {sum(map(ord, n))} "
                       f"> {run}/attack.log 2>&1 < /dev/null &"), [h.name for h in attackers])
                print(f"[{name}] t={elapsed:5.1f}s  {attack} flood started from {', '.join(h.name for h in attackers)}")
            time.sleep(poll_s)
            self._print_status(name, time.time() - t_start)

        final = self.status()
        self.stop()
        return self._collect(name, run, results_dir, offsets, final, {
            "scenario": name, "platform": "fabric", "duration": duration,
            "config": {"mitigate": mitigation, "attack": attack, "benign_rate": cfg.benign_rate, "renew": renew,
                       **{k: v for k, v in asdict(cfg).items() if k in ("block_seconds", "window", "min_flows",
                                                                         "server_rate_mbit", "host_rate_mbit")}},
            "attacker_ips": [h.ip for h in attackers], "benign_ips": [h.ip for h in clients],
            "server_ip": cfg.server_ip, "site": self.node(SWITCH).get_site(),
        }, attack_delay)

    def _print_status(self, name: str, elapsed: float) -> None:
        try:
            st = self.status()
        except (CommandError, ValueError):
            print(f"[{name}] t={elapsed:5.1f}s  controller not answering")
            return
        blocks = st.get("blocks", {})
        if not blocks:
            print(f"[{name}] t={elapsed:5.1f}s  no drop rules")
            return
        by_ip = {h.ip: h.name for h in self.hosts}
        rules = "  ".join(f"{by_ip.get(ip, ip)}: {b['drop_pps']:,.0f} pps dropped, {b['remaining_s']:.0f}s left"
                          + (f", renewed {b['renewals']}x" if b["renewals"] else "") for ip, b in sorted(blocks.items()))
        print(f"[{name}] t={elapsed:5.1f}s  {len(blocks)} drop rule(s)  {rules}  "
              f"| total dropped {st['totals']['dropped_packets']:,}")

    def _collect(self, name: str, run: str, results_dir: str, offsets: dict, final: dict,
                 meta: dict, attack_delay: float) -> Path:
        """Bring the run's logs here, every timestamp on the switch node's clock."""
        out = REPO / results_dir / name
        out.mkdir(parents=True, exist_ok=True)
        for old in out.glob("*"):
            if old.is_file():
                old.unlink()
        self.sh(SWITCH, f"tar -czf run.tgz -C {run} .")
        self.node(SWITCH).download_file(str(out / "run.tgz"), "run.tgz")
        with tarfile.open(out / "run.tgz") as tar:
            try:
                tar.extractall(out, filter="data")
            except TypeError:  # Python before 3.12 has no extraction filters
                tar.extractall(out)
        (out / "run.tgz").unlink()

        def shift(host: str) -> float:  # host clock -> switch clock
            return offsets[SWITCH] - offsets[host]

        starts = []
        for h in self.hosts:
            if h.role == "client":
                lines = []
                for line in self.sh(h.name, f"cat {run}/client_{h.name}.jsonl", check=False).splitlines():
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    rec["ts"] = round(rec["ts"] + shift(h.name), 4)
                    lines.append(json.dumps(rec))
                (out / f"client_{h.name}.jsonl").write_text("\n".join(lines) + "\n" if lines else "")
            elif h.role == "attacker":
                started = self.sh(h.name, f"cat {run}/attack_start 2>/dev/null", check=False).strip()
                if started:
                    starts.append(float(started) + shift(h.name))
                (out / f"attack_{h.name}.log").write_text(self.sh(h.name, f"cat {run}/attack.log 2>/dev/null", check=False))
        first = self._first_stamp(out / "telemetry.jsonl")
        meta.update({"attack_start": round(min(starts), 4) if starts else None,
                     "t_start": first, "clock_offsets": offsets, "final_status": final,
                     "attack_delay": attack_delay, "run_id": time.time()})
        (out / "scenario.json").write_text(json.dumps(meta, indent=2))
        print(f"[{name}] collected -> {out.relative_to(REPO)}")
        return out

    @staticmethod
    def _first_stamp(path: Path) -> float | None:
        try:
            with path.open() as fh:
                return json.loads(fh.readline())["t"]
        except (OSError, ValueError, KeyError):
            return None
