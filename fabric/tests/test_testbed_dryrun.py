"""Drive the orchestration against a fake fablib: checks the sequence of remote commands
and the collected result files, without a FABRIC account or a slice."""

import io
import json
import sys
import tarfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import fabric_ddos.testbed as T


class FakeIface:
    def __init__(self, dev):
        self.dev = dev

    def get_device_name(self):
        return self.dev


class FakeNode:
    def __init__(self, name, log):
        self.name, self.log, self.uploads = name, log, []

    def get_site(self):
        return "FAKE"

    def get_interface(self, network_name):
        return FakeIface(f"enp-{self.name}-{network_name}")

    def upload_file(self, local, remote):
        with tarfile.open(local) as tar:
            self.uploads.append(sorted(tar.getnames()))

    def download_file(self, local, remote):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            t = time.time()
            files = {
                "telemetry.jsonl": json.dumps({"event": "telemetry", "t": t, "window": 0.5, "hosts": {}}) + "\n",
                "controller_events.jsonl": json.dumps({"ts": t, "event": "switch_connected", "dpid": 1}) + "\n",
                "detections.jsonl": "",
            }
            for fname, text in files.items():
                info = tarfile.TarInfo(fname)
                info.size = len(text.encode())
                tar.addfile(info, io.BytesIO(text.encode()))
        Path(local).write_bytes(buf.getvalue())

    def execute(self, cmd, quiet=True):
        self.log.append((self.name, cmd))
        first = cmd.splitlines()[0]
        if first.startswith("date +%s.%N >"):
            out = ""
        elif "date +%s.%N" in first:
            out = f"{time.time() + (5.0 if self.name == 'h2' else 0.0):.6f}\n"   # h2's clock is 5 s fast
        elif "/sys/class/net" in first:
            out = f"02:00:00:00:{len(self.name):02x}:{sum(map(ord, first)) % 256:02x}\n"
        elif "/status" in first:
            out = json.dumps({"switches": [1], "mitigation": True, "totals": {"dropped_packets": 1234},
                              "blocks": {"10.0.0.1": {"drop_pps": 900.0, "remaining_s": 12.0, "renewals": 1}}})
        elif first.startswith("cat ") and "client_" in first:
            out = json.dumps({"ts": 1000.0, "ok": True, "latency_ms": 12.0}) + "\n"
        elif first.startswith("cat ") and "attack_start" in first:
            out = "2000.5\n"
        elif "install_" in first:
            out = "host ok: python 3.12\n"
        else:
            out = ""
        return out + "__rc=0\n", ""


class FakeSlice:
    def __init__(self):
        self.log, self.nodes = [], {}

    def get_node(self, name):
        return self.nodes.setdefault(name, FakeNode(name, self.log))


class FakeFablib:
    def __init__(self):
        self.slice = FakeSlice()

    def get_slice(self, name):
        return self.slice


def test_full_flow_against_a_fake_slice(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(T, "REPO", tmp_path)
    monkeypatch.setattr(T.time, "sleep", lambda s: None)
    fab = FakeFablib()
    tb = T.Testbed(fab, T.Config())
    tb.attach()
    tb.install()
    tb.configure_network()
    log = fab.slice.log
    uploaded = fab.slice.get_node("switch").uploads[0]   # code and model from the repository + node scripts
    for needed in ("controller/ddos_controller.py", "traffic/monitor.py", "ddos/flowmeter.py",
                   "models/random_forest.joblib", "testbed/attack.py", "./bin/start_monitor.sh",
                   "./requirements-monitor.txt"):
        assert needed in uploaded, needed

    switch_net = next(c for n, c in log if n == "switch" and "switch_net.sh" in c)
    assert switch_net.split("switch_net.sh ")[1].split()[:2] == ["20", "enp-switch-net_srv"]  # server = port 1
    routes = json.loads(next(c for n, c in log if "routes.json" in c).split("\n", 1)[1].rsplit("\n__EOF__", 1)[0])
    assert [r["port"] for r in routes] == [1, 2, 3, 4, 5] and routes[0]["ip"] == "10.0.0.100"
    host_net = next(c for n, c in log if n == "h1" and "host_net.sh" in c)
    assert " 10.0.0.1/24 " in host_net and "10.0.0.100" in host_net and " 10.0.0.1 " not in host_net.split("/24")[1]
    assert " 0 " in next(c for n, c in log if n == "srv" and "host_net.sh" in c)  # the server is not shaped

    clock = iter(x * 0.5 for x in range(10_000))        # each look at the clock advances it 0.5 s
    base = time.time()
    monkeypatch.setattr(T.time, "time", lambda: base + next(clock))
    out = tb.run_scenario("attack_mit", mitigation=True, duration=6, attack_delay=2, poll_s=1)

    cmds = [c for _, c in log]
    order = [next(i for i, c in enumerate(cmds) if key in c) for key in
             ("start_controller.sh", "webapp.py", "start_monitor.sh", "client.py", "attack.py")]
    assert order == sorted(order)
    assert "start_controller.sh ddos/runs/attack_mit 1 1" in cmds[order[0]]
    assert {n for n, c in log if "attack.py" in c} == {"h1", "h3"}
    assert {n for n, c in log if "client.py" in c} == {"h2", "h4"}
    assert "--target 10.0.0.100" in cmds[order[4]] and "--duration 4" in cmds[order[4]]

    meta = json.loads((out / "scenario.json").read_text())
    assert meta["config"]["mitigate"] is True and meta["attacker_ips"] == ["10.0.0.1", "10.0.0.3"]
    assert abs(meta["clock_offsets"]["h2"] - meta["clock_offsets"]["switch"] - 5.0) < 0.6
    h2 = json.loads((out / "client_h2.jsonl").read_text().splitlines()[0])
    h4 = json.loads((out / "client_h4.jsonl").read_text().splitlines()[0])
    assert abs((h4["ts"] - h2["ts"]) - 5.0) < 0.6      # h2's fast clock was corrected, h4's was not touched
    assert (out / "telemetry.jsonl").exists() and not (out / "run.tgz").exists()
    printed = capsys.readouterr().out
    assert "h1: 900 pps dropped, 12s left, renewed 1x" in printed and "total dropped 1,234" in printed
