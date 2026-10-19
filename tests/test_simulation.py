"""Data-collection simulation: plan, topology, labelling, cleaning, split, and the commands
the collector sends to the hosts (against a fake network: no root, no Mininet)."""

import json
import subprocess
import sys
import types
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "simulation"))
sys.path.insert(0, str(ROOT / "ml"))

import build_dataset as B
import collect as C
import plan as P
import topology as T
from ddos.features import FEATURES, LABEL_COL


# ------------------------------------------------------------------ plan and topology
def test_default_plan():
    plan = P.make_plan()
    assert len(plan) == 18 and len({s.id for s in plan}) == 18
    assert [s.name for s in plan[:6]] == ["benign_quiet", "benign_mixed", "benign_busy",
                                          "attack_udp", "attack_conn", "attack_http"]
    assert [s.attack_threads for s in plan if s.attack == "udp"] == [2, 4, 8]  # intensity steps up per repetition
    assert [s.attack_dport_pool for s in plan if s.attack == "udp"] == [4, 16, 64]
    assert {s.label for s in plan} == {"BENIGN", "Sim-UDP-flood", "Sim-TCP-connect-flood", "Sim-HTTP-flood"}
    for s in plan:
        if s.attack:
            assert 0 < s.attack_delay and s.attack_delay + s.attack_duration < s.duration  # ends inside the capture


def test_quick_plan_and_attack_subset():
    plan = P.make_plan(reps=5, quick=True, attacks=("http",))
    assert len(plan) == 20 and all(s.duration == 30 for s in plan)
    assert {s.attack for s in plan} == {None, "http"}
    with pytest.raises(ValueError):
        P.make_plan(attacks=("ping",))


def test_topology_mixes_roles_on_every_access_switch():
    hosts = T.host_plan(access=3, hosts_per_access=4, attackers_per_access=1)
    assert [h.name for h in hosts] == [f"h{i}" for i in range(1, 13)]
    assert len({h.ip for h in hosts}) == 12 and T.SERVER_IP not in {h.ip for h in hosts}
    for switch in ("s3", "s4", "s5"):
        roles = [h.role for h in hosts if h.switch == switch]
        assert roles.count("attacker") == 1 and roles.count("client") == 3
    with pytest.raises(ValueError):
        T.host_plan(hosts_per_access=2, attackers_per_access=2)  # no legitimate client left
    with pytest.raises(ValueError):
        T.host_plan(access=10, hosts_per_access=10)               # would collide with .100


# ------------------------------------------------------------------ dataset builder
def flows(rows):
    """Flow rows: (source ip, a value that makes the feature vector unique)."""
    df = pd.DataFrame(0.0, index=range(len(rows)), columns=FEATURES)
    df["Source IP"] = [ip for ip, _ in rows]
    df["Flow Duration"] = [v for _, v in rows]
    df["Protocol"] = 6
    df["Destination IP"], df["Destination Port"], df["start_ts"] = T.SERVER_IP, 80, np.arange(len(rows), dtype=float)
    return df


def make_session(coll: Path, sid: str, rep: int, name: str, label: str, attackers, rows):
    d = coll / "sessions" / sid
    d.mkdir(parents=True)
    (d / "session.json").write_text(json.dumps({"id": sid, "rep": rep, "name": name, "label": label,
                                                "attacker_ips": attackers}))
    flows(rows).to_parquet(d / "flows.parquet")


def test_labels_come_from_the_session_and_the_flow_source(tmp_path):
    make_session(tmp_path, "r1_01_benign_quiet", 1, "benign_quiet", "BENIGN", [],
                 [("10.0.0.1", 1), ("10.0.0.4", 2)])
    make_session(tmp_path, "r1_04_attack_udp", 1, "attack_udp", "Sim-UDP-flood", ["10.0.0.4"],
                 [("10.0.0.1", 3), ("10.0.0.4", 4), ("10.0.0.4", 5), ("10.0.0.100", 6)])
    df = pd.concat(B.from_collection(tmp_path, []))
    got = dict(zip(zip(df["session"], df["Flow Duration"]), df[LABEL_COL]))
    assert got[("r1_01_benign_quiet", 2)] == "BENIGN"           # the attacker host in a benign session
    assert got[("r1_04_attack_udp", 4)] == got[("r1_04_attack_udp", 5)] == "Sim-UDP-flood"
    assert got[("r1_04_attack_udp", 3)] == "BENIGN"             # a client during the attack
    assert got[("r1_04_attack_udp", 6)] == "BENIGN"             # a flow the server started


def test_cleaning_matches_the_cic_pipeline(tmp_path):
    make_session(tmp_path, "r1_01_benign_quiet", 1, "benign_quiet", "BENIGN", [],
                 [("10.0.0.1", 1), ("10.0.0.2", 1), ("10.0.0.3", 2)])  # first two: identical features
    df = pd.concat(B.from_collection(tmp_path, []))
    df.loc[df["Flow Duration"] == 2, "Flow Packets/s"] = np.inf
    cleaned, steps = B.clean(df)
    assert steps == {"flows": 3, "finite": 2, "deduplicated": 1} and len(cleaned) == 1


def test_build_dataset_end_to_end(tmp_path):
    make_session(tmp_path, "r1_04_attack_conn", 1, "attack_conn", "Sim-TCP-connect-flood", ["10.0.0.4"],
                 [("10.0.0.1", 1), ("10.0.0.4", 2)])
    subprocess.run([sys.executable, str(ROOT / "simulation/build_dataset.py"), str(tmp_path)], check=True,
                   capture_output=True)
    out = pd.read_parquet(tmp_path / "dataset.parquet")
    assert list(out.columns[:len(FEATURES)]) == FEATURES
    assert sorted(out[LABEL_COL]) == ["BENIGN", "Sim-TCP-connect-flood"]
    summary = json.loads((tmp_path / "dataset_summary.json").read_text())
    assert summary["labels"] == {"BENIGN": 1, "Sim-TCP-connect-flood": 1}


# ------------------------------------------------------------------ comparison split
def test_sim_split_never_puts_a_session_on_both_sides():
    import compare

    rows = []
    for rep in (1, 2, 3):
        for name, label in (("benign", "BENIGN"), ("attack_udp", "Sim-UDP-flood")):
            rows += [{"session": f"r{rep}_{name}", "rep": rep, LABEL_COL: label, "start_ts": float(i)} for i in range(50)]
    sim = pd.DataFrame(rows)
    tr, va, te, how = compare.sim_split(sim, None, seed=1)
    assert "repetition 3" in how
    assert set(sim["rep"].iloc[te]) == {3} and not set(sim["session"].iloc[te]) & set(sim["session"].iloc[np.r_[tr, va]])
    assert len(np.intersect1d(tr, va)) == 0 and len(tr) + len(va) + len(te) == len(sim)

    one = sim[sim["rep"] == 1].reset_index(drop=True)
    tr, va, te, how = compare.sim_split(one, None, seed=1)
    assert "in time" in how
    for s, g in one.groupby("session"):  # the test part of a session is always its latest flows
        test_ts = one["start_ts"].iloc[np.intersect1d(te, g.index)]
        fit_ts = one["start_ts"].iloc[np.intersect1d(np.r_[tr, va], g.index)]
        assert test_ts.min() > fit_ts.max()


# ------------------------------------------------------------------ collector commands
class FakeHost:
    def __init__(self, name, log):
        self.name, self.log = name, log

    def cmd(self, c):
        self.log.append((self.name, c))
        return ""


class FakeNet:
    def __init__(self):
        self.log, self.hosts = [], {}

    def get(self, name):
        return self.hosts.setdefault(name, FakeHost(name, self.log))


def test_session_commands(tmp_path, monkeypatch):
    popen, runs = [], []

    class FakeProc:
        def __init__(self, argv, **kw):
            popen.append(argv)
            Path(argv[argv.index("-w") + 1]).write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)

        def send_signal(self, sig):
            pass

        def wait(self, timeout=None):
            return 0

    def fake_run(argv, **kw):
        runs.append(argv)
        return types.SimpleNamespace(returncode=0, stderr="100 packets -> 7 flows in 0.0s\n", stdout="")

    monkeypatch.setattr(C.subprocess, "Popen", FakeProc)
    monkeypatch.setattr(C.subprocess, "run", fake_run)
    monkeypatch.setattr(C.time, "sleep", lambda s: None)
    net, hosts = FakeNet(), T.host_plan()
    sess = next(s for s in P.make_plan() if s.attack == "udp")
    meta = C.run_session(net, sess, hosts, "s2-eth2", tmp_path / sess.id, "/venv/python", keep_pcap=True)

    assert popen[0][:3] == ["tcpdump", "-i", "s2-eth2"] and "-s" in popen[0]
    cmds = dict(net.log)
    clients = [h for h in hosts if h.role == "client"]
    attackers = [h for h in hosts if h.role == "attacker"]
    assert {n for n, c in net.log if "testbed/client.py" in c} == {h.name for h in clients}
    assert {n for n, c in net.log if "testbed/attack.py" in c} == {h.name for h in attackers}
    assert len([n for n, c in net.log if "udp_service.py client" in c]) == round(len(clients) * sess.udp_share)
    for h in attackers:
        assert f"--type udp --target {T.SERVER_IP}" in cmds[h.name] and "--dport-pool 4" in cmds[h.name]
    profiles = {c.split("--profile ")[1].split()[0] for n, c in net.log if "testbed/client.py" in c}
    assert profiles == set(sess.profiles)
    for script in ("testbed/client.py", "testbed/attack.py", "simulation/udp_service.py"):
        assert (ROOT / script).exists()                       # every command points at a real file
    assert meta["attacker_ips"] == [h.ip for h in attackers] and meta["label"] == "Sim-UDP-flood"
    convert = next(r for r in runs if "pcap_to_flows.py" in str(r))
    assert convert[0] == "/venv/python" and convert[-1].endswith("flows.parquet")
    saved = json.loads((tmp_path / sess.id / "session.json").read_text())
    assert saved["attack_start"] is not None and saved["conversion"].startswith("100 packets")


def test_train_model_validation_split_and_name_guard():
    import train_model

    labels = np.array(["BENIGN"] * 100 + ["Sim-UDP-flood"] * 10)
    mask = train_model.stratified_val(labels, 0.2, seed=3)
    assert mask[:100].sum() == 20 and mask[100:].sum() == 2  # every class is represented in validation
    r = subprocess.run([sys.executable, str(ROOT / "simulation/train_model.py"), "--name", "random_forest",
                        "--sim", "unused.parquet"], capture_output=True, text=True)
    assert r.returncode != 0 and "refusing to overwrite" in r.stderr


# ------------------------------------------------------------------ snapshots and replay
def write_pcap(path: Path, packets) -> None:
    """Minimal Ethernet/IPv4/UDP classic pcap; packets = [(ts, src, dst, sport, dport, payload_len)]."""
    import struct

    def ip(a):
        return bytes(int(x) for x in a.split("."))

    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, src, dst, sport, dport, n in packets:
            udp = struct.pack("!HHHH", sport, dport, 8 + n, 0) + b"x" * n
            iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, ip(src), ip(dst))
            frame = b"\0" * 12 + b"\x08\x00" + iph + udp
            fh.write(struct.pack("<IIII", int(ts), int(round((ts % 1) * 1e6)), len(frame), len(frame)) + frame)


def test_snapshots_record_running_flows_at_each_age(tmp_path):
    # one 12 s flow (a packet every 0.5 s) and one 1.5 s flow
    pkts = [(100 + 0.5 * i, "10.0.0.4", T.SERVER_IP, 4000, 9000, 512) for i in range(25)]
    pkts += [(100 + 0.5 * i, "10.0.0.1", T.SERVER_IP, 4001, 9053, 20) for i in range(4)]
    write_pcap(tmp_path / "c.pcap", sorted(pkts))
    snaps = B.snapshot_flows(tmp_path / "c.pcap", [1, 2, 5, 10])
    long_flow = snaps[snaps["Source IP"] == "10.0.0.4"].sort_values("snapshot_s")
    assert list(long_flow["snapshot_s"]) == [1, 2, 5, 10]                       # once per age
    assert (long_flow["Flow Duration"] >= long_flow["snapshot_s"] * 1e6).all()   # taken at or just after the age
    assert list(long_flow["Total Fwd Packets"]) == [3, 5, 11, 21]               # a prefix of the flow, growing
    assert list(snaps.loc[snaps["Source IP"] == "10.0.0.1", "snapshot_s"]) == [1]  # ended before 2 s


def test_replay_measures_time_to_first_decision(tmp_path):
    import detection_time as D
    from ddos.model_io import Bundle

    class ProtocolModel:  # stands in for a trained model: every UDP flow is an attack
        n_jobs = 1

        def predict_proba(self, X):
            p = (X["Protocol"].to_numpy() == 17).astype(float)
            return np.c_[1 - p, p]

    start = 1000.0
    pkts = [(start + 2.0 + 0.01 * i, "10.0.0.4", T.SERVER_IP, 5000 + i % 8, 9000, 512) for i in range(400)]
    pkts += [(start + 0.3 * i, "10.0.0.2", T.SERVER_IP, 6000, 80, 40) for i in range(3)]  # too few flows to act on
    d = tmp_path / "r3_16_attack_udp"
    d.mkdir()
    write_pcap(d / "capture.pcap", sorted(pkts))
    (d / "session.json").write_text(json.dumps({
        "id": d.name, "name": "attack_udp", "attack": "udp", "label": "Sim-UDP-flood", "attack_duration": 20,
        "attack_start": start + 2.0, "attacker_ips": ["10.0.0.4"], "server_ip": T.SERVER_IP}))
    out = D.replay_session(("udp-is-attack", Bundle(ProtocolModel(), "p", 0.5, {"features": FEATURES}, {}), str(d)))
    assert out["false_blocks"] == []
    t = out["detection_s"]["10.0.0.4"]
    assert t is not None and 0 < t < 2.0  # 8 flows, re-scored within the monitor's 1 s flush
