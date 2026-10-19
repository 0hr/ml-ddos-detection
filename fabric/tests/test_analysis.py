"""Metrics computed from a synthetic run with known answers."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fabric_ddos.analysis import block_intervals, load_run, summarize, summary_table
from fabric_ddos.testbed import Config, hosts_for

ATT, BEN, T0 = "10.0.0.1", "10.0.0.2", 1000.0


def write(run: Path, name: str, records: list) -> None:
    (run / name).write_text("".join(json.dumps(r) + "\n" for r in records))


def make_run(tmp_path: Path, mitigate: bool = True, counters: bool = True) -> Path:
    run = tmp_path / "attack"
    run.mkdir()
    (run / "scenario.json").write_text(json.dumps({
        "scenario": "attack", "config": {"mitigate": mitigate, "attack": "udp"}, "t_start": T0,
        "attack_start": T0 + 9.8, "attacker_ips": [ATT], "benign_ips": [BEN]}))
    # 0.5 s windows: the flood is visible at the tap from t=10 to t=11, then blocked.
    tel = []
    for i in range(60):
        t = T0 + (i + 1) * 0.5
        hosts = {BEN: {"pps": 40}}
        if 10.0 < t - T0 <= 11.0 or (not mitigate and t - T0 > 11.0):
            hosts[ATT] = {"pps": 8000}
        tel.append({"event": "telemetry", "t": t, "window": 0.5, "hosts": hosts, "monitor": {"lag_ms": 15}})
    write(run, "telemetry.jsonl", tel)
    resp = {"ip": ATT} if mitigate else {"dry_run": True}
    write(run, "detections.jsonl", [{"ts": T0 + 10.9, "event": "block_request", "ip": ATT,
                                     "api_latency_ms": 4.0, "response": resp}])
    ctrl = []
    if mitigate:
        ctrl += [{"ts": T0 + 10.903, "event": "block_installed", "ip": ATT, "duration": 20},
                 {"ts": T0 + 10.905, "event": "block_confirmed", "ip": ATT, "latency_ms": 2.0}]
        if counters:
            ctrl += [{"ts": T0 + 12 + i, "event": "block_stats", "ip": ATT, "dpid": 1, "drop_pps": 8000.0,
                      "dropped_packets": 8000 * (i + 1)} for i in range(10)]
    write(run, "controller_events.jsonl", ctrl)
    ok_during = 1.0 if mitigate else 0.5
    reqs = [{"ts": T0 + 0.25 * i, "ok": True, "latency_ms": 20.0} for i in range(40)]
    reqs += [{"ts": T0 + 10.0 + 0.25 * i, "ok": i % 2 == 0 or ok_during == 1.0, "latency_ms": 30.0} for i in range(40)]
    write(run, "client_h2.jsonl", reqs)
    return run


def test_mitigated_run(tmp_path):
    s = summarize(load_run(make_run(tmp_path)))
    assert s["detection_s"] == 0.9            # first attack window starts at t=10.0, decision at 10.9
    assert s["mitigation_s"] == 0.905
    assert s["launch_to_decision_s"] == 1.1
    assert s["api_ms"] == 4.0 and s["confirm_ms"] == 2.0
    assert s["sources_blocked"] == 1 and s["false_blocks"] == 0
    assert s["attack_packets_at_server"] == 8000   # two 0.5 s windows at 8000 pps
    assert s["attack_packets_dropped"] == 80000
    assert s["exposure"] == round(8000 / 88000, 4)
    assert s["availability_before"] == 1.0 and s["availability_during"] == 1.0


def test_unmitigated_run(tmp_path):
    s = summarize(load_run(make_run(tmp_path, mitigate=False)))
    assert s["detection_s"] == 0.9 and s["mitigation_s"] is None
    assert s["api_ms"] is None                 # a dry run never called the controller
    assert s["sources_blocked"] == 0 and s["attack_packets_dropped"] == 0
    assert s["exposure"] == 1.0 and s["availability_during"] == 0.5


def test_missing_counters_are_unknown_not_zero(tmp_path):
    s = summarize(load_run(make_run(tmp_path, counters=False)))
    assert s["attack_packets_dropped"] is None and s["exposure"] is None
    assert "—" in summary_table([s])


def test_counter_restart_is_added_not_subtracted(tmp_path):
    run = make_run(tmp_path)
    with open(run / "controller_events.jsonl", "a") as fh:  # the source is blocked anew: counter restarts
        fh.write(json.dumps({"ts": T0 + 40, "event": "block_stats", "ip": ATT, "dpid": 1,
                             "drop_pps": 500.0, "dropped_packets": 500}) + "\n")
    assert summarize(load_run(run))["attack_packets_dropped"] == 80500


def test_block_intervals_merge_renewals(tmp_path):
    run = make_run(tmp_path)
    with open(run / "controller_events.jsonl", "a") as fh:
        fh.write(json.dumps({"ts": T0 + 28, "event": "block_renewed", "ip": ATT, "duration": 20}) + "\n")
    (start, end), = block_intervals(load_run(run))
    assert start == T0 + 10.903 and end == T0 + 30.0  # clipped to the end of the telemetry


def test_host_plan():
    hosts = hosts_for(Config(n_attackers=2, n_clients=3))
    assert [(h.name, h.ip, h.role) for h in hosts] == [
        ("srv", "10.0.0.100", "server"), ("h1", "10.0.0.1", "attacker"), ("h3", "10.0.0.3", "attacker"),
        ("h2", "10.0.0.2", "client"), ("h4", "10.0.0.4", "client"), ("h6", "10.0.0.6", "client")]
