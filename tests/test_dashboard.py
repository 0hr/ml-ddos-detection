"""Dashboard engine: a live run read from its log files, without a testbed."""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitor/server"))

from engine import Simulator
from live import RunSource

ATTACKER, BENIGN = "10.0.0.1", "10.0.0.2"


def append(run: Path, name: str, **rec) -> None:
    with open(run / name, "a") as fh:
        fh.write(json.dumps(rec) + "\n")


def make_run(tmp_path: Path, name="attack_mit", run_id=1.0, **meta) -> Path:
    run = tmp_path / name
    run.mkdir(parents=True, exist_ok=True)
    (run / "scenario.json").write_text(json.dumps(
        {"scenario": name, "config": {"mitigate": True, "attack": "udp"}, "run_id": run_id,
         "t_start": time.time(), **meta}))
    return run


def step(src: RunSource) -> dict:
    src._last_poll = 0.0  # look at the pointer / scenario.json on every tick
    src.tick(0.25)
    return src.snapshot()


def telemetry(run: Path, t: float, **hosts) -> None:
    append(run, "telemetry.jsonl", event="telemetry", t=t, window=0.5, hosts=hosts, monitor={"lag_ms": 12.0})


def test_incident_stages_and_drop_counters(tmp_path):
    t = time.time()
    run = make_run(tmp_path, attack_start=t)
    src = RunSource(str(run))
    telemetry(run, t + 0.5, **{ATTACKER: {"pps": 9000, "bps": 4e6, "flows": 40, "attack_flows": 40},
                               BENIGN: {"pps": 40, "bps": 2e4, "flows": 5, "attack_flows": 0}})
    snap = step(src)
    assert snap["phase"] == "attack" and snap["incident"]["detected_s"] is None
    assert snap["kpis"]["dropped_visible"] is False

    append(run, "detections.jsonl", ts=t + 0.8, event="block_request", ip=ATTACKER, attack_flows=40,
           window_flows=40, score=0.97, api_latency_ms=3.2, response={"ip": ATTACKER})
    append(run, "controller_events.jsonl", ts=t + 0.803, event="block_installed", ip=ATTACKER, duration=20,
           reason="40/40 flows", score=0.97)
    append(run, "controller_events.jsonl", ts=t + 0.805, event="block_confirmed", ip=ATTACKER, latency_ms=2.0)
    append(run, "controller_events.jsonl", ts=time.time(), event="block_stats", ip=ATTACKER, dpid=1,
           drop_pps=8800.0, dropped_packets=8800)
    telemetry(run, time.time(), **{BENIGN: {"pps": 40, "bps": 2e4, "flows": 5, "attack_flows": 0}})
    snap = step(src)
    inc = snap["incident"]
    assert snap["phase"] == "mitigated"
    assert abs(inc["detected_s"] - 0.8) < 0.01 and abs(inc["confirmed_s"] - 0.805) < 0.01
    assert inc["api_ms"] == 3.2 and inc["confirm_ms"] == 2.0 and inc["dropping_s"] is not None
    assert snap["kpis"]["dropped_visible"] is True
    assert snap["kpis"]["blocked_pps"] == 8800 and snap["kpis"]["dropped_packets"] == 8800
    assert snap["kpis"]["attack_pps"] == 0  # blocked traffic no longer reaches the capture point
    blk = snap["blocks"][0]
    assert blk["ip"] == ATTACKER and blk["dropped_packets"] == 8800 and blk["drop_pps"] == 8800
    host = {h["ip"]: h for h in snap["hosts"]}
    assert host[ATTACKER]["blocked"] and host[ATTACKER]["drop_pps"] == 8800
    assert host[BENIGN]["flows"] == 10 and host[BENIGN]["attack_flows"] == 0


def test_dry_run_decision_is_detection_without_mitigation(tmp_path):
    t = time.time()
    run = make_run(tmp_path, "attack_nomit", attack_start=t, config={"mitigate": False, "attack": "udp"})
    src = RunSource(str(run))
    append(run, "detections.jsonl", ts=t + 0.6, event="block_request", ip=ATTACKER, attack_flows=9,
           window_flows=9, score=0.98, response={"dry_run": True})
    snap = step(src)
    assert snap["mitigation"] is False
    assert snap["incident"]["suppressed"] is True and snap["incident"]["requested_s"] is None
    assert snap["kpis"]["detection_latency_s"] == 0.6 and snap["kpis"]["mitigation_latency_s"] is None
    assert not snap["blocks"]


def test_follows_the_pointer_to_the_next_run(tmp_path):
    pointer = tmp_path / "current.json"
    first = make_run(tmp_path, "normal")
    pointer.write_text(json.dumps({"run": str(first), "finished": False}))
    src = RunSource(None, pointer=str(pointer))
    telemetry(first, time.time(), **{BENIGN: {"pps": 55, "bps": 1e4}})
    assert step(src)["scenario"] == "normal"
    assert step(src)["kpis"]["benign_pps"] == 55

    second = make_run(tmp_path, "attack_mit", run_id=2.0, attack_start=time.time())
    pointer.write_text(json.dumps({"run": str(second), "finished": False}))
    snap = step(src)
    assert snap["scenario"] == "attack_mit" and snap["incident"] is not None
    assert snap["kpis"]["benign_pps"] == 0  # nothing carried over from the previous run


def test_reused_directory_starts_clean(tmp_path):
    run = make_run(tmp_path, "live", run_id=1.0, mode="session")
    src = RunSource(str(run))
    append(run, "controller_events.jsonl", ts=time.time(), event="block_installed", ip=ATTACKER, duration=20)
    assert len(step(src)["blocks"]) == 1
    for f in run.glob("*.jsonl"):
        f.unlink()
    make_run(tmp_path, "live", run_id=2.0, mode="session")  # a new session in the same directory
    assert step(src)["blocks"] == []


def test_session_events_open_and_close_incidents(tmp_path):
    t = time.time()
    run = make_run(tmp_path, "live", mode="session")
    src = RunSource(str(run))
    append(run, "session_events.jsonl", ts=t, event="attack_started", type="udp", hosts=["h1", "h3", "h5"])
    assert step(src)["incident"]["active"] is True
    append(run, "session_events.jsonl", ts=t + 5, event="attack_stopped", reason="operator")
    assert step(src)["incident"]["active"] is False
    append(run, "session_events.jsonl", ts=t + 9, event="attack_started", type="udp", hosts=["h1"])
    inc = step(src)["incident"]
    assert inc["n"] == 2 and inc["active"] is True and inc["detected_s"] is None


def test_runs_recorded_without_drop_counters_still_load(tmp_path):
    t = time.time() - 30
    run = make_run(tmp_path, attack_start=t, t_start=t - 8)
    append(run, "controller_events.jsonl", ts=t + 1, event="block_installed", ip=ATTACKER, duration=20)
    append(run, "controller_events.jsonl", ts=t + 18, event="block_renewed", ip=ATTACKER, duration=20, drop_pps=9000.0)
    src = RunSource(str(run), replay=True, speed=1000)
    time.sleep(0.05)
    snap = step(src)
    assert snap["mode"] == "replay" and snap["kpis"]["dropped_visible"] is False
    assert snap["kpis"]["blocked_pps"] == 0 and snap["controls"]["manual_block"] is False


def test_simulator_mitigates_and_counts_drops():
    sim = Simulator("attack_mit")
    sim.start -= sim.ATTACK_START + 1.5  # jump into the attack
    for _ in range(12):
        sim.tick(0.25)
        snap = sim.snapshot()
    inc = snap["incident"]
    assert inc["blocked"] == 3 and inc["confirmed_s"] is not None
    assert snap["kpis"]["attack_pps"] == 0 and snap["kpis"]["blocked_pps"] > 0
    assert snap["kpis"]["dropped_packets"] > 0


def test_rate_rule_decision_is_shown_as_such(tmp_path):
    t = time.time()
    run = make_run(tmp_path, "live", mode="session")
    src = RunSource(str(run))
    append(run, "session_events.jsonl", ts=t, event="attack_started", type="http", hosts=["h1"])
    append(run, "detections.jsonl", ts=t + 1.3, event="block_request", ip=ATTACKER, rule="rate", attack_flows=11,
           window_flows=2700, flow_rate=450.0, score=0.0, api_latency_ms=1.1, response={"ip": ATTACKER})
    snap = step(src)
    assert snap["incident"]["rule"] == "rate" and snap["incident"]["detected_s"] == 1.3
    flagged = [e for e in src.events if e["type"] == "detect"][-1]
    assert "450 flows/s" in flagged["detail"] and "score" not in flagged["detail"]
    assert snap["vote_rule"]["max_flow_rate"] == 100.0
