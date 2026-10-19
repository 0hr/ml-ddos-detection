"""Detection time: replay captured sessions through the live monitor with a given model.

Flow-level scores (F1, recall, ...) say how well a model labels finished flows. The live
system works differently: the monitor scores flows while they still run and blocks a source
once enough of its recent flows look like an attack. This measures that directly. Each
held-out session's capture is fed to traffic/monitor.py's own code (same flow meter,
batching and per-source vote, nothing rewritten), in packet time, and for every attacker it
records when the first block came, measured from when the attack was launched (session.json,
same clock as the capture).

The flow-rate rule is off here (max_flow_rate=0): we want to compare the models, and that
rule would decide some attacks before any model does. Blocks against non-attacker hosts are
counted as false blocks.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ddos.features import FEATURES
from ddos.model_io import Bundle
from traffic.monitor import Mitigator, run

# The live monitor's settings (testbed/run_experiment.py and testbed/live.py defaults).
WINDOW_S, MIN_FLOWS, RATIO, IDLE_TIMEOUT_S = 6.0, 5, 0.8, 2.0


class Recorder(Mitigator):
    """A Mitigator that decides exactly like the live one but only writes the decisions down."""

    def __init__(self, whitelist):
        super().__init__(controller=None, window=WINDOW_S, min_flows=MIN_FLOWS, ratio=RATIO, block_s=10**6,
                         cooldown=0.0, whitelist=whitelist, events=None, max_flow_rate=0)
        self.decisions: list[tuple[str, float]] = []

    def _emit(self, rec):
        if rec.get("event") == "block_request":
            self.decisions.append((rec["ip"], rec["flow_ts"]))


def as_bundle(model, threshold: float, name: str) -> Bundle:
    """Wrap a freshly trained estimator so the monitor can use it like a saved model."""
    return Bundle(model, name, threshold, {"features": FEATURES}, {})


def replay_session(job: tuple) -> dict:
    """job = (model name, Bundle, session directory). Runs in a worker process."""
    name, bundle, session_dir = job
    session_dir = Path(session_dir)
    meta = json.loads((session_dir / "session.json").read_text())
    bundle.model.n_jobs = 1  # small streaming batches: a thread pool per call costs more than it saves
    rec = Recorder([meta.get("server_ip", "10.0.0.100")])
    # The monitor logs every decision to stderr; here they are collected instead.
    with open(session_dir / "capture.pcap", "rb") as fh, contextlib.redirect_stderr(io.StringIO()):
        run(fh, bundle, rec, None, flush_every=1.0, idle_timeout=IDLE_TIMEOUT_S)
    attackers, start = set(meta.get("attacker_ips") or []), meta.get("attack_start")
    first: dict[str, float] = {}
    for ip, ts in rec.decisions:
        first.setdefault(ip, ts)
    return {
        "model": name, "session": meta["id"], "scenario": meta["name"], "attack": meta.get("attack"),
        "label": meta["label"], "attackers": sorted(attackers),
        "attack_duration_s": meta.get("attack_duration"),
        "detection_s": {ip: (round(first[ip] - start, 2) if ip in first else None) for ip in sorted(attackers)}
        if start else {},
        "false_blocks": sorted(ip for ip in first if ip not in attackers),
    }


def measure(models: dict[str, Bundle], session_dirs: list[Path], workers: int | None = None) -> list[dict]:
    """Replay every session with every model, in parallel processes."""
    jobs = [(name, bundle, str(d)) for name, bundle in models.items() for d in session_dirs]
    with ProcessPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(replay_session, jobs))
