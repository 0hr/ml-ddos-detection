"""Live traffic monitor: capture -> flow features -> model -> block requests.

Reads a pcap stream from stdin (``tcpdump -U -w -``) or a file, builds flows with the
same FlowMeter used for training, scores finished flows with the saved model, and asks
the controller to block a source IP when enough of its recent flows look like an attack.

    tcpdump -i s1-eth1 -U -w - | \
        sudo python3 traffic/monitor.py --model models/random_forest.joblib \
            --controller http://127.0.0.1:8080 --events results/runs/foo/detections.jsonl

Blocking rules, per source IP over a sliding window (one vote per flow):
  * keep each IP's flow verdicts from the last --window seconds; flows still running are
    re-scored every --flush-every seconds, so long floods are caught early
  * model rule: block when attack flows >= --min-flows and their share >= --attack-ratio
  * rate rule:  block when the source makes more than --max-flow-rate flows/s. The model
    judges one flow at a time, so a flood of ordinary-looking connections only shows up
    by its count.
  * whitelisted IPs are scored but never blocked
  * if the controller installs nothing (unreachable, no switch, too many blocks), retry
    after --retry-seconds instead of assuming the source is blocked
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ddos.features import fix_rates
from ddos.flowmeter import FlowMeter
from ddos.model_io import load_bundle
from ddos.pcapio import iter_packets

import pandas as pd


RETRY_S = 2.0       # after a block request that installed nothing
PRUNE_EVERY_S = 30  # how often sources that went quiet are dropped from the vote history
SCAN_EVERY_S = 0.25  # a busy source's expired votes are swept at most this often
MAX_FLOW_RATE = 100.0  # flows/s per source; ~3x the busiest legitimate client in the testbed


class SourceVotes:
    """One source's flow verdicts in the window, with running totals.

    One vote per flow (latest wins), so re-scoring a long flow never double-counts it.
    Totals are kept as we go: a flood source can hold thousands of votes, so recounting
    them every time would cost more than the model.
    """

    __slots__ = ("votes", "attacks", "proba_sum", "last_scan")

    def __init__(self):
        self.votes = {}  # flow key -> (ts, is_attack, proba)
        self.attacks = 0
        self.proba_sum = 0.0  # over attack votes
        self.last_scan = 0.0

    def _drop(self, key):
        _, was_attack, proba = self.votes.pop(key)
        if was_attack:
            self.attacks -= 1
            self.proba_sum -= proba

    def add(self, key, ts, is_attack, proba, window):
        if key in self.votes:
            self._drop(key)
        self.votes[key] = (ts, is_attack, proba)
        if is_attack:
            self.attacks += 1
            self.proba_sum += proba
        # Small sources are swept on every vote (exact); busy ones a few times per second.
        if len(self.votes) <= 64 or ts - self.last_scan >= SCAN_EVERY_S:
            self.last_scan = ts
            for k in [k for k, (t, _, _) in self.votes.items() if ts - t > window]:
                self._drop(k)

    def quiet(self, now, window):
        return all(now - t > window for t, _, _ in self.votes.values())


class Mitigator:
    def __init__(self, controller, window, min_flows, ratio, block_s, cooldown, whitelist, events,
                 token="", retry_s=RETRY_S, max_flow_rate=MAX_FLOW_RATE):
        self.controller = controller.rstrip("/") if controller else None
        self.token = token
        self.retry_s = retry_s
        self.window = window
        self.min_flows = min_flows
        self.ratio = ratio
        self.max_flows = max_flow_rate * window if max_flow_rate > 0 else None  # None = rule off
        self.block_s = block_s
        self.cooldown = cooldown
        self.whitelist = set(whitelist)
        self.events = events
        self.history = defaultdict(SourceVotes)  # ip -> its votes in the window
        self.blocked_until = {}
        self.suppressed = set()  # sources whose block the controller is holding back (detect-only)
        self.counts = defaultdict(int)
        self._last_prune = 0.0

    def _emit(self, rec):
        rec["ts"] = time.time()
        if self.events:
            with open(self.events, "a") as fh:
                fh.write(json.dumps(rec) + "\n")

    def _post(self, path, payload):
        if not self.controller:
            return {"dry_run": True}
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(self.controller + path, data=json.dumps(payload).encode(),
                                     headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=2.0) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as exc:  # the controller answered, but refused
            try:
                detail = json.loads(exc.read()).get("error", "")
            except ValueError:
                detail = ""
            self._emit({"event": "controller_error", "path": path, "status": exc.code, "error": detail})
            return {"error": detail or f"HTTP {exc.code}", "status": exc.code}
        except Exception as exc:
            self._emit({"event": "controller_error", "path": path, "error": str(exc)})
            return {"error": str(exc)}

    def observe(self, src, key, now, is_attack, proba, final=True):
        if final:
            self.counts["flows"] += 1
            self.counts["attack_flows"] += int(is_attack)
        else:
            self.counts["interim_scores"] += 1
        votes = self.history[src]
        votes.add(key, now, is_attack, proba, self.window)
        self._maybe_block(src, now, votes)
        if now - self._last_prune > PRUNE_EVERY_S:
            self._prune(now)

    def _prune(self, now):
        """Forget sources that sent nothing for a whole window, so memory stays bounded."""
        self._last_prune = now
        for src in [s for s, v in self.history.items() if v.quiet(now, self.window)]:
            del self.history[src]
        for src in [s for s, until in self.blocked_until.items() if until < now]:
            del self.blocked_until[src]

    def _maybe_block(self, src, now, votes):
        if src in self.whitelist or now < self.blocked_until.get(src, 0):
            return
        n_flows, n_attack = len(votes.votes), votes.attacks
        if n_attack >= self.min_flows and n_attack / n_flows >= self.ratio:
            rule, reason = "model", f"{n_attack}/{n_flows} flows"
        elif self.max_flows is not None and n_flows > self.max_flows:
            rule = "rate"
            reason = f"{n_flows / self.window:.0f} flows/s (limit {self.max_flows / self.window:.0f})"
        else:
            return
        score = votes.proba_sum / n_attack if n_attack else 0.0
        t0 = time.time()
        resp = self._post("/block", {"ip": src, "duration": self.block_s, "reason": reason,
                                     "score": round(score, 4) if rule == "model" else None})
        latency_ms = round((time.time() - t0) * 1000, 2)
        if "error" in resp:
            # Nothing was installed: ask again soon instead of assuming the source is blocked.
            # (403 = whitelisted on the controller, which will not change, so back off.)
            refused = resp.get("status") == 403
            self.blocked_until[src] = now + (self.block_s if refused else self.retry_s)
            self.counts["failed_blocks"] += 1
            return
        if resp.get("suppressed"):
            # Detect-only mode: keep asking so the block lands when mitigation is turned
            # back on, but log it only once.
            self.blocked_until[src] = now + self.retry_s
            if src in self.suppressed:
                return
            self.suppressed.add(src)
        else:
            self.suppressed.discard(src)
            self.blocked_until[src] = now + self.block_s + self.cooldown
        self.counts["blocks"] += 1
        self._emit({"event": "block_request", "ip": src, "rule": rule, "flow_ts": now, "attack_flows": n_attack,
                    "window_flows": n_flows, "flow_rate": round(n_flows / self.window, 1),
                    "score": round(score, 4), "api_latency_ms": latency_ms, "response": resp})
        print(f"[block] {src} rule={rule} {reason} score={score:.3f} api={latency_ms}ms {resp}",
              file=sys.stderr, flush=True)


class TelemetryWriter:
    """Per-window packet/byte/flow totals per source, for the live dashboard.

    Gives pps/bps without shipping every packet: counters are flushed every `interval`
    seconds of capture time as one JSON line the dashboard reads.
    """

    def __init__(self, path: str, interval: float = 0.5):
        self.path = path
        self.interval = interval
        self.pkts: dict[str, int] = {}
        self.bytes: dict[str, int] = {}
        self.flows: dict[str, int] = {}
        self.attack_flows: dict[str, int] = {}
        self.stats: dict = {}  # monitor health, filled in by run()
        self._last = None
        open(path, "w").close()

    def packet(self, pkt) -> None:
        self.pkts[pkt.src] = self.pkts.get(pkt.src, 0) + 1
        self.bytes[pkt.src] = self.bytes.get(pkt.src, 0) + pkt.payload_len

    def flow(self, src: str, is_attack: bool) -> None:
        self.flows[src] = self.flows.get(src, 0) + 1
        if is_attack:
            self.attack_flows[src] = self.attack_flows.get(src, 0) + 1

    def maybe_flush(self, now: float) -> None:
        if self._last is None:
            self._last = now
            return
        dt = now - self._last
        if dt < self.interval:
            return
        hosts = {ip: {"pps": round(n / dt, 1), "bps": round(self.bytes.get(ip, 0) / dt, 1),
                      "flows": self.flows.get(ip, 0), "attack_flows": self.attack_flows.get(ip, 0)}
                 for ip, n in self.pkts.items()}
        # lag = how far the monitor is behind live traffic; grows when scoring can't keep up.
        rec = {"event": "telemetry", "t": now, "window": round(dt, 3), "hosts": hosts,
               "monitor": {**self.stats, "lag_ms": round(max(0.0, time.time() - now) * 1000, 1)}}
        with open(self.path, "a") as fh:
            fh.write(json.dumps(rec) + "\n")
        self.pkts, self.bytes, self.flows, self.attack_flows = {}, {}, {}, {}
        self._last = now


def flow_key(flow) -> tuple:
    return (flow.src, flow.sport, flow.dst, flow.dport, flow.proto, flow.start)


def run(stream, bundle, mit, tee, flush_every, idle_timeout, telemetry=None, batch_every=0.25):
    """Feed packets through the flow meter and score flows in batches.

    Each model call costs about the same (~10 ms), so scoring one flow at a time caps the
    monitor near 100 flows/s and it falls behind under many short connections. Finished
    flows are queued and scored together every `batch_every` seconds instead.
    """
    meter = FlowMeter()
    last_flush = last_batch = None
    pending = []

    def score(flows, final=True):
        if not flows:
            return
        df = pd.DataFrame.from_records([f.record() for f in flows])
        fix_rates(df)
        proba = bundle.predict_proba(df)
        for flow, p in zip(flows, proba):
            is_attack = p >= bundle.threshold
            mit.observe(flow.src, flow_key(flow), flow.last, is_attack, float(p), final=final)
            if telemetry and final:
                telemetry.flow(flow.src, is_attack)

    try:
        for pkt in iter_packets(stream, tee=tee):
            if telemetry:
                telemetry.packet(pkt)
                telemetry.stats = {"active_flows": len(meter.active), "flows_scored": mit.counts["flows"],
                                   "attack_flows": mit.counts["attack_flows"], "blocks": mit.counts["blocks"]}
                telemetry.maybe_flush(pkt.ts)
            pending += meter.add(pkt)
            if last_flush is None:
                last_flush = last_batch = pkt.ts
                continue
            if pkt.ts - last_batch >= batch_every:
                score(pending)
                pending, last_batch = [], pkt.ts
            if pkt.ts - last_flush > flush_every:
                score(meter.expire(pkt.ts, idle_timeout))
                # Score flows still in progress: a flood that reuses one 5-tuple never goes
                # idle, so it would otherwise only be scored at the 120 s timeout, too late.
                live = [f for f in meter.active.values()
                        if f.packets >= meter.min_packets and f.last > last_flush]
                score(live, final=False)
                last_flush = pkt.ts
    except KeyboardInterrupt:
        pass  # normal shutdown
    score(pending + meter.flush())
    return mit.counts


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", default=str(ROOT / "models/random_forest.joblib"))
    ap.add_argument("--pcap", help="read from this file instead of stdin")
    ap.add_argument("--controller", default=os.environ.get("DDOS_CONTROLLER", "http://127.0.0.1:8080"))
    ap.add_argument("--token", default=os.environ.get("DDOS_API_TOKEN", ""),
                    help="bearer token for the controller API (default: $DDOS_API_TOKEN)")
    ap.add_argument("--retry-seconds", type=float, default=RETRY_S,
                    help="ask again this soon after a block request that installed nothing")
    ap.add_argument("--no-mitigate", action="store_true", help="detect and log only, never block")
    ap.add_argument("--save-pcap", help="tee the captured stream to this pcap file")
    ap.add_argument("--events", help="append detection/mitigation events as JSON lines")
    ap.add_argument("--telemetry", help="append per-window per-host packet aggregates (for the dashboard)")
    ap.add_argument("--telemetry-interval", type=float, default=0.5)
    ap.add_argument("--window", type=float, default=10.0)
    ap.add_argument("--min-flows", type=int, default=5)
    ap.add_argument("--attack-ratio", type=float, default=0.8)
    ap.add_argument("--max-flow-rate", type=float, default=MAX_FLOW_RATE,
                    help="block a source above this many flows/s over the window, whatever the "
                         "model says (0 = model rule only)")
    ap.add_argument("--block-seconds", type=int, default=30)
    ap.add_argument("--cooldown", type=float, default=0.0,
                    help="extra seconds after a block expires before the same IP may be re-blocked")
    ap.add_argument("--idle-timeout", type=float, default=5.0, help="finish idle flows after N s for fast detection")
    ap.add_argument("--flush-every", type=float, default=1.0)
    ap.add_argument("--whitelist", default="10.0.0.100")
    args = ap.parse_args()

    bundle = load_bundle(args.model)
    # Small frequent batches: the n_jobs=-1 thread-pool setup costs more than the predict
    # itself, so the streaming monitor runs single-threaded.
    bundle.model.n_jobs = 1
    print(f"loaded {bundle.name} (schema {bundle.schema['schema_hash']}, threshold {bundle.threshold})",
          file=sys.stderr)
    mit = Mitigator(
        controller=None if args.no_mitigate else args.controller,
        window=args.window, min_flows=args.min_flows, ratio=args.attack_ratio,
        block_s=args.block_seconds, cooldown=args.cooldown,
        whitelist=[w for w in args.whitelist.split(",") if w], events=args.events,
        token=args.token, retry_s=args.retry_seconds, max_flow_rate=args.max_flow_rate,
    )
    tee = open(args.save_pcap, "wb") if args.save_pcap else None
    telemetry = TelemetryWriter(args.telemetry, args.telemetry_interval) if args.telemetry else None
    stream = open(args.pcap, "rb") if args.pcap else sys.stdin.buffer
    try:
        counts = run(stream, bundle, mit, tee, args.flush_every, args.idle_timeout, telemetry)
    finally:
        if tee:
            tee.close()
    print(f"done: {dict(counts)}", file=sys.stderr)
    if args.events:
        mit._emit({"event": "monitor_summary", **dict(counts)})


if __name__ == "__main__":
    main()
