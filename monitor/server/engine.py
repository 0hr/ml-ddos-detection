"""Dashboard state engine + scripted scenario simulator.

The engine holds the dashboard state (hosts, links, blocks, the current incident, KPIs) and
emits a JSON snapshot each tick. Two sources drive it:
  * Simulator  (this file)  - a scripted baseline -> attack -> detect -> mitigate -> recover
                              timeline, so the dashboard runs with no testbed and no root.
  * RunSource  (live.py)    - a real testbed run, tailed live or replayed in recorded time.

Both produce the same snapshot schema (mirrored in monitor/web/src/types.ts). Every timestamp
goes through Engine.now(), so a replay can run on the recorded clock.

Per-host rates: `pps` is what the capture point on the server link sees from a host,
`drop_pps` is what the switches drop from it (from the drop rules' counters). A blocked host
therefore shows pps ~ 0 and drop_pps > 0.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field

SERVER_IP = "10.0.0.100"

# Host roles match testbed/topology.py + run_experiment.py: attackers h1/h3/h5 on s1,
# normal clients h2/h4/h6 on s2, the server on s1.
HOSTS = [
    {"id": "srv", "ip": SERVER_IP, "role": "server", "switch": "s1"},
    {"id": "h1", "ip": "10.0.0.1", "role": "attacker", "switch": "s1"},
    {"id": "h3", "ip": "10.0.0.3", "role": "attacker", "switch": "s1"},
    {"id": "h5", "ip": "10.0.0.5", "role": "attacker", "switch": "s1"},
    {"id": "h2", "ip": "10.0.0.2", "role": "benign", "switch": "s2"},
    {"id": "h4", "ip": "10.0.0.4", "role": "benign", "switch": "s2"},
    {"id": "h6", "ip": "10.0.0.6", "role": "benign", "switch": "s2"},
]
IP_TO_HOST = {h["ip"]: h["id"] for h in HOSTS}
SWITCHES = ["s1", "s2"]
ATTACKING_PPS = 200.0  # an attacker host above this rate is shown as attacking
VOTE_WINDOW_S = 6.0    # per-source flow verdicts are summed over this window (monitor --window)
VOTE_MIN_FLOWS = 5     # monitor --min-flows
VOTE_RATIO = 0.8       # monitor --attack-ratio
VOTE_MAX_FLOW_RATE = 100.0  # monitor --max-flow-rate (flows/s per source)
# Simulator only: server load at which benign requests start failing.
SERVER_CAPACITY_PPS = 6000.0


@dataclass
class HostState:
    id: str
    ip: str
    role: str
    switch: str
    pps: float = 0.0
    bps: float = 0.0
    drop_pps: float = 0.0
    blocked: bool = False
    remaining_block_s: float = 0.0
    votes: list = field(default_factory=list)  # (t, flows, attack_flows) per telemetry window

    def vote(self, now: float) -> tuple[int, int]:
        """(flows, attack flows) the model scored for this source in the vote window."""
        self.votes = [v for v in self.votes if now - v[0] <= VOTE_WINDOW_S]
        return sum(v[1] for v in self.votes), sum(v[2] for v in self.votes)


@dataclass
class Block:
    ip: str
    host: str
    reason: str
    score: float
    duration_s: float
    start: float
    installed_at: float
    confirm_ms: float = 0.0
    renewals: int = 0
    dropped_packets: int = 0
    drop_pps: float = 0.0

    def remaining(self, now: float) -> float:
        return max(0.0, self.duration_s - (now - self.start))


@dataclass
class Incident:
    """One attack, from its start to when its traffic is being dropped.

    Every field is a timestamp (or None until that stage happens), so the UI can show the
    mitigation pipeline with the real time each step took.
    """

    attack_at: float
    kind: str = ""
    detected_at: float | None = None   # first block decision for an attacking source
    requested_at: float | None = None  # controller accepted the first block
    confirmed_at: float | None = None  # barrier reply: the rule is in the switches
    dropping_at: float | None = None   # first drop-counter sample that moved
    ended_at: float | None = None
    api_ms: float | None = None        # monitor -> controller REST round trip
    confirm_ms: float | None = None    # controller -> all switches confirmed
    suppressed: bool = False           # decision taken but mitigation was off
    rule: str = "model"                # what flagged it: the model's verdicts, or the flow-rate limit
    flagged: set = field(default_factory=set)
    blocked: set = field(default_factory=set)


class Engine:
    # What the UI may offer for this source; subclasses override.
    controls = {"scenario": False, "mitigation_toggle": False, "manual_block": False,
                "attack": False, "load": False}
    availability_source = "simulated"  # simulated | measured | unavailable
    dropped_visible = True  # are the switches' drop counters available?

    def __init__(self, mode: str, scenario: str, mitigation: bool | None):
        self.mode = mode
        self.scenario = scenario
        self.mitigation = mitigation
        self._event_id = 0
        self.events: list[dict] = []
        self.reset()

    def now(self) -> float:
        return time.time()

    def reset(self) -> None:
        """Clear run state; event ids keep rising so clients never miss new events."""
        self.start = self.now()
        self.hosts = {h["id"]: HostState(**h) for h in HOSTS}
        self.blocks: dict[str, Block] = {}
        self.availability: float | None = None
        self.incident: Incident | None = None
        self.incidents = 0
        self.dropped_total = 0
        self._first_decision: tuple[float, str] | None = None

    # ---------------------------------------------------------------- events
    def emit(self, type_: str, title: str, detail: str = "", ip: str = "", at: float | None = None) -> None:
        self._event_id += 1
        self.events.append({
            "id": self._event_id, "t": self.now() if at is None else at, "type": type_,
            "title": title, "detail": detail, "ip": ip, "host": IP_TO_HOST.get(ip, ""),
        })
        self.events = self.events[-400:]

    # ---------------------------------------------------------------- incident
    def mark_attack_start(self, at: float, detail: str, kind: str = "") -> None:
        """Open a new incident. A second call while one still runs is ignored."""
        if self.incident is not None and self.incident.ended_at is None:
            return
        self.incident = Incident(attack_at=at, kind=kind)
        self.incidents += 1
        self.emit("attack", "Attack started", detail, at=at)
        # The decision can arrive before the record that marks the attack start.
        if self._first_decision is not None and self._first_decision[0] >= at:
            self.mark_detection(*self._first_decision)
        self._first_decision = None

    def mark_attack_end(self, at: float, detail: str = "") -> None:
        if self.incident is not None and self.incident.ended_at is None:
            self.incident.ended_at = at
            self.emit("info", "Attack stopped", detail, at=at)

    def mark_detection(self, at: float, ip: str, suppressed: bool = False,
                       api_ms: float | None = None, rule: str = "model") -> None:
        """First block decision for an attacking source (requested, or logged as 'would block')."""
        inc = self.incident
        if inc is None or inc.ended_at is not None or at < inc.attack_at:
            if self._first_decision is None:
                self._first_decision = (at, ip)
            return
        inc.flagged.add(ip)
        if inc.detected_at is None:
            inc.detected_at, inc.suppressed, inc.api_ms, inc.rule = at, suppressed, api_ms, rule
        elif inc.suppressed and not suppressed:
            inc.suppressed = False

    def _incident_block(self, ip: str, at: float) -> None:
        inc = self.incident
        host = self.hosts.get(IP_TO_HOST.get(ip, ""))
        if inc is None or at < inc.attack_at or host is None or host.role != "attacker":
            return
        inc.blocked.add(ip)
        inc.suppressed = False
        if inc.requested_at is None:
            inc.requested_at = at

    def _incident_confirm(self, ip: str, at: float, latency_ms: float) -> None:
        inc = self.incident
        if inc is not None and ip in inc.blocked and inc.confirmed_at is None:
            inc.confirmed_at, inc.confirm_ms = at, latency_ms

    def _incident_drop(self, ip: str, at: float) -> None:
        inc = self.incident
        if inc is not None and ip in inc.blocked and inc.dropping_at is None:
            inc.dropping_at = at

    # ---------------------------------------------------------------- mitigation
    def add_block(self, ip: str, duration: float, reason: str, score: float,
                  confirm_ms: float = 0.0, at: float | None = None) -> bool:
        if ip == SERVER_IP:
            return False
        at = self.now() if at is None else at
        new = ip not in self.blocks
        old = self.blocks.get(ip)
        self.blocks[ip] = Block(ip, IP_TO_HOST.get(ip, ip), reason, score, duration, at, at, confirm_ms,
                                dropped_packets=old.dropped_packets if old else 0)
        self._incident_block(ip, at)
        if new:
            host = IP_TO_HOST.get(ip, ip)
            detail = f"drop rule installed for {duration:.0f}s" + (f" · score {score:.2f}" if score else "")
            self.emit("block", f"Blocked {host}", detail, ip, at=at)
        return True

    def remove_block(self, ip: str, reason: str = "expired", at: float | None = None) -> None:
        blk = self.blocks.pop(ip, None)
        if blk is not None:
            dropped = f" · {blk.dropped_packets:,} packets dropped" if blk.dropped_packets else ""
            self.emit("unblock", f"Unblocked {IP_TO_HOST.get(ip, ip)}", reason + dropped, ip, at=at)
        host = self.hosts.get(IP_TO_HOST.get(ip, ""))
        if host is not None:
            host.drop_pps = 0.0

    def _expire_blocks(self, now: float) -> None:
        for ip in [ip for ip, b in self.blocks.items() if b.remaining(now) <= 0]:
            self.remove_block(ip, "drop rule expired", at=self.blocks[ip].start + self.blocks[ip].duration_s)

    # ---------------------------------------------------------------- snapshot
    def health(self, now: float) -> dict:
        return {"monitor": "ok", "telemetry_age_s": 0.0, "monitor_lag_ms": None,
                "controller": "ok", "switches": len(SWITCHES), "session": False}

    def session_state(self) -> dict | None:
        return None

    def snapshot(self) -> dict:
        now = self.now()
        self._expire_blocks(now)
        for h in self.hosts.values():
            b = self.blocks.get(h.ip)
            h.blocked = b is not None
            h.remaining_block_s = b.remaining(now) if b else 0.0

        attackers = [h for h in self.hosts.values() if h.role == "attacker"]
        benign_pps = sum(h.pps for h in self.hosts.values() if h.role == "benign")
        attack_pps = sum(h.pps for h in attackers)  # reaching the server
        blocked_pps = sum(h.drop_pps for h in self.hosts.values()) if self.dropped_visible else 0.0
        blocked_sources = sum(h.blocked for h in attackers)
        srv = self.hosts["srv"]
        srv.pps = benign_pps + attack_pps
        inc = self.incident

        return {
            "t": now,
            "mode": self.mode,
            "scenario": self.scenario,
            "mitigation": self.mitigation,
            "controls": self.controls,
            "elapsed": now - self.start,
            "phase": self._phase(attack_pps, blocked_sources),
            "health": self.health(now),
            "session": self.session_state(),
            "vote_rule": {"window_s": VOTE_WINDOW_S, "min_flows": VOTE_MIN_FLOWS, "ratio": VOTE_RATIO,
                          "max_flow_rate": VOTE_MAX_FLOW_RATE},
            "kpis": {
                "total_pps": benign_pps + attack_pps + blocked_pps,
                "benign_pps": benign_pps,
                "attack_pps": attack_pps,
                "blocked_pps": blocked_pps,
                "dropped_visible": self.dropped_visible,
                "dropped_packets": self.dropped_total,
                "server_pps": srv.pps,
                "active_blocks": len(self.blocks),
                "blocked_sources": blocked_sources,
                "availability": self.availability,
                "availability_source": self.availability_source,
                "detection_latency_s": self._latency(inc, "detected_at"),
                "mitigation_latency_s": self._latency(inc, "confirmed_at"),
            },
            "incident": self._incident_json(inc, now),
            "hosts": [self._host_json(h, now) for h in self.hosts.values()],
            "switches": SWITCHES,
            "links": self._links(now),
            "blocks": [{
                "ip": b.ip, "host": b.host, "reason": b.reason, "score": b.score,
                "remaining_s": round(b.remaining(now), 1), "duration_s": b.duration_s,
                "confirm_ms": b.confirm_ms, "renewals": b.renewals,
                "dropped_packets": b.dropped_packets, "drop_pps": round(b.drop_pps),
                "age_s": round(max(0.0, now - b.installed_at), 1),
            } for b in sorted(self.blocks.values(), key=lambda b: b.ip)],
            "history_point": {
                "t": round(now - self.start, 2),
                "benign_pps": round(benign_pps),
                "attack_pps": round(attack_pps),
                "blocked_pps": round(blocked_pps),
                "availability": None if self.availability is None else round(self.availability, 4),
                "active_blocks": len(self.blocks),
            },
        }

    @staticmethod
    def _latency(inc: Incident | None, stage: str) -> float | None:
        at = getattr(inc, stage) if inc is not None else None
        return None if at is None else round(max(0.0, at - inc.attack_at), 2)

    def _incident_json(self, inc: Incident | None, now: float) -> dict | None:
        if inc is None:
            return None
        attackers = [h.ip for h in self.hosts.values() if h.role == "attacker"]
        rel = lambda t: None if t is None else round(max(0.0, t - inc.attack_at), 3)
        return {
            "n": self.incidents, "kind": inc.kind, "attack_at": inc.attack_at,
            "age_s": round(now - inc.attack_at, 1), "active": inc.ended_at is None,
            "detected_s": rel(inc.detected_at), "requested_s": rel(inc.requested_at),
            "confirmed_s": rel(inc.confirmed_at), "dropping_s": rel(inc.dropping_at),
            "ended_s": rel(inc.ended_at),
            "api_ms": inc.api_ms, "confirm_ms": inc.confirm_ms, "suppressed": inc.suppressed, "rule": inc.rule,
            "flagged": len(inc.flagged), "blocked": len(inc.blocked), "attackers": len(attackers),
        }

    def _host_json(self, h: HostState, now: float) -> dict:
        state = ("server" if h.role == "server" else
                 "blocked" if h.blocked else
                 "attacking" if (h.role == "attacker" and h.pps > ATTACKING_PPS) else
                 "active" if h.pps > 5 else "idle")
        flows, attack_flows = h.vote(now)
        return {
            "id": h.id, "ip": h.ip, "role": h.role, "switch": h.switch,
            "pps": round(h.pps), "bps": round(h.bps), "drop_pps": round(h.drop_pps), "blocked": h.blocked,
            "remaining_block_s": round(h.remaining_block_s, 1), "state": state,
            "flows": flows, "attack_flows": attack_flows,
        }

    def _links(self, now: float) -> list[dict]:
        links = []
        for h in self.hosts.values():
            if h.role == "server":
                continue
            kind = ("blocked" if h.blocked else
                    "attack" if (h.role == "attacker" and h.pps > ATTACKING_PPS) else
                    "benign" if h.pps > 5 else "idle")
            pps = h.drop_pps if h.blocked else h.pps
            links.append({"src": h.id, "dst": h.switch, "pps": round(pps), "kind": kind})
        srv = self.hosts["srv"]
        links.append({"src": "srv", "dst": "s1", "pps": round(srv.pps), "kind": "server" if srv.pps > 5 else "idle"})
        cross = sum(h.pps for h in self.hosts.values() if h.switch == "s2")
        links.append({"src": "s2", "dst": "s1", "pps": round(cross), "kind": "benign" if cross > 5 else "idle"})
        # The control channel lights up while a rule is being pushed (install or renewal).
        pushing = any(now - b.start < 1.5 for b in self.blocks.values())
        links += [{"src": "controller", "dst": sw, "pps": 0, "kind": "control", "active": pushing}
                  for sw in SWITCHES]
        return links

    def _phase(self, attack_pps: float, blocked_sources: int) -> str:
        # In a real run, blocked traffic is dropped before the capture point, so "no attack
        # traffic" must not be read as "recovered" while drop rules are active.
        if blocked_sources:
            return "mitigated"
        if attack_pps > 100:
            return "attack"
        return "recovered" if self.incident is not None else "baseline"


class Simulator(Engine):
    """Scripted scenario on a repeating cycle, so the dashboard always shows motion."""

    controls = {"scenario": True, "mitigation_toggle": True, "manual_block": True,
                "attack": False, "load": False}
    availability_source = "simulated"
    dropped_visible = True

    CYCLE = 46.0
    ATTACK_START = 9.0
    ATTACK_STOP = 39.0
    ATTACK_PPS = 11000.0
    BENIGN_PPS = 45.0
    BLOCK_SECONDS = 20.0  # matches testbed/run_experiment.py --block-seconds

    def __init__(self, scenario="attack_mit", seed=7):
        self.rng = random.Random(seed)
        super().__init__("simulate", scenario, scenario == "attack_mit")

    def reset(self) -> None:
        super().reset()
        self.availability = 1.0
        self._cycle_n = -1
        self._decided = False

    def set_scenario(self, scenario: str) -> None:
        self.scenario = scenario
        self.mitigation = scenario == "attack_mit"
        self.reset()
        names = {"normal": "Normal traffic", "attack_nomit": "Attack, mitigation off",
                 "attack_mit": "Attack, mitigation on"}
        self.emit("info", names.get(scenario, scenario), "simulated scenario started")

    def _sim_block(self, h: HostState, now: float) -> None:
        confirm = 2 + 3 * self.rng.random()
        self.add_block(h.ip, self.BLOCK_SECONDS, "5/5 flows", 0.95 + 0.04 * self.rng.random(), confirm_ms=confirm)
        self._incident_confirm(h.ip, now + confirm / 1000, confirm)

    def tick(self, dt: float) -> None:
        now = self.now()
        cyc = (now - self.start) % self.CYCLE
        n = int((now - self.start) // self.CYCLE)
        if n != self._cycle_n:
            self._cycle_n, self._decided = n, False

        attacking = self.scenario != "normal" and self.ATTACK_START <= cyc < self.ATTACK_STOP
        ramp = 0.0
        if attacking:
            ramp = min(1.0, (cyc - self.ATTACK_START) / 2.0)
            if cyc > self.ATTACK_STOP - 2:
                ramp *= max(0.0, (self.ATTACK_STOP - cyc) / 2.0)
            if ramp > 0.05:  # mark the start once attack traffic actually flows
                self.mark_attack_start(now, "UDP flood from h1, h3, h5 toward the server", "udp")
        elif self.incident is not None and self.incident.ended_at is None:
            self.mark_attack_end(now, "flood generators finished")

        for h in self.hosts.values():
            if h.role == "benign":
                rate = self.BENIGN_PPS * (0.7 + 0.6 * self.rng.random())
                flows, bad = round(rate * dt / 9), 0
            elif h.role == "attacker":
                rate = self.ATTACK_PPS * ramp * (0.85 + 0.3 * self.rng.random()) if attacking else 0.0
                flows = bad = round(rate * dt / 80)
            else:
                continue
            blocked = h.ip in self.blocks
            h.pps, h.drop_pps = (0.0, rate) if blocked else (rate, 0.0)
            h.bps = h.pps * 550
            if blocked:
                dropped = round(rate * dt)
                self.blocks[h.ip].dropped_packets += dropped
                self.blocks[h.ip].drop_pps = rate
                self.dropped_total += dropped
                if rate > 0:
                    self._incident_drop(h.ip, now)
            elif flows:
                h.votes.append((now, flows, bad))

        # The monitor decides: one block request per attacker (a dry run if mitigation is off).
        if attacking and ramp > 0.4 and not self._decided:
            self._decided = True
            for h in self.hosts.values():
                if h.role != "attacker" or h.ip in self.blocks:
                    continue
                score = 0.95 + 0.04 * self.rng.random()
                self.mark_detection(now, h.ip, suppressed=not self.mitigation, api_ms=3 + 2 * self.rng.random())
                if self.mitigation:
                    self.emit("detect", f"Flagged {h.id}", f"5/5 recent flows attack · score {score:.2f}", h.ip)
                    self._sim_block(h, now)
                else:
                    self.emit("detect", f"Flagged {h.id}", f"would block · score {score:.2f} (mitigation off)", h.ip)
        if self.mitigation and attacking and self._decided:
            for h in self.hosts.values():
                if h.role != "attacker":
                    continue
                blk = self.blocks.get(h.ip)
                if blk is None and h.pps > ATTACKING_PPS:  # e.g. mitigation turned on mid-attack
                    self.mark_detection(now, h.ip, api_ms=3 + 2 * self.rng.random())
                    self._sim_block(h, now)
                elif blk is not None and blk.remaining(now) < 3 and h.drop_pps > 0:
                    # Like the controller: renew a rule that is still dropping near expiry.
                    blk.start, blk.renewals = now, blk.renewals + 1
                    self.emit("block", f"Renewed {h.id}",
                              f"still dropping {h.drop_pps:,.0f} pkt/s · +{self.BLOCK_SECONDS:.0f}s", h.ip)

        # Simulated availability: drops as more attack load reaches the server.
        attack_to_server = sum(h.pps for h in self.hosts.values() if h.role == "attacker")
        overload = attack_to_server / SERVER_CAPACITY_PPS
        target = min(0.99, max(0.03, 1.0 / (1.0 + overload ** 1.5))) if overload > 0 else 0.99
        self.availability += (target - self.availability) * min(1.0, dt * 1.3)

    def manual_block(self, ip: str) -> bool:
        return self.add_block(ip, self.BLOCK_SECONDS, "manual (operator)", 0.0)

    def manual_unblock(self, ip: str) -> None:
        self.remove_block(ip, "removed by operator")

