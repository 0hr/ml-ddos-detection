"""RunSource: drive the dashboard from a real testbed run (results/runs/<scenario>/).

Files read (all append-only JSON lines written by the testbed):
  telemetry.jsonl          per-0.5 s per-host packet rates and flow verdicts (traffic/monitor.py)
  detections.jsonl         block decisions, also dry runs                    (traffic/monitor.py)
  controller_events.jsonl  drop rules installed / confirmed / renewed / removed, and the
                           rules' drop counters once per second              (controller)
  client_h*.jsonl          every normal HTTP request, ok or not              (testbed/client.py)
  session_events.jsonl     attack / load start and stop                      (testbed/live.py)
  scenario.json            roles, mitigation mode, attack start

live    tails a run in progress on the wall clock. Without --run it follows
        results/runs/current.json, so it moves from scenario to scenario by itself. It also
        polls the controller (and the live session, if there is one) for their health.
replay  plays a finished run back on its recorded clock (looping), so timings, charts and
        countdowns match what actually happened.

Availability is *measured*: the share of normal requests that succeeded in the last 5 s.
Dropped traffic is *measured* too, from the switches' drop-rule counters, the only place
blocked packets can still be counted.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from pathlib import Path

from engine import ATTACKING_PPS, HOSTS, IP_TO_HOST, Engine

AVAIL_WINDOW_S = 5.0
TELEMETRY_STALE_S = 2.5
DROP_STALE_S = 2.5  # a drop counter older than this no longer reflects now
POLL_S = 1.0
ATTACKER_IPS = {h["ip"] for h in HOSTS if h["role"] == "attacker"}
ATTACK_NAMES = {"udp": "UDP flood", "conn": "TCP connection flood", "http": "HTTP request flood"}


def _read_jsonl(path: Path, start: int = 0) -> tuple[list[dict], int]:
    """Complete lines from byte offset `start`; returns (records, new offset).

    A file shorter than the offset was truncated or recreated (a new run reusing the
    directory), so it is read again from the top.
    """
    out = []
    try:
        if path.stat().st_size < start:
            start = 0
        with path.open() as fh:
            fh.seek(start)
            while True:
                line = fh.readline()
                if not line.endswith("\n"):
                    break  # partial line still being written; re-read next tick
                start = fh.tell()
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except FileNotFoundError:
        return out, 0
    return out, start


def _stamp(kind: str, rec: dict) -> float | None:
    return rec.get("t") if kind == "telemetry" else rec.get("ts")


def _get_json(url: str, token: str = "", timeout: float = 1.0) -> dict | None:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except (OSError, ValueError):
        return None


class RunSource(Engine):
    availability_source = "measured"

    def __init__(self, run_dir: str | None, replay: bool = False, speed: float = 1.0,
                 pointer: str | None = None, controller: str = "", token: str = ""):
        self.replay = replay
        self.speed = speed
        self.pointer = Path(pointer) if pointer and not run_dir else None
        self.controller_url, self.token = controller.rstrip("/"), token
        self.run: Path | None = Path(run_dir) if run_dir else None
        self.meta: dict = {}
        self.finished = False
        self._ctl: dict | None = None      # last controller /status, None = unreachable
        self._session: dict | None = None  # last live-session /state, None = no session
        self._offsets: dict[Path, int] = {}
        self._last_poll = 0.0
        self._load_meta()
        super().__init__("replay" if replay else "live", self._name(), self.meta.get("config", {}).get("mitigate"))
        if replay:
            self._timeline = self._load_all()
            ts = [t for t, _, _ in self._timeline]
            self._t0 = self.meta.get("t_start") or (min(ts) if ts else time.time())
            self._t_end = max(ts) if ts else self._t0
            self._restart()
        else:
            threading.Thread(target=self._poll_loop, daemon=True).start()

    # ------------------------------------------------------------------ run / meta
    def _load_meta(self) -> None:
        if self.pointer is not None:
            try:
                cur = json.loads(self.pointer.read_text())
                self.run, self.finished = Path(cur["run"]), bool(cur.get("finished"))
            except (OSError, ValueError, KeyError):
                pass
        if self.run is None:
            return
        try:
            self.meta = json.loads((self.run / "scenario.json").read_text())
        except (OSError, ValueError):
            pass

    def _name(self) -> str:
        if self.run is None:
            return "waiting for a run"
        name = self.meta.get("scenario", self.run.name)
        if self.run.name.startswith("rep"):  # one repetition of a repeated experiment
            name = f"{self.run.parent.name} {self.run.name}"
        return name

    @property
    def is_session(self) -> bool:
        return self.meta.get("mode") == "session"

    @property
    def controls(self) -> dict:
        ctl = not self.replay and self._ctl is not None
        sess = not self.replay and self._session is not None
        return {"scenario": False, "mitigation_toggle": ctl, "manual_block": ctl, "attack": sess, "load": sess}

    def _refresh_run(self) -> None:
        """Live: notice a new run (pointer moved, or the directory reused) and pick up what
        the runner added to scenario.json since the last look."""
        run, run_id = self.run, self.meta.get("run_id")
        self._load_meta()
        if self.run != run or self.meta.get("run_id") != run_id:
            self._offsets.clear()
            self.reset()
            self.scenario = self._name()
            self.emit("info", f"Following {self.scenario}", str(self.run))
        self.scenario = self._name()
        self.start = self.meta.get("t_start", self.start)
        if self._ctl is None:  # no controller to ask: the run's own config is the best answer
            self.mitigation = self.meta.get("config", {}).get("mitigate", self.mitigation)
        start = self.meta.get("attack_start")
        if start and not self.is_session and start != self._meta_attack:
            self._meta_attack = start
            kind = self.meta.get("config", {}).get("attack") or ""
            self.mark_attack_start(start, f"{ATTACK_NAMES.get(kind, 'flood')} from the attack hosts", kind)

    # ------------------------------------------------------------------ clock
    def now(self) -> float:
        if self.replay and hasattr(self, "_wall0"):
            return self._t0 + (time.time() - self._wall0) * self.speed
        return time.time()

    def _restart(self) -> None:
        self._wall0 = time.time()
        self._cursor = 0
        self.reset()
        self.emit("info", f"Replaying {self.scenario}", "recorded run, real timings")

    def reset(self) -> None:
        super().reset()
        self.dropped_visible = False  # until the first drop counter arrives
        self._requests: deque = deque()  # (ts, ok) of benign requests
        self._last_telemetry: float | None = None
        self._lag_ms: float | None = None
        self._drops: dict[tuple, tuple] = {}  # (ip, dpid) -> (ts, pps)
        self._drop_last: dict[str, int] = {}  # ip -> last cumulative dropped packets
        self._meta_attack = None
        self._switches: set = set()
        self._ground_truth = False
        if self.replay and hasattr(self, "_t0"):
            self.start = self._t0
        elif self.meta.get("t_start"):
            self.start = self.meta["t_start"]
        self.availability_source = "measured"
        if self.replay and not self._client_files():
            self.availability_source = "unavailable"

    # ------------------------------------------------------------------ input
    def _client_files(self) -> list[Path]:
        return sorted(self.run.glob("client_*.jsonl")) if self.run else []

    def _sources(self) -> list[tuple[str, Path]]:
        if self.run is None:
            return []
        return ([("session", self.run / "session_events.jsonl"), ("telemetry", self.run / "telemetry.jsonl"),
                 ("detection", self.run / "detections.jsonl"),
                 ("controller", self.run / "controller_events.jsonl")]
                + [("client", p) for p in self._client_files()])

    def _load_all(self) -> list[tuple[float, str, dict]]:
        rows = []
        for kind, path in self._sources():
            recs, _ = _read_jsonl(path)
            rows += [(t, kind, r) for r in recs if (t := _stamp(kind, r)) is not None]
        if self.meta.get("attack_start") and not self.is_session:
            rows.append((self.meta["attack_start"], "attack_start", {}))  # recorded by the runner
        rows.sort(key=lambda x: x[0])
        return rows

    def tick(self, dt: float) -> None:
        now = self.now()
        if self.replay:
            while self._cursor < len(self._timeline) and self._timeline[self._cursor][0] <= now:
                _, kind, rec = self._timeline[self._cursor]
                self._apply(kind, rec)
                self._cursor += 1
            if self._cursor >= len(self._timeline) and now > self._t_end + 4:
                self._restart()  # loop the recording
                return
        else:
            if now - self._last_poll >= POLL_S:
                self._last_poll = now
                self._refresh_run()
            for kind, path in self._sources():
                recs, self._offsets[path] = _read_jsonl(path, self._offsets.get(path, 0))
                for rec in recs:
                    self._apply(kind, rec)
        # Telemetry stopped (monitor exited or run over): rates are no longer known.
        if self._last_telemetry is not None and now - self._last_telemetry > TELEMETRY_STALE_S:
            for h in self.hosts.values():
                h.pps = h.bps = 0.0
        for h in self.hosts.values():
            h.drop_pps = sum(pps for (ip, _), (ts, pps) in self._drops.items()
                             if ip == h.ip and now - ts <= DROP_STALE_S and ip in self.blocks)
        for blk in self.blocks.values():
            host = self.hosts.get(IP_TO_HOST.get(blk.ip, ""))
            blk.drop_pps = host.drop_pps if host is not None else 0.0
        self._update_availability(now)

    def _apply(self, kind: str, rec: dict) -> None:
        if kind == "telemetry":
            self._apply_telemetry(rec)
        elif kind == "detection":
            self._apply_detection(rec)
        elif kind == "controller":
            self._apply_controller(rec)
        elif kind == "session":
            self._apply_session(rec)
        elif kind == "client":
            self._requests.append((rec.get("ts", 0.0), bool(rec.get("ok"))))
        elif kind == "attack_start":
            kind_ = self.meta.get("config", {}).get("attack") or ""
            self._ground_truth = True
            self.mark_attack_start(self.meta["attack_start"],
                                   f"{ATTACK_NAMES.get(kind_, 'flood')} from the attack hosts", kind_)

    def _apply_telemetry(self, rec: dict) -> None:
        if rec.get("event") != "telemetry":
            return
        t = rec["t"]
        self._last_telemetry = t
        self._lag_ms = (rec.get("monitor") or {}).get("lag_ms")
        seen = rec.get("hosts", {})
        # A host missing from a window sent nothing: its rate is 0, not "unchanged".
        for h in self.hosts.values():
            if h.role == "server":
                continue
            m = seen.get(h.ip, {})
            h.pps, h.bps = float(m.get("pps", 0)), float(m.get("bps", 0))
            if m.get("flows"):
                h.votes.append((t, int(m["flows"]), int(m.get("attack_flows", 0))))
        # Fallback: with no recorded attack start, guess it from the traffic.
        known = self._ground_truth or self.meta.get("attack_start") or self.is_session
        if not known and any(self.hosts[IP_TO_HOST[ip]].pps > ATTACKING_PPS for ip in ATTACKER_IPS):
            self.mark_attack_start(t - rec.get("window", 0.5), "flood from the attack hosts toward the server")

    def _apply_detection(self, rec: dict) -> None:
        if rec.get("event") != "block_request":
            return
        ip, ts = rec.get("ip", ""), rec["ts"]
        host = IP_TO_HOST.get(ip, ip)
        dry = bool((rec.get("response") or {}).get("dry_run"))
        rule = rec.get("rule", "model")
        if ip in ATTACKER_IPS:
            self.mark_detection(ts, ip, suppressed=dry, api_ms=rec.get("api_latency_ms"), rule=rule)
        if rule == "rate":  # ordinary-looking flows, just far too many of them
            verdict = f"{rec.get('flow_rate', 0):,.0f} flows/s, over the rate limit"
        else:
            verdict = f"{rec.get('attack_flows', '?')}/{rec.get('window_flows', '?')} recent flows attack"
            if rec.get("score") is not None:
                verdict += f" · score {rec['score']:.2f}"
        self.emit("detect", f"Flagged {host}", verdict + (" · would block (mitigation off)" if dry else ""),
                  ip, at=ts)

    def _apply_controller(self, rec: dict) -> None:
        ev, ip, ts = rec.get("event"), rec.get("ip", ""), rec.get("ts")
        if ev == "block_installed":
            self.add_block(ip, float(rec.get("duration", 20)), rec.get("reason", "model"),
                           float(rec.get("score") or 0.0), at=ts)
            self._drop_last.pop(ip, None)
        elif ev == "block_confirmed":
            latency = float(rec.get("latency_ms", 0))
            if ip in self.blocks:
                self.blocks[ip].confirm_ms = latency
            self._incident_confirm(ip, ts, latency)
        elif ev == "block_renewed":
            duration = float(rec.get("duration", 20))
            if ip not in self.blocks:
                self.add_block(ip, duration, "renewed", 0.0, at=ts)
            blk = self.blocks[ip]
            blk.start, blk.duration_s = ts, duration
            blk.renewals = int(rec.get("renewals", blk.renewals + 1))
            self.emit("block", f"Renewed {IP_TO_HOST.get(ip, ip)}",
                      f"still dropping {rec.get('drop_pps', 0):,.0f} pkt/s · +{duration:.0f}s", ip, at=ts)
        elif ev == "block_stats":
            self.dropped_visible = True
            pps = float(rec.get("drop_pps", 0))
            self._drops[(ip, rec.get("dpid"))] = (ts, pps)
            total = int(rec.get("dropped_packets", 0))
            last = self._drop_last.get(ip, 0)
            self.dropped_total += total - last if total >= last else total
            self._drop_last[ip] = total
            if ip in self.blocks:
                self.blocks[ip].dropped_packets = total
            if pps > 0:
                self._incident_drop(ip, ts)
        elif ev == "unblock":
            self.remove_block(ip, "removed by operator", at=ts)
        elif ev == "mitigation_changed":
            self.mitigation = bool(rec.get("enabled"))
            self.emit("info", f"Mitigation {'on' if self.mitigation else 'off'}",
                      "drop rules are installed again" if self.mitigation else "detect only: decisions are logged, not enforced",
                      at=ts)
        elif ev == "block_refused":
            self.emit("info", f"Block refused for {IP_TO_HOST.get(ip, ip)}", str(rec.get("why", "")), ip, at=ts)
        elif ev == "switch_connected":
            self._switches.add(rec.get("dpid"))
        elif ev == "switch_disconnected":
            self._switches.discard(rec.get("dpid"))
            self.emit("info", f"Switch {rec.get('dpid')} disconnected", at=ts)
        # block_removed fires once per switch at hard-timeout; the engine handles expiry.

    def _apply_session(self, rec: dict) -> None:
        ev, ts = rec.get("event"), rec.get("ts")
        if ev == "attack_started":
            kind = rec.get("type", "")
            hosts = ", ".join(rec.get("hosts", [])) or "the attack hosts"
            self.mark_attack_start(ts, f"{ATTACK_NAMES.get(kind, 'flood')} from {hosts}", kind)
        elif ev == "attack_stopped":
            self.mark_attack_end(ts, "stopped by operator" if rec.get("reason") == "operator" else "generators finished")
        elif ev == "load_started":
            self.emit("info", "Flash crowd started", f"legitimate clients at {rec.get('rate', '?')} req/s per worker", at=ts)
        elif ev == "load_stopped":
            self.emit("info", "Flash crowd ended", at=ts)
        elif ev == "session_started":
            self.emit("info", "Live session started", at=ts)
        elif ev == "session_ended":
            self.emit("info", "Live session ended", at=ts)

    def _update_availability(self, now: float) -> None:
        while self._requests and self._requests[0][0] < now - AVAIL_WINDOW_S:
            self._requests.popleft()
        recent = [ok for ts, ok in self._requests if ts <= now]
        if recent:
            self.availability = sum(recent) / len(recent)
        elif not self._client_files():
            self.availability = None  # no client logs: unknown, never made up

    # ------------------------------------------------------------------ health
    def _poll_loop(self) -> None:
        """Ask the controller and live session how they are; never blocks the tick."""
        while True:
            self._ctl = _get_json(self.controller_url + "/status", self.token) if self.controller_url else None
            api = self.meta.get("control_api")
            self._session = _get_json(api + "/state") if api and not self.finished else None
            if self._ctl is not None:
                self.mitigation = bool(self._ctl.get("mitigation", self.mitigation))
            time.sleep(POLL_S)

    def health(self, now: float) -> dict:
        age = None if self._last_telemetry is None else max(0.0, now - self._last_telemetry)
        if self.replay:
            return {"monitor": "recorded", "telemetry_age_s": age, "monitor_lag_ms": self._lag_ms,
                    "controller": "recorded", "switches": len(self._switches) or None, "session": False}
        monitor = "waiting" if age is None else "ok" if age <= TELEMETRY_STALE_S else "stale"
        return {
            "monitor": "finished" if self.finished and monitor != "ok" else monitor,
            "telemetry_age_s": None if age is None else round(age, 1),
            "monitor_lag_ms": self._lag_ms if monitor == "ok" else None,
            "controller": "ok" if self._ctl is not None else "down",
            "switches": len(self._ctl.get("switches", [])) if self._ctl is not None else None,
            "session": self._session is not None,
        }

    def session_state(self) -> dict | None:
        return self._session
