"""Dashboard API server: drives an engine and streams snapshots to the React UI over SSE.

    uv run python monitor/server/app.py                                   # simulated data, no root
    uv run python monitor/server/app.py --mode live                       # follow the run in progress
    uv run python monitor/server/app.py --mode live   --run results/runs/attack_mit
    uv run python monitor/server/app.py --mode replay --run results/runs/attack_mit

Live mode without --run follows results/runs/current.json, which the testbed keeps pointed
at the run in progress (an experiment scenario, or an interactive `testbed/live.py` session).

Endpoints:
    GET  /events                Server-Sent Events: a full state snapshot 4x per second
    GET  /api/state             one snapshot (JSON)
    GET  /api/config            mode, available controls, scenario list, topology
    POST /api/scenario {name}   switch the simulated scenario           (simulate only)
    POST /api/mitigation {enabled}  simulate: local · live: the controller's detect-only switch
    POST /api/block {ip}        simulate: local · live: forwarded to the SDN controller
    POST /api/unblock {ip}      simulate: local · live: forwarded to the SDN controller
    POST /api/attack {action, type, duration}  start/stop an attack  (live session only)
    POST /api/load   {action, duration}        start/stop a flash crowd (live session only)
A control that the current source cannot honour answers 409 (a replay is read-only).
"""

import argparse
import json
import os
import queue
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory

from engine import HOSTS, SWITCHES, Simulator
from live import RunSource

ROOT = Path(__file__).resolve().parents[2]
WEB_DIST = ROOT / "monitor/web/dist"

app = Flask(__name__, static_folder=None)
TICK_HZ = 4.0
SCENARIOS = [
    {"id": "normal", "label": "Normal", "desc": "normal traffic only"},
    {"id": "attack_nomit", "label": "Attack", "desc": "flood, mitigation off"},
    {"id": "attack_mit", "label": "Attack + mitigation", "desc": "flood, automatic blocking"},
]
CONTROLLER = "http://127.0.0.1:8080"  # set from --controller
TOKEN = ""  # set from --token / $DDOS_API_TOKEN


class Hub:
    """Owns the engine, ticks it, and fans snapshots out to SSE subscribers."""

    def __init__(self, engine):
        self.engine = engine
        self.lock = threading.Lock()
        self.subscribers: set[queue.Queue] = set()
        self.last_event_id = 0
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        period = 1.0 / TICK_HZ
        last = time.time()
        while True:
            now = time.time()
            dt, last = now - last, now
            with self.lock:
                self.engine.tick(dt)
                snap = self.engine.snapshot()
                snap["events"] = [e for e in self.engine.events if e["id"] > self.last_event_id]
                if self.engine.events:
                    self.last_event_id = self.engine.events[-1]["id"]
            payload = f"data: {json.dumps(snap)}\n\n"
            for q in list(self.subscribers):
                try:
                    q.put_nowait(payload)
                except queue.Full:
                    pass
            time.sleep(max(0.0, period - (time.time() - now)))

    def subscribe(self) -> queue.Queue:
        q = queue.Queue(maxsize=8)
        with self.lock:  # give a new client some recent history so it is not blank
            first = self.engine.snapshot()
            first["events"] = self.engine.events[-40:]
        q.put_nowait(f"data: {json.dumps(first)}\n\n")
        self.subscribers.add(q)
        return q

    def unsubscribe(self, q):
        self.subscribers.discard(q)


hub: Hub = None  # set in main


def refuse(control: str):
    return jsonify({"error": f"'{control}' is not available in {hub.engine.mode} mode"}), 409


def forward(url: str, body: dict, token: str = "", what: str = "controller"):
    """POST to the controller or the live session and relay its answer."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return jsonify(json.loads(r.read())), r.status
    except urllib.error.HTTPError as exc:
        try:
            return jsonify(json.loads(exc.read() or b"{}")), exc.code
        except ValueError:
            return jsonify({"error": f"{what} answered HTTP {exc.code}"}), exc.code
    except OSError as exc:
        return jsonify({"error": f"{what} unreachable: {exc}"}), 502


def controller_post(path: str, body: dict):
    return forward(CONTROLLER + path, body, TOKEN)


def session_post(path: str, body: dict):
    api = getattr(hub.engine, "meta", {}).get("control_api")
    if not api:
        return jsonify({"error": "this run has no live session"}), 409
    return forward(api + path, body, what="live session")


@app.get("/events")
def events():
    def stream():
        q = hub.subscribe()
        try:
            while True:
                try:
                    yield q.get(timeout=5)
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            hub.unsubscribe(q)
    return Response(stream(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"})


@app.get("/api/state")
def state():
    with hub.lock:
        return jsonify(hub.engine.snapshot())


@app.get("/api/config")
def config():
    e = hub.engine
    return jsonify({
        "mode": e.mode, "scenario": e.scenario, "mitigation": e.mitigation, "controls": e.controls,
        "scenarios": SCENARIOS if e.controls["scenario"] else [],
        "topology": {"hosts": HOSTS, "switches": SWITCHES, "controller": "controller"},
        "tick_hz": TICK_HZ,
    })


@app.post("/api/scenario")
def set_scenario():
    if not hub.engine.controls["scenario"]:
        return refuse("scenario")
    name = (request.json or {}).get("name", "")
    if not any(s["id"] == name for s in SCENARIOS):
        return jsonify({"error": "unknown scenario"}), 400
    with hub.lock:
        hub.engine.set_scenario(name)
    return jsonify({"ok": True, "scenario": name, "mitigation": hub.engine.mitigation})


@app.post("/api/mitigation")
def set_mitigation():
    if not hub.engine.controls["mitigation_toggle"]:
        return refuse("mitigation toggle")
    on = bool((request.json or {}).get("enabled", True))
    if hub.engine.mode == "live":  # the controller's switch; the dashboard sees it in events
        return controller_post("/mitigation", {"enabled": on})
    with hub.lock:
        hub.engine.mitigation = on
        hub.engine.emit("info", f"Mitigation {'on' if on else 'off'}", "operator toggle")
    return jsonify({"ok": True, "mitigation": on})


@app.post("/api/block")
def manual_block():
    if not hub.engine.controls["manual_block"]:
        return refuse("block")
    ip = (request.json or {}).get("ip", "")
    if hub.engine.mode == "live":  # the real drop rule; the dashboard sees it via controller events
        return controller_post("/block", {"ip": ip, "duration": 20, "reason": "manual (operator)"})
    with hub.lock:
        ok = hub.engine.manual_block(ip)
    return (jsonify({"ok": True, "ip": ip}), 200) if ok else (jsonify({"error": "server is whitelisted"}), 403)


@app.post("/api/unblock")
def manual_unblock():
    if not hub.engine.controls["manual_block"]:
        return refuse("unblock")
    ip = (request.json or {}).get("ip", "")
    if hub.engine.mode == "live":
        return controller_post("/unblock", {"ip": ip})
    with hub.lock:
        hub.engine.manual_unblock(ip)
    return jsonify({"ok": True, "ip": ip})


@app.post("/api/attack")
def attack():
    if not hub.engine.controls["attack"]:
        return refuse("attack control")
    return session_post("/attack", request.json or {})


@app.post("/api/load")
def load():
    if not hub.engine.controls["load"]:
        return refuse("load control")
    return session_post("/load", request.json or {})


# ---- serve the built SPA (production) --------------------------------------------
@app.get("/")
@app.get("/<path:path>")
def spa(path="index.html"):
    if (WEB_DIST / path).is_file():
        return send_from_directory(WEB_DIST, path)
    if (WEB_DIST / "index.html").exists():
        return send_from_directory(WEB_DIST, "index.html")
    return Response("Frontend not built. Run `npm run build` in monitor/web, "
                    "or use the Vite dev server (npm run dev).", mimetype="text/plain")


def main():
    global hub, CONTROLLER, TOKEN
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["simulate", "live", "replay"], default="simulate")
    ap.add_argument("--scenario", default="attack_mit", choices=[s["id"] for s in SCENARIOS])
    ap.add_argument("--run", help="run directory, e.g. results/runs/attack_mit "
                    "(replay: required · live: default is the run in progress)")
    ap.add_argument("--speed", type=float, default=1.0, help="replay speed multiplier")
    ap.add_argument("--controller", default=CONTROLLER, help="SDN controller REST API (live mode)")
    ap.add_argument("--token", default=os.environ.get("DDOS_API_TOKEN", ""),
                    help="bearer token for the controller API (default: $DDOS_API_TOKEN)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8099)
    args = ap.parse_args()
    CONTROLLER, TOKEN = args.controller.rstrip("/"), args.token

    if args.mode == "simulate":
        engine = Simulator(scenario=args.scenario)
        engine.set_scenario(args.scenario)
    else:
        if args.run and not Path(args.run).is_dir():
            ap.error(f"--run {args.run} is not a directory")
        if args.mode == "replay" and not args.run:
            ap.error("--run is required in replay mode")
        engine = RunSource(args.run, replay=args.mode == "replay", speed=args.speed,
                           pointer=str(ROOT / "results/runs/current.json"),
                           controller=CONTROLLER if args.mode == "live" else "", token=TOKEN)
    hub = Hub(engine)
    print(f"dashboard API: http://{args.host}:{args.port}  (mode={args.mode})")
    app.run(host=args.host, port=args.port, threaded=True, debug=False)


if __name__ == "__main__":
    main()
