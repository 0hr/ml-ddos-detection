"""Interactive live session (MUST run as root; needs Mininet + OVS).

Brings the whole testbed up and keeps it up: controller, topology, web service, the
tap -> monitor pipeline and the normal clients. Nothing is scripted after that: attacks and
load bursts are started and stopped on demand through a small control API, which is what the
dashboard's buttons call. Open the dashboard in live mode to watch it happen:

    sudo python3 testbed/live.py                 # terminal 1 (root)
    uv run python monitor/server/app.py --mode live   # terminal 2, then http://127.0.0.1:8099

Control API on 127.0.0.1:8091 (loopback only):
    GET  /state                      what is running, and for how much longer
    POST /attack {"action": "start", "type": "udp", "duration": 30}
    POST /attack {"action": "stop"}
    POST /load   {"action": "start", "duration": 30}   flash crowd (must not be blocked)
    POST /load   {"action": "stop"}
Mitigation is turned on and off on the controller (POST /mitigation), so you can toggle it
while an attack runs.

Output: results/runs/live/ - the same files as an experiment run plus session_events.jsonl
(attack/load start and stop times, the truth behind the latency shown on screen). The
session ends on Ctrl-C or after --max-minutes.
"""

import argparse
import json
import queue
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mininet.log import setLogLevel

from testbed.run_experiment import (
    ATTACKER_HOSTS, BENIGN_HOSTS, RUNS, Controller, add_stack_args, check_environment, kill_stale,
    set_current, start_attack, start_benign, start_stack, stop_procs, write_meta,
)
from testbed.topology import SERVER_IP, build_net

ATTACK_TYPES = ("udp", "conn", "http")
MAX_ATTACK_S = 120.0
MAX_LOAD_S = 120.0


class Session:
    """State shared by the control API (reads, queues) and the main loop (acts).

    Mininet's host.cmd() is not thread-safe, so API requests are only queued; the main loop
    is the only place that touches the network.
    """

    def __init__(self, net, out_dir: Path, args, meta: dict):
        self.net, self.out_dir, self.args, self.meta = net, out_dir, args, meta
        self.commands: queue.Queue = queue.Queue()
        self.lock = threading.Lock()
        self.attack = None  # {"type", "started", "ends"}
        self.load = None    # {"started", "ends"}
        self.n_side = max(1, args.hosts // 2)
        self.seq = 0
        self.started = time.time()
        self.ends = self.started + args.max_minutes * 60

    def log(self, event: str, **fields) -> None:
        rec = {"ts": time.time(), "event": event, **fields}
        with open(self.out_dir / "session_events.jsonl", "a") as fh:
            fh.write(json.dumps(rec) + "\n")
        print(f"[session] {event} {fields}", flush=True)

    def state(self) -> dict:
        now = time.time()
        with self.lock:
            def view(x):
                return None if x is None else {**x, "remaining_s": round(max(0.0, x["ends"] - now), 1)}
            return {"uptime_s": round(now - self.started, 1), "remaining_s": round(self.ends - now, 1),
                    "attack": view(self.attack), "load": view(self.load),
                    "attack_types": list(ATTACK_TYPES), "attackers": list(ATTACKER_HOSTS[: self.n_side]),
                    "max_attack_s": MAX_ATTACK_S}

    # ---- actions: main loop only -------------------------------------------------
    def start_attack(self, kind: str, duration: float, threads: int) -> None:
        if self.attack is not None:
            return
        self.seq += 1
        hosts = ATTACKER_HOSTS[: self.n_side]
        now = time.time()
        ips = start_attack(self.net, self.out_dir, hosts, kind, threads, duration, self.seq * 100)
        with self.lock:
            self.attack = {"type": kind, "started": now, "ends": now + duration}
        self.meta["attacker_ips"] = ips
        self.meta["attack_start"] = now
        self.meta.setdefault("attacks", []).append({"type": kind, "start": now, "duration": duration})
        write_meta(self.out_dir, self.meta)
        self.log("attack_started", type=kind, duration=duration, threads=threads, hosts=list(hosts), ips=ips)

    def stop_attack(self, reason: str) -> None:
        if self.attack is None:
            return
        subprocess.run(["pkill", "-f", "testbed/attack.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with self.lock:
            kind, self.attack = self.attack["type"], None
        self.log("attack_stopped", type=kind, reason=reason)

    def start_load(self, duration: float) -> None:
        if self.load is not None:
            return
        self.seq += 1
        now = time.time()
        start_benign(self.net, self.out_dir, BENIGN_HOSTS[: self.n_side], rate=12.0, workers=2,
                     duration=duration, seed_base=self.seq * 100, suffix=f"_burst{self.seq}")
        with self.lock:
            self.load = {"started": now, "ends": now + duration}
        self.log("load_started", duration=duration, rate=12.0)

    def stop_load(self, reason: str) -> None:
        if self.load is None:
            return
        subprocess.run(["pkill", "-f", "_burst"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with self.lock:
            self.load = None
        self.log("load_stopped", reason=reason)

    def step(self) -> None:
        """Run queued commands and close anything whose time is up."""
        try:
            while True:
                kind, body = self.commands.get_nowait()
                action = body.get("action")
                if kind == "attack" and action == "start":
                    self.start_attack(body["type"], body["duration"], body["threads"])
                elif kind == "attack" and action == "stop":
                    self.stop_attack("operator")
                elif kind == "load" and action == "start":
                    self.start_load(body["duration"])
                elif kind == "load" and action == "stop":
                    self.stop_load("operator")
        except queue.Empty:
            pass
        now = time.time()
        if self.attack and now >= self.attack["ends"]:
            self.stop_attack("finished")
        if self.load and now >= self.load["ends"]:
            self.stop_load("finished")


def validate(kind: str, body: dict, args) -> tuple[int, dict]:
    """Check a control request; returns (status, cleaned body or error)."""
    if not isinstance(body, dict) or body.get("action") not in ("start", "stop"):
        return 400, {"error": "action must be 'start' or 'stop'"}
    if body["action"] == "stop":
        return 200, {"action": "stop"}
    try:
        limit = MAX_ATTACK_S if kind == "attack" else MAX_LOAD_S
        duration = min(max(float(body.get("duration", 30)), 3.0), limit)
    except (TypeError, ValueError):
        return 400, {"error": "duration must be a number of seconds"}
    clean = {"action": "start", "duration": duration}
    if kind == "attack":
        clean["type"] = body.get("type", "udp")
        if clean["type"] not in ATTACK_TYPES:
            return 400, {"error": f"type must be one of {', '.join(ATTACK_TYPES)}"}
        clean["threads"] = args.attack_threads
    return 200, clean


def make_handler(session: Session, args):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, payload: dict) -> None:
            data = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._send(*((200, session.state()) if self.path == "/state" else (404, {"error": "not found"})))

        def do_POST(self):
            kind = self.path.strip("/")
            if kind not in ("attack", "load"):
                return self._send(404, {"error": "not found"})
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            except ValueError:
                return self._send(400, {"error": "invalid JSON"})
            code, clean = validate(kind, body, args)
            if code != 200:
                return self._send(code, clean)
            state = session.state()
            if clean["action"] == "start" and state[kind] is not None:
                return self._send(409, {"error": f"{kind} already running"})
            session.commands.put((kind, clean))
            self._send(200, {"ok": True, kind: clean})

        def log_message(self, *a):  # keep the terminal clean for session events
            pass

    return Handler


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_stack_args(ap)
    ap.add_argument("--control-port", type=int, default=8091)
    ap.add_argument("--max-minutes", type=float, default=30, help="the session ends by itself after this long")
    ap.add_argument("--benign-rate", type=float, default=2.0, help="requests/s per benign client worker")
    ap.add_argument("--no-mitigation", action="store_true", help="start in detect-only mode")
    ap.add_argument("--save-pcap", action="store_true", help="also write capture.pcap (grows quickly)")
    args = ap.parse_args()
    check_environment()
    setLogLevel("warning")

    out_dir = RUNS / "live"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    kill_stale()
    subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    controller = Controller(out_dir, args.of_port, args.api_port, mitigation=not args.no_mitigation)
    net, procs, server, session = None, [], None, None
    n_side = max(1, args.hosts // 2)
    meta = {"scenario": "live", "mode": "session", "repeat": 1, "hosts": args.hosts,
            "config": {"mitigate": not args.no_mitigation, "benign_rate": args.benign_rate},
            "attacker_ips": [], "benign_ips": [], "server_ip": SERVER_IP, "attack_start": None,
            "control_api": f"http://127.0.0.1:{args.control_port}", "run_id": time.time(),
            "t_start": time.time()}
    write_meta(out_dir, meta)
    set_current(out_dir, meta)
    try:
        controller.start()
        net = build_net(n_hosts=args.hosts, controller_port=args.of_port)
        net.start()
        # The monitor always asks for blocks; the controller enforces detect-only, so you can
        # switch mitigation while the session runs.
        procs += start_stack(net, out_dir, args, True, meta, save_pcap=args.save_pcap)
        meta["t_start"] = time.time()
        meta["benign_ips"] = start_benign(net, out_dir, BENIGN_HOSTS[:n_side], args.benign_rate, 2,
                                          args.max_minutes * 60, 0)
        meta["attacker_ips"] = [net.get(h).IP() for h in ATTACKER_HOSTS[:n_side]]
        write_meta(out_dir, meta)
        set_current(out_dir, meta)

        session = Session(net, out_dir, args, meta)
        server = ThreadingHTTPServer(("127.0.0.1", args.control_port), make_handler(session, args))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        session.log("session_started", control_api=meta["control_api"], max_minutes=args.max_minutes)
        print(f"\nlive session up - control API {meta['control_api']}\n"
              f"dashboard:  uv run python monitor/server/app.py --mode live   (http://127.0.0.1:8099)\n"
              f"Ctrl-C to stop\n", flush=True)
        while time.time() < session.ends:
            session.step()
            for proc in procs:
                if proc.poll() is not None:
                    raise RuntimeError("the tap/monitor pipeline exited; see results/runs/live/monitor.log")
            time.sleep(0.2)
    except KeyboardInterrupt:
        print("\nstopping ...", flush=True)
    finally:
        if session is not None:
            session.stop_attack("session ended")
            session.stop_load("session ended")
            session.log("session_ended")
        if server is not None:
            server.shutdown()
        stop_procs(procs)
        if net is not None:
            net.stop()
        controller.stop()
        kill_stale()
        meta["t_end"] = time.time()
        write_meta(out_dir, meta)
        set_current(out_dir, meta, finished=True)
    print(f"session saved -> {out_dir.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
