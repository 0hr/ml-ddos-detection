"""Run the full testbed experiment (MUST run as root; needs Mininet + OVS).

For each scenario it starts the controller, builds the topology, runs the Flask service
on `srv`, captures a pcap on the server link, runs the live monitor (detect + block),
drives normal and/or attack traffic, then tears it all down. We know each host's role, so
detection quality is measured on real testbed flows, not just the offline dataset.

Scenarios (default: all):
  normal        normal clients only, low rate                 -> baseline
  highload      normal clients only, high rate (flash crowd)  -> normal != attack check
  attack_nomit  normal + attackers, monitor detects but does NOT block
  attack_mit    normal + attackers, monitor blocks via the controller

Outputs under results/runs/<scenario>/ (or .../rep<k>/ with --repeat):
  capture.pcap  flows.parquet (features + prediction + truth)  client logs
  detections.jsonl  controller_events.jsonl  telemetry.jsonl  scenario.json
Plus results/experiment_summary.json tying the scenarios together. results/runs/current.json
always names the run in progress, which the dashboard's live mode follows.

--repeat N runs every scenario N times so the analysis can report a mean and a range. The
repetitions are interleaved (all scenarios once, then again), so slow drift on the host
spreads evenly, and each one uses fresh seeds for the client timing and the attack's ports,
so the repetitions are independent.

    sudo python3 testbed/run_experiment.py --hosts 6 --duration 40
    sudo python3 testbed/run_experiment.py --repeat 5
    sudo python3 testbed/run_experiment.py --scenario attack_mit --duration 30
"""

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mininet.log import setLogLevel

from testbed.topology import SERVER_IP, build_net

VENV_PY = str(ROOT / ".venv/bin/python")           # sklearn/pandas/flask (python 3.14)
OSKEN = str(ROOT / ".venv-osken/bin/osken-manager")  # controller (python 3.12)
ATTACKER_HOSTS = ("h1", "h3", "h5")
BENIGN_HOSTS = ("h2", "h4", "h6")
PROBER_HOST = "h2"
RUNS = ROOT / "results/runs"

SCENARIOS = {
    "normal": {"benign_rate": 2.0, "attack": None, "mitigate": False},
    "highload": {"benign_rate": 12.0, "attack": None, "mitigate": False},
    "attack_nomit": {"benign_rate": 2.0, "attack": "udp", "mitigate": False},
    "attack_mit": {"benign_rate": 2.0, "attack": "udp", "mitigate": True},
}


def wait_port(port, host="127.0.0.1", timeout=15):
    import socket

    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.3)
    return False


class Controller:
    """OpenFlow controller process + its mitigation REST API."""

    def __init__(self, out_dir, of_port, api_port, mitigation=True):
        self.out_dir = out_dir
        self.of_port = of_port
        self.api_port = api_port
        self.mitigation = mitigation
        self.events = out_dir / "controller_events.jsonl"
        self.log = open(out_dir / "controller.log", "w")
        self.proc = None

    def start(self):
        env = dict(os.environ, DDOS_API_PORT=str(self.api_port), DDOS_API_HOST="127.0.0.1",
                   DDOS_CTRL_LOG=str(self.events), DDOS_WHITELIST=SERVER_IP, PYTHONUNBUFFERED="1",
                   DDOS_MITIGATION="1" if self.mitigation else "0")
        env.pop("DDOS_API_TOKEN", None)  # loopback only; a stray token would lock the monitor out
        self.proc = subprocess.Popen(
            [OSKEN, "--ofp-tcp-listen-port", str(self.of_port),
             str(ROOT / "controller/ddos_controller.py")],
            stdout=self.log, stderr=subprocess.STDOUT, env=env)
        if not wait_port(self.api_port):
            raise RuntimeError("controller API did not come up")
        time.sleep(1.0)

    def status(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.api_port}/status", timeout=3) as r:
            return json.loads(r.read())

    def stop(self):
        if self.proc:
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.log.close()


STALE_PATTERNS = ("osken-manager", "testbed/webapp.py", "traffic/monitor.py", "testbed/client.py",
                  "testbed/attack.py")


def kill_stale():
    """Kill testbed processes left behind by a past (maybe crashed) run.

    eventlet listens with SO_REUSEPORT, so a leftover controller does not stop a new one
    from binding: both listen and the kernel splits switch and /block connections between
    them. Clearing them before each scenario keeps the results clean. One pkill per pattern
    and no shell, since `pkill -f` inside `sh -c` would match and kill the shell itself.
    """
    for pattern in STALE_PATTERNS:
        subprocess.run(["pkill", "-f", pattern], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)


def write_meta(out_dir: Path, meta: dict) -> None:
    """Rewrite scenario.json as the run goes, so the live dashboard sees the roles, the
    mitigation mode and the attack start while the run is still on."""
    tmp = out_dir / "scenario.json.tmp"
    tmp.write_text(json.dumps(meta, indent=2))
    tmp.replace(out_dir / "scenario.json")


def set_current(out_dir: Path, meta: dict, finished: bool = False) -> None:
    """Point results/runs/current.json at the run in progress (followed by the dashboard)."""
    tmp = RUNS / "current.json.tmp"
    tmp.write_text(json.dumps({"run": str(out_dir), "scenario": meta.get("scenario"),
                               "repeat": meta.get("repeat"), "started": meta.get("t_start"),
                               "finished": finished}))
    tmp.replace(RUNS / "current.json")


def server_capture_interface(srv) -> str:
    # srv-eth0 is inside the srv namespace, which tcpdump here cannot see. Capture the
    # switch-side end of the same veth (s1-ethN, root namespace) instead.
    link = srv.defaultIntf().link
    return (link.intf2 if link.intf1.node is srv else link.intf1).name


def start_stack(net, out_dir: Path, args, mitigate: bool, meta: dict, save_pcap: bool = True) -> list:
    """Web service on `srv`, optional pcap capture, and the tap -> monitor pipeline.

    Returns the processes to stop at teardown. Raises if anything exits early, so a scenario
    never runs with nothing captured.
    """
    srv = net.get("srv")
    # Flow rules need the controller; a ping round nudges MAC learning.
    net.pingAll(timeout="1")
    srv.cmd(f"{VENV_PY} {ROOT}/testbed/webapp.py --port 80 > {out_dir}/webapp.log 2>&1 &")
    if not net.get(PROBER_HOST).cmd(f"timeout 5 bash -c 'until curl -sf http://{SERVER_IP}/health; "
                                    f"do sleep 0.3; done' 2>/dev/null"):
        raise RuntimeError("web service did not become reachable")

    srv_if = server_capture_interface(srv)
    meta["capture_interface"] = srv_if
    procs, watched = [], []
    if save_pcap:
        cap = subprocess.Popen(["tcpdump", "-i", srv_if, "-n", "-s", "128", "-U",
                                "-w", str(out_dir / "capture.pcap")],
                               stdout=subprocess.DEVNULL, stderr=open(out_dir / "tcpdump.log", "w"))
        procs.append(cap)
        watched.append((cap, "tcpdump.log"))

    # The monitor runs in every scenario; in the normal-only ones (detect-only) it records
    # whether heavy *normal* load would have caused a false block.
    mon_cmd = [VENV_PY, str(ROOT / "traffic/monitor.py"),
               "--model", args.model, "--pcap", "/dev/stdin",
               "--events", str(out_dir / "detections.jsonl"),
               "--telemetry", str(out_dir / "telemetry.jsonl"),
               "--controller", f"http://127.0.0.1:{args.api_port}", "--token", "",
               "--whitelist", SERVER_IP, "--block-seconds", str(args.block_seconds),
               "--window", str(args.window), "--min-flows", str(args.min_flows),
               "--idle-timeout", str(args.idle_timeout)]
    if not mitigate:
        mon_cmd.append("--no-mitigate")
    tap = subprocess.Popen(["tcpdump", "-i", srv_if, "-n", "-s", "128", "-U", "-w", "-"],
                           stdout=subprocess.PIPE, stderr=open(out_dir / "tap.log", "w"))
    monitor = subprocess.Popen(mon_cmd, stdin=tap.stdout,
                               stdout=open(out_dir / "monitor.log", "w"), stderr=subprocess.STDOUT)
    tap.stdout.close()
    procs += [tap, monitor]
    watched += [(tap, "tap.log"), (monitor, "monitor.log")]
    time.sleep(2.0)  # let the model load before traffic starts
    for proc, log in watched:
        if proc.poll() is not None:
            raise RuntimeError(f"{log.split('.')[0]} exited early:\n{(out_dir / log).read_text()[-800:]}")
    return procs


def start_benign(net, out_dir: Path, hosts, rate, workers, duration, seed_base, suffix="") -> list:
    """Start the benign HTTP clients; returns their IPs. Logs go to client_<host><suffix>.jsonl."""
    ips = []
    for i, h in enumerate(hosts):
        host = net.get(h)
        ips.append(host.IP())
        host.cmd(f"python3 {ROOT}/testbed/client.py --server {SERVER_IP} "
                 f"--rate {rate} --workers {workers} "
                 f"--duration {duration} --name {h} --seed {seed_base + i + 1} "
                 f"--log {out_dir}/client_{h}{suffix}.jsonl > {out_dir}/client_{h}{suffix}.err 2>&1 &")
    return ips


def start_attack(net, out_dir: Path, hosts, kind, threads, duration, seed_base) -> list:
    """Start the flood generators on the attacker hosts; returns their IPs."""
    ips = []
    for j, h in enumerate(hosts):
        host = net.get(h)
        ips.append(host.IP())
        host.cmd(f"python3 {ROOT}/testbed/attack.py --type {kind} "
                 f"--target {SERVER_IP} --threads {threads} "
                 f"--duration {duration} --seed {seed_base + j + 7} "
                 f">> {out_dir}/attack_{h}.log 2>&1 &")
    return ips


def stop_procs(procs) -> None:
    for p in procs:
        if p.poll() is None:
            p.send_signal(signal.SIGINT)
    time.sleep(1.5)
    for p in procs:
        if p.poll() is None:
            p.kill()


def run_scenario(name, cfg, args, out_dir: Path, rep: int = 1):
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    controller = Controller(out_dir, args.of_port, args.api_port)
    net = None
    procs = []
    n_side = max(1, args.hosts // 2)
    meta = {"scenario": name, "repeat": rep, "config": cfg, "hosts": args.hosts, "duration": args.duration,
            "attacker_ips": [], "benign_ips": [], "server_ip": SERVER_IP, "attack_start": None,
            "run_id": time.time(), "t_start": time.time()}
    write_meta(out_dir, meta)
    set_current(out_dir, meta)
    try:
        # Everything below is torn down in `finally`, even if setup fails, so a crash
        # cannot leave an orphan controller holding the OpenFlow/API ports.
        controller.start()
        net = build_net(n_hosts=args.hosts, controller_port=args.of_port)
        net.start()
        procs += start_stack(net, out_dir, args, cfg["mitigate"], meta)

        meta["t_start"] = time.time()
        # Normal clients (known-good traffic).
        meta["benign_ips"] = start_benign(net, out_dir, BENIGN_HOSTS[:n_side], cfg["benign_rate"],
                                          cfg.get("benign_workers", 2), args.duration, rep * 100)
        write_meta(out_dir, meta)
        set_current(out_dir, meta)
        # Stop early if the normal clients did not start (their logs are the availability data).
        time.sleep(3)
        missing = [h for h in BENIGN_HOSTS[:n_side] if not (out_dir / f"client_{h}.jsonl").exists()]
        if missing:
            err = (out_dir / f"client_{missing[0]}.err").read_text()[-800:]
            raise RuntimeError(f"benign clients {missing} produced no log:\n{err}")
        # Attackers (known-bad traffic), started after a short warm-up.
        if cfg["attack"] is not None:
            time.sleep(max(0.0, args.attack_delay - 3))  # 3 s already spent on the client check
            meta["attack_start"] = time.time()
            meta["attacker_ips"] = start_attack(net, out_dir, ATTACKER_HOSTS[:n_side], cfg["attack"],
                                                args.attack_threads, args.duration - args.attack_delay,
                                                rep * 100)
            write_meta(out_dir, meta)

        time.sleep(args.duration + 2)
        meta["t_end"] = time.time()
        try:
            meta["final_status"] = controller.status()
        except Exception as exc:
            meta["final_status"] = {"error": str(exc)}
    finally:
        stop_procs(procs)
        if net is not None:
            net.stop()
        controller.stop()
        kill_stale()

    write_meta(out_dir, meta)
    set_current(out_dir, meta, finished=True)
    # Offline: pcap -> flows + prediction, for the confusion matrix.
    pcap = out_dir / "capture.pcap"
    if pcap.exists() and pcap.stat().st_size > 24:
        subprocess.run([VENV_PY, str(ROOT / "traffic/pcap_to_flows.py"), str(pcap),
                        "--out", str(out_dir / "flows.parquet"), "--model", args.model], check=False)
    else:
        print(f"[{name}] no packets captured on {meta.get('capture_interface')}; skipping flow conversion")
    print(f"[{name}] done -> {out_dir.relative_to(ROOT)}", flush=True)
    return meta


def add_stack_args(ap) -> None:
    """Options shared by the scripted experiment and the interactive live session."""
    ap.add_argument("--hosts", type=int, default=6)
    ap.add_argument("--attack-threads", type=int, default=8)
    ap.add_argument("--model", default=str(ROOT / "models/random_forest.joblib"))
    ap.add_argument("--of-port", type=int, default=6653)
    ap.add_argument("--api-port", type=int, default=8080)
    ap.add_argument("--block-seconds", type=int, default=20)
    ap.add_argument("--window", type=float, default=6.0)
    ap.add_argument("--min-flows", type=int, default=5)
    ap.add_argument("--idle-timeout", type=float, default=2.0)


def check_environment() -> None:
    if os.geteuid() != 0:
        sys.exit(f"must run as root (Mininet). Try: sudo python3 {sys.argv[0]}")
    for tool, path in [("osken-manager", OSKEN), (".venv python", VENV_PY)]:
        if not Path(path).exists():
            sys.exit(f"missing {tool} at {path}; see README setup")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", choices=list(SCENARIOS) + ["all"], default="all")
    ap.add_argument("--duration", type=float, default=40)
    ap.add_argument("--attack-delay", type=float, default=8, help="benign warm-up before attack starts")
    ap.add_argument("--repeat", type=int, default=1, help="run every scenario N times (interleaved)")
    ap.add_argument("--attack", choices=["udp", "conn", "http"], default="udp",
                    help="flood type of the two attack scenarios (testbed/attack.py --type)")
    ap.add_argument("--runs-dir", default=str(RUNS), help="where the runs are written (default results/runs)")
    add_stack_args(ap)
    args = ap.parse_args()
    if args.repeat < 1:
        ap.error("--repeat must be >= 1")
    check_environment()
    setLogLevel("warning")

    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    scenarios = {n: {**cfg, "attack": args.attack if cfg["attack"] else None} for n, cfg in SCENARIOS.items()}
    runs = (ROOT / args.runs_dir).resolve()  # a relative path is taken from the repo root
    runs.mkdir(parents=True, exist_ok=True)
    # Clear each chosen scenario once, so an earlier single run never mixes with new repeats.
    for name in names:
        if (runs / name).exists():
            shutil.rmtree(runs / name)
    total = len(names) * args.repeat
    est = total * (args.duration + 15) / 60
    print(f"running {len(names)} scenario(s) x {args.repeat} repetition(s) = {total} runs, ~{est:.0f} min", flush=True)

    summary = {"args": vars(args), "scenarios": {n: [] for n in names}}
    done = 0
    for rep in range(1, args.repeat + 1):  # interleaved: every scenario once per pass
        for name in names:
            done += 1
            print(f"[{done}/{total}] {name}" + (f" rep {rep}/{args.repeat}" if args.repeat > 1 else ""), flush=True)
            kill_stale()
            subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            out_dir = runs / name / f"rep{rep}" if args.repeat > 1 else runs / name
            summary["scenarios"][name].append(run_scenario(name, scenarios[name], args, out_dir, rep))
            time.sleep(2)
    out = ROOT / "results" / ("experiment_summary.json" if args.attack == "udp" else f"experiment_summary_{args.attack}.json")
    out.write_text(json.dumps(summary, indent=2, default=str))
    print(f"wrote {out}\nnow run:  {VENV_PY} ml/analyze_results.py --runs {runs} --out <report dir>")


if __name__ == "__main__":
    main()
