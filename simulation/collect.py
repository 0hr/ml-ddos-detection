"""Collect a labelled flow dataset from the Mininet campus network (MUST run as root).

Builds the network in simulation/topology.py, starts the controller in forwarding-only mode
(no drop rules: here we record the attacks, not stop them), the web service and the UDP
lookup service on `srv`, then runs every session in simulation/plan.py. Each session is
captured on the server's switch port into its own pcap and turned into flow features with
the same flow meter the models use.

    sudo python3 simulation/collect.py                 # default plan: 3 repetitions, ~20 min
    sudo python3 simulation/collect.py --quick         # 1 repetition, 30 s sessions, ~5 min
    sudo python3 simulation/collect.py --reps 5 --attacks udp http
    python3 simulation/collect.py --list               # show the plan and topology, no root needed

Output (default simulation/data/<timestamp>/):
  collection.json                topology, plan and settings
  sessions/<id>/capture.pcap     the captured packets  (--no-pcap deletes them after conversion)
  sessions/<id>/flows.parquet    flow features of that session
  sessions/<id>/session.json     what ran, when, which hosts were attackers, client success rates
  dataset.parquet                every session's flows, labelled and cleaned (simulation/build_dataset.py)
simulation/data/latest.json points at the newest collection.

All traffic stays inside the emulated network and targets only its own server.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

import plan as P
import topology as T

UDP_PORT = 9053
SNAPLEN = 128  # headers only: enough for every flow feature, keeps pcaps small


def sh(host, cmd: str) -> str:
    return host.cmd(cmd)


def stop_traffic() -> None:
    """End every client and flood generator; the servers keep running. Mininet hosts share
    the root PID namespace, so one pkill reaches every host's processes."""
    for pattern in ("[t]estbed/client.py", "[t]estbed/attack.py", "[u]dp_service.py client"):
        subprocess.run(["pkill", "-f", pattern], check=False)


def start_session(net, sess: P.Session, hosts, out: Path) -> dict:
    """Start the normal clients now and schedule the attack; returns what was started."""
    clients = [h for h in hosts if h.role == "client"]
    attackers = [h for h in hosts if h.role == "attacker"]
    n_udp = round(len(clients) * sess.udp_share)
    started = {"clients": [], "udp_clients": [], "attackers": []}
    for i, h in enumerate(clients):
        profile = sess.profiles[i % len(sess.profiles)]
        sh(net.get(h.name),
           f"python3 {ROOT}/testbed/client.py --server {T.SERVER_IP} --rate {sess.benign_rate} "
           f"--workers {sess.benign_workers} --profile {profile} --duration {sess.duration} "
           f"--name {h.name} --seed {sess.seed * 100 + i} --log {out}/client_{h.name}.jsonl "
           f"> {out}/client_{h.name}.err 2>&1 &")
        started["clients"].append({"host": h.name, "ip": h.ip, "profile": profile})
        if sess.udp_rate and i < n_udp:
            sh(net.get(h.name),
               f"python3 {HERE}/udp_service.py client --server {T.SERVER_IP} --port {UDP_PORT} "
               f"--rate {sess.udp_rate} --duration {sess.duration} --name {h.name} "
               f"--seed {sess.seed * 100 + 50 + i} --log {out}/udp_{h.name}.jsonl > /dev/null 2>&1 &")
            started["udp_clients"].append(h.name)
    started["attacker_hosts"] = [{"host": h.name, "ip": h.ip} for h in attackers]
    return started


def start_attack(net, sess: P.Session, hosts, out: Path) -> list[str]:
    ips = []
    for j, h in enumerate(h for h in hosts if h.role == "attacker"):
        pool = f"--dport-pool {sess.attack_dport_pool} " if sess.attack == "udp" else ""
        sh(net.get(h.name),
           f"python3 {ROOT}/testbed/attack.py --type {sess.attack} --target {T.SERVER_IP} "
           f"--threads {sess.attack_threads} {pool}--duration {sess.attack_duration} "
           f"--seed {sess.seed * 10 + j} >> {out}/attack_{h.name}.log 2>&1 &")
        ips.append(h.ip)
    return ips


def success_rates(out: Path) -> dict:
    """Share of normal requests that succeeded, per traffic kind (context for the session)."""
    rates = {}
    for kind, pattern in (("http", "client_*.jsonl"), ("udp", "udp_*.jsonl")):
        ok = total = 0
        for p in out.glob(pattern):
            for line in p.read_text().splitlines():
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                total += 1
                ok += bool(rec.get("ok"))
        rates[kind] = {"requests": total, "ok_share": round(ok / total, 4) if total else None}
    return rates


def run_session(net, sess: P.Session, hosts, cap_if: str, out: Path, venv_py: str, keep_pcap: bool) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    pcap = out / "capture.pcap"
    cap = subprocess.Popen(["tcpdump", "-i", cap_if, "-n", "-s", str(SNAPLEN), "-U", "-w", str(pcap)],
                           stdout=subprocess.DEVNULL, stderr=open(out / "tcpdump.log", "w"))
    time.sleep(1.0)
    meta = {**sess.as_dict(), "capture_interface": cap_if, "server_ip": T.SERVER_IP,
            "t_start": time.time(), "attack_start": None, "attacker_ips": []}
    meta.update(start_session(net, sess, hosts, out))
    if sess.attack:
        time.sleep(sess.attack_delay)
        meta["attack_start"] = time.time()
        meta["attacker_ips"] = start_attack(net, sess, hosts, out)
        time.sleep(max(0.0, sess.duration - sess.attack_delay))
    else:
        time.sleep(sess.duration)
    stop_traffic()
    time.sleep(2.0)  # let the last replies and FINs reach the capture
    cap.send_signal(2)
    cap.wait(timeout=10)
    meta["t_end"] = time.time()
    meta["requests"] = success_rates(out)

    # pcap -> flow features (the project venv has pandas; Mininet's python3 may not)
    r = subprocess.run([venv_py, str(ROOT / "traffic/pcap_to_flows.py"), str(pcap), "--out", str(out / "flows.parquet")],
                       capture_output=True, text=True)
    meta["conversion"] = (r.stderr.strip().splitlines() or [""])[0]
    if r.returncode != 0:
        meta["conversion_error"] = r.stderr[-2000:]
    meta["pcap_bytes"] = pcap.stat().st_size if pcap.exists() else 0
    if not keep_pcap and pcap.exists():
        pcap.unlink()
    (out / "session.json").write_text(json.dumps(meta, indent=2))
    return meta


def chown_to_invoking_user(path: Path) -> None:
    """Files written as root would not be editable by the user who ran sudo."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and gid:
        subprocess.run(["chown", "-R", f"{uid}:{gid}", str(path)], check=False)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reps", type=int, default=3, help="repetitions of the session set (intensity steps up)")
    ap.add_argument("--attacks", nargs="+", default=["udp", "conn", "http"], choices=sorted(P.ATTACK_LABELS))
    ap.add_argument("--quick", action="store_true", help="1 repetition, 30 s sessions")
    ap.add_argument("--benign-seconds", type=float, default=60)
    ap.add_argument("--attack-seconds", type=float, default=45)
    ap.add_argument("--access", type=int, default=3, help="access switches")
    ap.add_argument("--hosts-per-access", type=int, default=4)
    ap.add_argument("--attackers-per-access", type=int, default=1)
    ap.add_argument("--server-mbit", type=float, default=20, help="bandwidth of the server link")
    ap.add_argument("--out", help="output directory (default simulation/data/<timestamp>)")
    ap.add_argument("--no-pcap", action="store_true", help="delete each pcap once it is converted")
    ap.add_argument("--of-port", type=int, default=6653)
    ap.add_argument("--api-port", type=int, default=8080)
    ap.add_argument("--list", action="store_true", help="print the plan and topology and exit")
    args = ap.parse_args()

    reps = 1 if args.quick else args.reps
    sessions = P.make_plan(reps, tuple(args.attacks), args.quick, args.benign_seconds, args.attack_seconds)
    hosts = T.host_plan(args.access, args.hosts_per_access, args.attackers_per_access)
    if args.list:
        print("topology\n" + T.describe(hosts) + "\n\nplan\n" + P.describe(sessions))
        return

    if os.geteuid() != 0:
        sys.exit("must run as root (Mininet): sudo python3 simulation/collect.py   (--list works without root)")
    from mininet.log import setLogLevel

    from testbed.run_experiment import VENV_PY, Controller, check_environment, kill_stale

    check_environment()
    setLogLevel("warning")
    out = Path(args.out) if args.out else HERE / "data" / time.strftime("%Y%m%d-%H%M%S")
    if out.exists() and any(out.iterdir()):
        sys.exit(f"{out} is not empty; choose another --out")
    out.mkdir(parents=True, exist_ok=True)
    collection = {"created": time.time(), "topology": [h.__dict__ for h in hosts], "server_ip": T.SERVER_IP,
                  "server_mbit": args.server_mbit, "snaplen": SNAPLEN, "udp_service_port": UDP_PORT,
                  "plan": [s.as_dict() for s in sessions], "argv": sys.argv[1:]}
    (out / "collection.json").write_text(json.dumps(collection, indent=2))
    print(f"collecting into {out}\ntopology\n{T.describe(hosts)}\n\nplan\n{P.describe(sessions)}\n", flush=True)

    kill_stale()
    subprocess.run(["pkill", "-f", "[u]dp_service.py"], check=False)
    subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    controller = Controller(out, args.of_port, args.api_port, mitigation=False)
    net = None
    t0 = time.time()
    try:
        controller.start()
        net = T.build_net(hosts, controller_port=args.of_port, server_bw=args.server_mbit)
        net.start()
        net.pingAll(timeout="1")
        srv = net.get("srv")
        sh(srv, f"{VENV_PY} {ROOT}/testbed/webapp.py --port 80 > {out}/webapp.log 2>&1 &")
        sh(srv, f"python3 {HERE}/udp_service.py server --port {UDP_PORT} > {out}/udp_server.log 2>&1 &")
        probe = net.get(next(h.name for h in hosts if h.role == "client"))
        if not sh(probe, f"timeout 8 bash -c 'until curl -sf http://{T.SERVER_IP}/health; do sleep 0.3; done'"):
            raise RuntimeError("web service did not become reachable")
        link = srv.defaultIntf().link
        cap_if = (link.intf2 if link.intf1.node is srv else link.intf1).name

        for n, sess in enumerate(sessions, start=1):
            print(f"[{n}/{len(sessions)}] {sess.id} ({sess.duration:.0f} s, label {sess.label}) ...", flush=True)
            meta = run_session(net, sess, hosts, cap_if, out / "sessions" / sess.id, VENV_PY, not args.no_pcap)
            req = meta["requests"]["http"]
            ok = f"{req['ok_share']:.0%}" if req["ok_share"] is not None else "-"
            print(f"      {meta['conversion'] or 'no flows'} · legitimate HTTP ok {ok} of {req['requests']}"
                  + (f" · ERROR {meta['conversion_error'][-200:]}" if "conversion_error" in meta else ""), flush=True)
    finally:
        stop_traffic()
        if net is not None:
            net.stop()
        controller.stop()
        kill_stale()
        subprocess.run(["pkill", "-f", "[u]dp_service.py"], check=False)
        chown_to_invoking_user(out)

    print(f"\ntraffic done in {(time.time() - t0) / 60:.1f} min; building the dataset ...", flush=True)
    subprocess.run([VENV_PY, str(HERE / "build_dataset.py"), str(out)], check=False)
    (HERE / "data" / "latest.json").write_text(json.dumps({"collection": str(out)}))
    chown_to_invoking_user(HERE / "data")
    print(f"\nnext:  uv run python simulation/compare.py --sim {out / 'dataset.parquet'}")


if __name__ == "__main__":
    main()
