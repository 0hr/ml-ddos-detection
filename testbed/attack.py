"""High-volume traffic generator for the isolated Mininet testbed only.

This is the attack-side traffic we use to test detection and mitigation. It uses ONLY
ordinary OS sockets (no raw sockets, no packet forging). The goal is the high packet/flow
rate and many short flows of a volumetric flood, so the flow meter and model see realistic
attack-shaped features.

    udp    UDP flood  - send fixed-size datagrams to random destination ports
    conn   TCP connect flood - open and close many short connections
    http   HTTP GET flood - many concurrent requests to the web service

Safety: traffic goes only to --target, which must be a private address, and the run stops
after --duration seconds (hard cap). Run it inside a Mininet host on an isolated virtual
network; never point it at machines you do not own.

    python3 testbed/attack.py --type udp --target 10.0.0.100 --duration 30
"""

import argparse
import ipaddress
import random
import socket
import threading
import time
import urllib.request

PAYLOAD = b"x" * 512
DPORT_POOL = 16  # destination ports per thread (set from --dport-pool)


def _udp_flood(stop_at, target, port, rng, counter, idx):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # A fixed pool of destination ports per thread: still a multi-port flood, but each
    # (src, sport, dst, dport) repeats fast, so it forms real flows on the wire. (A new
    # random port per packet would make every packet its own one-packet "flow".)
    pool = [port] if port else [rng.randint(1024, 65535) for _ in range(DPORT_POOL)]
    n = 0
    while time.time() < stop_at:
        try:
            sock.sendto(PAYLOAD, (target, pool[n % len(pool)]))
            n += 1
        except OSError:
            time.sleep(0.001)
    counter[idx] = n


def _conn_flood(stop_at, target, port, rng, counter, idx):
    n = 0
    while time.time() < stop_at:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
        s.settimeout(0.5)
        try:
            s.connect((target, port))
        except OSError:
            pass
        finally:
            s.close()
            n += 1
    counter[idx] = n


def _http_flood(stop_at, target, port, rng, counter, idx):
    url = f"http://{target}:{port}/"
    n = 0
    while time.time() < stop_at:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as r:
                r.read(64)
        except Exception:
            pass
        n += 1
    counter[idx] = n


WORKERS = {"udp": _udp_flood, "conn": _conn_flood, "http": _http_flood}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--type", choices=WORKERS, required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--port", type=int, default=0, help="target port; 0 = random pool (udp only)")
    ap.add_argument("--dport-pool", type=int, default=16, help="udp: destination ports per thread")
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--duration", type=float, default=30)
    ap.add_argument("--max-duration", type=float, default=300, help="hard safety cap")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    global DPORT_POOL
    DPORT_POOL = max(1, args.dport_pool)

    ip = ipaddress.ip_address(args.target)
    if not ip.is_private:
        ap.error(f"refusing to target non-private address {args.target}")
    duration = min(args.duration, args.max_duration)
    if args.type != "udp" and args.port == 0:
        args.port = 80

    stop_at = time.time() + duration
    counter = [0] * args.threads
    fn = WORKERS[args.type]
    threads = [
        threading.Thread(target=fn, args=(stop_at, args.target, args.port,
                                          random.Random(args.seed * 100 + i), counter, i))
        for i in range(args.threads)
    ]
    t0 = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - t0
    total = sum(counter)
    print(f"{args.type} flood -> {args.target}:{args.port or 'rand'}  "
          f"{total:,} ops in {elapsed:.1f}s ({total / elapsed:,.0f}/s) across {args.threads} threads")


if __name__ == "__main__":
    main()
