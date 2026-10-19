"""Normal HTTP client: Poisson request timing, logs every request as JSON lines.

Used for both the "normal" and "high load" (flash crowd) scenarios; only --rate and
--workers differ. --profile sets what a client asks for (the data-collection run mixes
them so normal traffic is not all alike). Stdlib only, so it runs inside Mininet hosts as
root.

    python3 testbed/client.py --server 10.0.0.100 --rate 2 --workers 2 --duration 60 --log h2.jsonl
"""

import argparse
import json
import random
import threading
import time
import urllib.error
import urllib.request

PROFILES = {
    # (path, weight). "browse" is the default and what the experiment scenarios use.
    "browse": [("/", 0.4), ("/api/items?n=50", 0.3), ("/health", 0.2), ("/download?kb=64", 0.1)],
    "api": [("/api/items?n=20", 0.5), ("/api/items?n=200", 0.3), ("/health", 0.2)],
    "download": [("/download?kb=256", 0.5), ("/download?kb=1024", 0.2), ("/", 0.3)],
    "monitor": [("/health", 1.0)],  # a health checker: tiny, regular requests
}
PATHS = PROFILES["browse"]


def worker(args, stop_at: float, rng: random.Random, out, lock: threading.Lock) -> None:
    paths, weights = zip(*PROFILES[args.profile])
    while True:
        now = time.time()
        if now >= stop_at:
            return
        time.sleep(min(rng.expovariate(args.rate), max(stop_at - now, 0)))
        if time.time() >= stop_at:
            return
        path = rng.choices(paths, weights)[0]
        t0 = time.time()
        rec = {"ts": t0, "client": args.name, "profile": args.profile, "path": path}
        try:
            with urllib.request.urlopen(f"http://{args.server}:{args.port}{path}", timeout=args.timeout) as r:
                r.read()
                rec.update(ok=200 <= r.status < 400, status=r.status)
        except urllib.error.HTTPError as exc:
            rec.update(ok=False, status=exc.code, error="http")
        except Exception as exc:  # timeouts, refused connections, resets
            rec.update(ok=False, status=0, error=type(exc).__name__)
        rec["latency_ms"] = round((time.time() - t0) * 1000, 2)
        with lock:
            out.write(json.dumps(rec) + "\n")
            out.flush()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--server", default="10.0.0.100")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--rate", type=float, default=2.0, help="requests/s per worker (Poisson)")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--profile", choices=sorted(PROFILES), default="browse", help="what the client requests")
    ap.add_argument("--duration", type=float, default=60)
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--name", default="client")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--log", required=True)
    args = ap.parse_args()

    stop_at = time.time() + args.duration
    lock = threading.Lock()
    with open(args.log, "a") as out:
        threads = [
            threading.Thread(target=worker, args=(args, stop_at, random.Random(args.seed * 1000 + i), out, lock))
            for i in range(args.workers)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()


if __name__ == "__main__":
    main()
