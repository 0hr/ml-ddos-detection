"""Normal UDP request/response traffic for the data-collection run.

Without it every UDP flow in the collected data would be an attack, and a model could score
perfectly by looking at the protocol alone. This is a small DNS-style lookup service: a
client sends a short query and gets one reply.

    python3 simulation/udp_service.py server --port 9053
    python3 simulation/udp_service.py client --server 10.0.0.100 --rate 1 --duration 60 --log q.jsonl

A client reuses one socket (one source port, so one flow) for a few queries, then opens a
new one, like a stub resolver. Stdlib only, so it runs inside Mininet hosts.
"""

import argparse
import hashlib
import json
import random
import socket
import time

MAX_REPLY = 512


def serve(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    while True:
        data, addr = sock.recvfrom(2048)
        # The reply size depends on the query, like records of different lengths.
        digest = hashlib.sha256(data).digest()
        size = 60 + digest[0] % (MAX_REPLY - 60)
        sock.sendto((digest * (size // len(digest) + 1))[:size], addr)


def query_loop(args) -> None:
    rng = random.Random(args.seed)
    stop_at = time.time() + args.duration
    sock, left = None, 0
    with open(args.log, "a") as out:
        while time.time() < stop_at:
            time.sleep(min(rng.expovariate(args.rate), max(stop_at - time.time(), 0)))
            if time.time() >= stop_at:
                break
            if left == 0:  # a new "resolver session": new socket, new source port, new flow
                if sock:
                    sock.close()
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(args.timeout)
                left = rng.randint(1, 6)
            name = f"host{rng.randint(1, 500)}.svc{rng.randint(1, 40)}.lab"
            t0 = time.time()
            rec = {"ts": t0, "client": args.name, "kind": "udp-query"}
            try:
                sock.sendto(name.encode(), (args.server, args.port))
                reply, _ = sock.recvfrom(2048)
                rec.update(ok=True, reply_bytes=len(reply))
            except OSError as exc:
                rec.update(ok=False, error=type(exc).__name__)
            rec["latency_ms"] = round((time.time() - t0) * 1000, 2)
            out.write(json.dumps(rec) + "\n")
            out.flush()
            left -= 1
    if sock:
        sock.close()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("server")
    s.add_argument("--port", type=int, default=9053)
    c = sub.add_parser("client")
    c.add_argument("--server", required=True)
    c.add_argument("--port", type=int, default=9053)
    c.add_argument("--rate", type=float, default=1.0, help="queries per second (Poisson)")
    c.add_argument("--duration", type=float, default=60)
    c.add_argument("--timeout", type=float, default=1.0)
    c.add_argument("--name", default="client")
    c.add_argument("--seed", type=int, default=1)
    c.add_argument("--log", required=True)
    args = ap.parse_args()
    if args.mode == "server":
        serve(args.port)
    else:
        query_loop(args)


if __name__ == "__main__":
    main()
