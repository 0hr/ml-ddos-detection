"""Simple Flask service protected by the testbed.

    /          small HTML page
    /api/items JSON with a little server-side work (?n=)
    /download  larger response (?kb=, default 64)
    /health    liveness probe used by the availability measurements
"""

import argparse
import hashlib
import logging
import random
import time

from flask import Flask, Response, jsonify, request

app = Flask(__name__)
STARTED = time.time()
PAGE = "<html><head><title>DDoS testbed</title></head><body><h1>Service OK</h1>{}</body></html>"


@app.get("/")
def index():
    return PAGE.format("<p>" + "lorem ipsum " * 40 + "</p>")


@app.get("/api/items")
def items():
    n = min(int(request.args.get("n", 20)), 500)
    rng = random.Random(n)
    data = [{"id": i, "value": rng.random(), "sha": hashlib.sha256(str(i).encode()).hexdigest()[:12]}
            for i in range(n)]
    return jsonify(items=data, count=n)


@app.get("/download")
def download():
    kb = min(int(request.args.get("kb", 64)), 2048)
    return Response(b"x" * (kb * 1024), mimetype="application/octet-stream")


@app.get("/health")
def health():
    return jsonify(status="ok", uptime_s=round(time.time() - STARTED, 1))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=80)
    args = ap.parse_args()
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
