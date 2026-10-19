#!/usr/bin/env bash
# Start the OpenFlow controller + mitigation API (loopback :8080) for one run.
#   start_controller.sh <run_dir> <mitigation 1|0> [block renewal 1|0]
set -euo pipefail
cd "$(dirname "$0")/.."
run="$1"; mkdir -p "$run"
pkill -f osken-manager 2>/dev/null || true
sleep 0.5
DDOS_CTRL_LOG="$run/controller_events.jsonl" DDOS_MITIGATION="$2" DDOS_RENEW="${3:-1}" \
DDOS_STATIC_ROUTES="$PWD/routes.json" DDOS_WHITELIST="$(cat server_ip)" PYTHONUNBUFFERED=1 \
    setsid nohup venv-controller/bin/osken-manager --ofp-tcp-listen-port 6653 controller/ddos_controller.py \
    > "$run/controller.log" 2>&1 < /dev/null &
for _ in $(seq 40); do
    if curl -sf http://127.0.0.1:8080/status | grep -q '"switches": \[1'; then
        echo "controller up, switch connected"; exit 0
    fi
    sleep 0.5
done
echo "controller did not come up or the switch did not connect:" >&2
tail -n 20 "$run/controller.log" >&2
exit 1
