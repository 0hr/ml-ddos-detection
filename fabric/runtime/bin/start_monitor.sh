#!/usr/bin/env bash
# Tap the server link and run the detector: tcpdump -> flow meter -> model -> /block.
#   start_monitor.sh <run_dir> <tap_dev> <block_seconds> <window> <min_flows>
set -euo pipefail
cd "$(dirname "$0")/.."
run="$1"; dev="$2"; mkdir -p "$run"
sudo pkill -f "[t]cpdump -i $dev" 2>/dev/null || true
pkill -f traffic/monitor.py 2>/dev/null || true
setsid nohup bash -c "sudo tcpdump -i $dev -n -s 128 -U -w - 2>'$run/tap.log' | \
    venv-monitor/bin/python traffic/monitor.py --pcap /dev/stdin \
        --events '$run/detections.jsonl' --telemetry '$run/telemetry.jsonl' \
        --controller http://127.0.0.1:8080 --whitelist $(cat server_ip) \
        --block-seconds $3 --window $4 --min-flows $5 --idle-timeout 2" \
    > "$run/monitor.log" 2>&1 < /dev/null &
for _ in $(seq 40); do
    grep -q "^loaded " "$run/monitor.log" 2>/dev/null && { echo "monitor up on $dev"; exit 0; }
    sleep 0.5
done
echo "monitor did not start:" >&2; tail -n 20 "$run/monitor.log" >&2; exit 1
