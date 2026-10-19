#!/usr/bin/env bash
# Stop everything this runtime started on the node (safe to run on any node, any time).
# "[t]cpdump": the bracket keeps the pattern from matching this command line itself.
sudo pkill -INT -f "[t]cpdump -i" 2>/dev/null || true
sleep 1
pkill -INT -f traffic/monitor.py 2>/dev/null || true
pkill -f testbed/attack.py 2>/dev/null || true
pkill -f testbed/client.py 2>/dev/null || true
if [ "${1:-}" = "all" ]; then
    pkill -INT -f osken-manager 2>/dev/null || true
    sudo pkill -f testbed/webapp.py 2>/dev/null || true
fi
sleep 0.5
echo stopped
