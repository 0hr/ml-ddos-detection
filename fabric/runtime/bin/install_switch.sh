#!/usr/bin/env bash
# Switch node: Open vSwitch, capture tools and the two Python environments.
set -euo pipefail
cd "$(dirname "$0")/.."
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y -qq openvswitch-switch tcpdump ethtool python3-venv curl >/dev/null
sudo systemctl enable --now openvswitch-switch >/dev/null 2>&1 || true
[ -x venv-monitor/bin/python ] || python3 -m venv venv-monitor
venv-monitor/bin/pip install -q --upgrade pip
venv-monitor/bin/pip install -q -r requirements-monitor.txt
[ -x venv-controller/bin/python ] || python3 -m venv venv-controller
venv-controller/bin/pip install -q --upgrade pip
venv-controller/bin/pip install -q -r requirements-controller.txt
venv-monitor/bin/python - <<'PY'
import sys
sys.path.insert(0, ".")
from ddos.model_io import load_bundle
b = load_bundle("models/random_forest.joblib")
print(f"model ok: {b.name}, {len(b.features)} features, threshold {b.threshold}, python {sys.version.split()[0]}")
PY
venv-controller/bin/osken-manager --version 2>&1 | tail -1
