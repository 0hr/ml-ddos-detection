#!/usr/bin/env bash
# Server / client / attacker nodes: the traffic scripts only need the standard library,
# the web service needs Flask.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y -qq python3-flask curl iproute2 >/dev/null
python3 -c "import flask, sys; print('host ok: python', sys.version.split()[0], 'flask', flask.__version__)"
