# CS-558 - Advanced Cybersecurity
## AI-Based DDoS Detection and Mitigation

This project trains a machine learning model to spot DDoS attacks from network
traffic, then tests it live inside a small virtual network (Mininet). When the
model sees an attack, the SDN controller installs a temporary drop rule on the
switch to block that source. The same feature code is used for training and for
live traffic, so the model sees the same numbers in both places.

```
 CIC-DDoS2019 zip -> prepare -> clean -> train -> models/*.joblib
                                                      |
 Mininet traffic -> tcpdump -> flow meter -> model -> controller -> switch drops it
```

## How it fits together

| Path | What it does |
|---|---|
| `ddos/features.py` | the list of features, shared by training and live traffic |
| `ddos/pcapio.py` | reads pcap files, parses IPv4/TCP/UDP (no extra libraries) |
| `ddos/flowmeter.py` | turns packets into flows, like CICFlowMeter |
| `ddos/model_io.py` | saves and loads a model together with its feature list |
| `ml/prepare_data.py` | samples the 22 GB dataset zip into a smaller balanced file |
| `ml/clean.py` | cleans the data, handles NaN/inf, writes a report |
| `ml/train.py` | trains the Decision Tree and Random Forest, writes results |
| `ml/analyze_results.py` | builds the final comparison from the testbed runs |
| `ml/report.py` | charts and tables of the models (F1, accuracy, ROC/PR, confusion) |
| `traffic/monitor.py` | live: packets -> flows -> model -> block requests |
| `traffic/pcap_to_flows.py` | offline: pcap -> flow features (+ predictions) |
| `controller/ddos_controller.py` | OpenFlow controller: forwarding + block rules |
| `testbed/topology.py` | the Mininet network (2 switches, server + hosts) |
| `testbed/webapp.py` | the small Flask server we protect |
| `testbed/client.py` | normal client traffic |
| `testbed/attack.py` | flood traffic for the testbed only, private targets only |
| `testbed/run_experiment.py` | runs all four test scenarios |
| `testbed/live.py` | keeps the testbed up so you start attacks by hand |
| `simulation/` | collect our own dataset in Mininet and compare it with CIC-DDoS2019 — see [`simulation/README.md`](simulation/README.md) |
| `fabric/` | deploy the system on a FABRIC slice — see [`fabric/README.md`](fabric/README.md) |
| `monitor/` | live React dashboard (topology, traffic, mitigation) — see [`monitor/README.md`](monitor/README.md) |

## Setup

Two virtualenvs are needed. The ML code runs on Python 3.14, but the controller
(os-ken) needs Python 3.12.

```bash
make setup          # uv sync + a second venv with os-ken
```

You also need `mininet`, `openvswitch` (running), and `tcpdump` installed. Put the
dataset at `dataset/raw/CSV-01-12.zip`.

## 1. Data and training (no root)

```bash
make data           # sample the dataset
make clean-data     # clean it + write results/data/eda_report.md
make train          # train the models -> models/*.joblib
make test           # flow-meter unit tests
```

`ml/train.py` writes `results/ml/report.md`: per-split metrics, confusion
matrices, ROC/PR curves, per-attack detection rates, and the false positives.

### Why 43 features

The CSV files have 88 columns. We keep only the ones our own flow meter can also
measure, so training and live traffic match. IPs, ports, and timestamps are kept
for inspection but never given to the model: in CIC-DDoS2019 the victim is always
the same host, so a model that saw IPs would cheat and would not work in the
testbed. We also drop CICFlowMeter's unreliable flag counters (a SYN flood is
logged with `SYN Flag Count = 0`), constant columns, duplicate `Subflow*` columns,
and the `Active/Idle` columns (they depend on CICFlowMeter's internal timeout).
The feature list is hashed into each saved model, and loading refuses a model
whose list does not match.

## 2. Live testbed (needs root)

```bash
make experiment     # run all four scenarios, ~3-4 min
make analyze        # -> results/report/summary.md + graphs
```

Each scenario starts the controller, builds the network, runs the Flask server,
captures a pcap, runs the monitor, drives traffic, and tears down:

| scenario | traffic | mitigation | purpose |
|---|---|---|---|
| `normal` | normal, low rate | - | baseline |
| `highload` | normal, high rate | - | check heavy *normal* load is not blocked |
| `attack_nomit` | normal + flood | detect only | service hurt, no blocking |
| `attack_mit` | normal + flood | block | service kept up by blocking |

### Watching it live

```bash
make live              # terminal 1 (root): testbed up, normal clients, no attack yet
make dashboard-live    # terminal 2: http://127.0.0.1:8099
```

From the dashboard you start and stop an attack, start a flash crowd, turn
mitigation on or off, and block a host by hand. It shows each step and how long it
took: attack -> flagged by the model -> block requested -> rule on the switch ->
traffic dropped.

### How blocking works

The monitor scores flows and asks the controller to block a source IP when either:
5 or more of its flows in the last 6 seconds look like an attack and they are at
least 80% of its flows, or the source sends more than 100 flows per second (a flood
of many normal-looking connections). The controller then installs a drop rule for
that IP with a timeout, so the block is temporary and clears itself. The server is
never blocked, and the number of blocks at once is capped. Turning mitigation off
(`POST /mitigation {"enabled": false}`) puts it in detect-only mode without a
restart.
