# Own dataset: collect, train, compare with CIC-DDoS2019

This folder builds a labelled flow dataset from traffic generated in a Mininet network,
trains the project's Random Forest on it, and compares it with CIC-DDoS2019 in both
directions. Flow features come from the same flow meter the models use, so the two
datasets have identical columns and can be mixed or swapped.

```bash
sudo python3 simulation/collect.py          # ~20 min: 18 sessions, labelled dataset at the end
uv run python simulation/compare.py         # ~1 min: figures + tables in simulation/results/
```

`make collect` and `make compare` do the same. Try `sudo python3 simulation/collect.py --quick`
(about 5 minutes) first to check that everything runs on your machine.

## Network

```
                         controller (OpenFlow 1.3, forwarding only)
                                 |
                              s1 core
              /            /           \             \
          s3 access    s4 access    s5 access       s2 data centre
         /  |  |  \     ...           ...              |
       h1  h2  h3  h4                                 srv  10.0.0.100
       c   c   c   a                                  web :80 · UDP lookup :9053
```

- **12 hosts on 3 access switches.** Each switch has 3 legitimate clients and 1 attacker,
  so attack and legitimate flows share the same paths and queues.
- **Bandwidth.** Hosts have 10 Mbit/s links, uplinks 100 Mbit/s, and the server link
  20 Mbit/s, so a flood congests the server link. That congestion changes the legitimate
  flows too (retransmissions, slow replies), and those flows are part of the data.
- **Capture point.** Every session is captured on the data-centre switch port toward the
  server, which every flow to the server crosses.
- **No drop rules.** The controller only forwards, so each attack is recorded in full.
- **Configurable.** `--access`, `--hosts-per-access`, `--attackers-per-access` and
  `--server-mbit` change the network.

## What is collected

Each repetition runs six sessions, and each session is captured into its own pcap.

| Session | Legitimate traffic | Attack |
|---|---|---|
| `benign_quiet` | light browsing and health checks, a few UDP lookups | — |
| `benign_mixed` | browsing, API calls, downloads, health checks, UDP lookups | — |
| `benign_busy` | heavy browsing, API calls and downloads (flash crowd) | — |
| `attack_udp` | mixed, as above | UDP flood from h4, h8, h12 |
| `attack_conn` | mixed | TCP connect flood (short complete connections) |
| `attack_http` | mixed | HTTP request flood |

- **Intensity steps up with each repetition.** Attack threads go 2 → 4 → 8, the UDP
  flood's destination-port pool 4 → 16 → 64, and legitimate request rates rise ×1 → ×1.5 → ×2.
  The dataset therefore never holds just one traffic level per class.
- **Attack timing.** An attack starts 10 s into its session (legitimate traffic only
  before that) and stops 5 s before the end.
- **See the full plan.** `python3 simulation/collect.py --list` prints every session
  without running anything.

The traffic sources are the project's existing tools: `testbed/client.py` (legitimate
HTTP clients, with `--profile browse|api|download|monitor`), `testbed/attack.py` (the
three flood types, ordinary sockets only, private target, capped duration), and
`simulation/udp_service.py`.

`udp_service.py` is a small DNS-style lookup service. It exists because otherwise every
UDP flow in the data would be an attack, and a model could score perfectly by looking
only at the protocol. The preview below shows that happening.

### Labels

Labels come from the session design, not from inspecting packets.

- **Attacker hosts send only their flood.** In an attack session, every flow an attacker
  host starts gets that session's label: `Sim-UDP-flood`, `Sim-TCP-connect-flood` or
  `Sim-HTTP-flood`.
- **Everything else is `BENIGN`.** That covers legitimate clients, flows the server starts,
  and attacker hosts in the benign sessions.

Cleaning is the same as for CIC-DDoS2019 (`ml/clean.py`): rows with non-finite features
are dropped, and duplicate (features, label) rows are removed.

### In-progress snapshots

The live monitor does not wait for a flow to end; it scores flows while they are still
running. A dataset of finished flows only teaches a model what a 30-second flood flow
looks like at the end, and such a model cannot recognise the same flow 2 seconds in. With
finished flows only, the model trained on our data needed about 20 s to flag a UDP flood.

So `build_dataset.py` replays each session's capture and also records every flow still
running at 1, 2, 5 and 10 s, as it looked then, with the same label (column `snapshot_s`;
0 = the finished flow). Benign flows get snapshots too, so a snapshot says nothing about
the class.

- **Training only.** Snapshots are used for training and threshold tuning. Every score
  is computed on finished flows, the same unit CIC-DDoS2019 is made of.
- **Turning it off.** `--snapshots ""` builds a finished-flows-only dataset. `compare.py`
  trains that variant as well, so the effect is shown.
- **Rebuilding.** Run `uv run python simulation/build_dataset.py simulation/data/<collection>`
  to rebuild an existing collection without collecting again (the captures must still be there).

### Output

```
simulation/data/<timestamp>/
  collection.json               topology, plan, settings
  sessions/<id>/capture.pcap    the packets (headers only, 128 bytes per packet; --no-pcap deletes them)
  sessions/<id>/flows.parquet   flow features of that session
  sessions/<id>/session.json    what ran, when, which hosts attacked, legitimate request success rates
  dataset.parquet               all sessions, labelled and cleaned: 43 features + Label + session info
                                + in-progress snapshots (snapshot_s > 0)
  dataset_summary.md / .json    flows per label, per protocol, per session
simulation/data/latest.json     the newest collection (what compare.py uses by default)
```

`simulation/data/` is not tracked by git; it can grow to a few hundred MB with the pcaps.

## The comparison (`compare.py`)

Every model is the project's Random Forest with the same settings as `ml/train.py`. Each
model's threshold is tuned on validation data from its own training set.

| Train on | Test on | Question |
|---|---|---|
| CIC-DDoS2019 | CIC-DDoS2019 | baseline (the saved model, the same test split as `ml/train.py`) |
| CIC-DDoS2019 | simulated | does the public-dataset model recognise our traffic? |
| simulated | simulated | can our own data train a detector? |
| simulated | CIC-DDoS2019 | does a model trained on our data recognise the public attacks? |
| both | each | does adding our data help, or hurt? |
| simulated, finished flows only | each | what do the in-progress snapshots change? |

**Detection time.** Flow scores say how well a model classifies finished flows; they don't
say how fast the live system reacts. `compare.py` therefore replays every held-out
session's capture through the monitor's own code (`traffic/monitor.py`: same flow meter,
scoring and per-source vote) with each of the four models. For every attacker it records
the time from launching the attack to the first block decision, and it counts any decision
against a legitimate host as a false block.

- **Model rule only.** The flow-rate rule is switched off here, so the models are
  compared on their own. Live, that rule also blocks the TCP connect and HTTP floods
  within about 3 s, whatever the model.
- **Run time.** The replay takes about a minute on 16 cores. `--no-replay` skips it.

**How the simulated data is split.** Flows from one session are near-copies of each
other, so a random split would place near-duplicates on both sides and overstate accuracy.
`compare.py` therefore splits by session.

- **Several repetitions:** the last repetition, which is also the most intense, is the test set.
- **One repetition** (`--quick`): each session's last 30 % of flows are the test set.

**How different the datasets are.** A classifier is also trained to tell which dataset a
flow came from. ROC-AUC 0.5 means the datasets are indistinguishable; 1.0 means fully
separable. The features it relies on show where they differ.

Figures and tables are written to `simulation/results/<collection>/`.

| File | Shows |
|---|---|
| `00_results_table.png` | all train → test results (accuracy, precision, recall, F1, FPR, ROC-AUC) |
| `01_datasets.png` | flows per class in each dataset |
| `02_transfer_matrix.png` | F1 for every train → test pair |
| `03_transfer_metrics.png` | precision, recall, F1, accuracy per pair |
| `04_feature_distributions.png` | six key features, benign and attack, in both datasets |
| `05_feature_importance.png` | what each model relies on |
| `06_sim_per_attack.png` | detection per simulated attack type, per model |
| `07_domain_gap.png` | how separable the datasets are, and by which features |
| `08_detection_time.png` | time to the first block decision per attack type and model, and false blocks |
| `09_detection_table.png` | the same as a table: attackers flagged, median and slowest time |
| `tables.md`, `results.json` | every number in the figures |

### Results of the first full collection

Collection `20261115-120806`: 3 repetitions, 118,305 finished flows. Repetition 3 is
held out.

| Model | F1, our traffic | F1, CIC-DDoS2019 | TCP connect flood | UDP flood | HTTP flood | False blocks |
|---|---|---|---|---|---|---|
| CIC-DDoS2019 | 0.30 | 0.999 | not flagged | 1.0 s | not flagged | 0 |
| Simulated, finished flows only | 0.83 | 0.00 | 0.1 s | not flagged | not flagged | 0 |
| Simulated (with snapshots) | 0.83 | 0.005 | 0.1 s | 9.0 s (1 of 3) | not flagged | 0 |
| CIC + simulated | 0.92 | 0.999 | 0.1 s | 1.0 s | not flagged | 0 |

- **Our data covers what CIC-DDoS2019 misses.** Models trained on it flag the TCP connect
  flood within 0.1 s; the CIC-DDoS2019 model never does.
- **CIC-DDoS2019 covers what our data misses.** Our models score F1 ≈ 0 on the public
  dataset. Its reflection and amplification attacks are not in our collection.
- **The combined model is best on both.** It is the fastest or tied on every attack, and
  keeps CIC-DDoS2019 performance.
- **The UDP flood is our data's weak spot.** It is 1.5 % of our flows, and its shape
  changes sharply between repetitions (24 → 192 → 1,536 flows). Snapshots raised detection
  from 0 of 3 attackers to 1 of 3. More repetitions, or a fixed UDP intensity, would give
  that class enough examples.
- **No model flags the HTTP flood on its own.** Its flows are ordinary web requests; live,
  the flow-rate rule blocks it.

## Train a model on your data

```bash
uv run python simulation/train_model.py              # CIC-DDoS2019 + newest collection   (make train-sim)
uv run python simulation/train_model.py --all-reps   # final model: every collected repetition
uv run python simulation/train_model.py --mode sim   # collected data only
```

- **Same model as the main one.** It is the project's Random Forest with the
  `ml/train.py` settings, saved with its feature schema to `models/random_forest_cic_sim.joblib`
  (or `random_forest_sim.joblib`). It never overwrites `models/random_forest.joblib`.
- **Report.** `results/ml/<name>.md` puts its test results next to the main model's on
  both test sets, with a per-class table for your attacks.
- **Same split as the comparison.** Your data is split by repetition and the last one is
  held out, so the report shows how the model does on traffic it never saw. `--all-reps`
  then trains the final model on every repetition. That version has no held-out collected
  test set, so look at the evaluated run first.
- **Using it.** Pass it to the monitor through the testbed:

  ```bash
  make live MODEL=models/random_forest_cic_sim.joblib
  make experiment MODEL=models/random_forest_cic_sim.joblib
  ```

  The dashboard needs no change: it shows whatever the monitor decides.

Why not `ml/train.py --extra-flows`? That option splits by flow, so near-duplicates of a
session land in both training and test and the scores come out too high. It also writes
over the main model.

## Preview: the older testbed runs

`simulation/results/from-runs/` holds the comparison run on the 12 existing experiment
runs (`results/runs/`), imported with
`uv run python simulation/build_dataset.py simulation/data/from-runs --from-runs results/runs`.
That data has a single attack type (UDP flood), no legitimate UDP traffic, and only
6 hosts. It shows the pipeline working, and it also shows the problem the new collection
fixes:

- **Simulated → simulated scores F1 1.000,** because in that data the protocol alone
  separates the classes: every UDP flow is an attack and every benign flow is TCP.
- **CIC-DDoS2019 → simulated:** recall 100 % but 1.8 % false positives on the testbed's
  legitimate traffic.
- **Simulated → CIC-DDoS2019:** recall 78 %. A model trained on one flood type misses
  many of the public attacks.
- **The datasets are fully separable** (ROC-AUC 1.000), mostly through the shortest gaps
  between packets (`Flow IAT Min`, `Fwd IAT Min`) and the TCP window sizes. Those reflect
  the emulated links and the host operating system, not the attacks.

Read the numbers from a full collection, not this preview.

## Notes

- **Root.** `collect.py` needs root for Mininet, Open vSwitch and tcpdump. Everything
  else runs as your user, and the collected files are handed back to the user who ran
  `sudo`.
- **What the attacks are.** The three floods are volumetric and connection floods sent
  from ordinary sockets. They are not the reflection and amplification attacks that make
  up most of CIC-DDoS2019, so each dataset contains attack types the other lacks. That is
  part of what the comparison measures.
- **Scope.** All generated traffic stays inside the emulated network and targets only
  its own server.
- **UDP flood flow counts.** Each repetition steps up both the threads and the
  destination ports of the UDP flood, so its flow count grows ×8 per repetition (24 → 192 →
  1,536 flows with the defaults). Held out, repetition 3's many short UDP flows look unlike
  the few long ones of repetitions 1 and 2, and a model trained only on collected data
  misses them. That is a real generalisation gap. To compare without it, hold out a
  different repetition (`--test-rep 2`) or collect more repetitions.
