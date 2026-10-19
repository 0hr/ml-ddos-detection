# DDoS mitigation on FABRIC

A Jupyter notebook that deploys the mitigation half of this project on a
[FABRIC](https://portal.fabric-testbed.net) slice and runs it against a controlled flood: a traffic monitor scores flows with an
already trained Random Forest, and an OpenFlow 1.3 controller installs temporary drop
rules for the sources it flags. Nothing is trained here.

```
                     switch   Open vSwitch br0 + controller + monitor
               /        |         |         \         \
            srv        h1        h3         h2        h4
        web service  attacker  attacker   client    client
        10.0.0.100   10.0.0.1  10.0.0.3   10.0.0.2  10.0.0.4
```

## Run it

1. In the FABRIC JupyterHub (fablib already configured: project, bastion and slice keys),
   put the whole ML-DDoS repository in your home directory — `git clone` it, or upload it.
   The notebook deploys the code and the trained model from the repository it sits in, so
   the `fabric/` folder must stay inside it.
2. Open [`fabric/ddos_mitigation_fabric.ipynb`](ddos_mitigation_fabric.ipynb) and run the
   cells in order. Creating the slice and installing take about ten minutes; each scenario takes
   about one.
3. Run the last cell to delete the slice.

The notebook needs one site with six small VMs and ten `NIC_Basic` interfaces (five links,
two ends each). Sizes, the number of attackers and clients, the site, link shaping and the
block duration are fields of `Config` in the second code cell.

## What it does

| Step | Notebook cell | What happens |
|---|---|---|
| Slice | `tb.create()` | one switch node and five hosts, each on its own L2 network to the switch node |
| Install | `tb.install()` | uploads the code, the model and the node scripts; Open vSwitch, tcpdump and two Python environments on the switch node, Flask on the hosts |
| Data plane | `tb.configure_network()` | addresses and shaping on the hosts, the OpenFlow bridge, the forwarding table |
| Mitigation on | `tb.run_scenario("attack_mit", mitigation=True)` | benign clients, then a UDP flood; prints the drop rules and their counters every 2 s |
| Mitigation off | `tb.run_scenario("attack_nomit", mitigation=False)` | the same attack, decisions logged but nothing installed |
| Results | `analysis.summarize`, `analysis.plot_runs` | metrics table and a figure, per run |

During a scenario the monitor taps the switch port of the server link, builds flow
features, scores them, and asks the controller to block a source once at least 5 of its
flows in 6 s are classified as attack and they are at least 80 % of its traffic, or once
it produces more than 100 flows per second. A drop
rule lasts 20 s; the controller renews it while its packet counter is still moving and
lets it expire otherwise. The server address can never be blocked.

### Metrics

| Metric | Measured from |
|---|---|
| First attack packet at the tap → block decision | monitor telemetry and decisions, both on the switch node's clock (resolution: one 0.5 s window) |
| Controller API round trip, rule install confirmed | the monitor's request timing; the OpenFlow barrier reply |
| Attack packets that reached the server | packets from the attackers seen at the tap |
| Attack packets dropped at the switch | the drop rules' own packet counters, read every second |
| Benign requests ok before / during the attack | the clients' request logs |
| Benign sources blocked | drop rules installed for an address that is not an attacker |

Client and attacker timestamps come from other machines. The notebook measures each node's
clock offset when a scenario starts and moves those timestamps onto the switch node's
clock; the offsets are saved in `scenario.json`.

### Results

Each scenario is collected into `fabric/results/<scenario>/` in the same file format the Mininet
testbed writes (`telemetry.jsonl`, `detections.jsonl`, `controller_events.jsonl`,
`client_h*.jsonl`, `scenario.json`). A collected run can therefore be replayed in the
ML-DDoS dashboard:

```bash
uv run python monitor/server/app.py --mode replay --run fabric/results/attack_mit
```

## How forwarding works here

`NIC_Basic` interfaces are SR-IOV virtual functions: they normally accept only frames
addressed to their own MAC address and emit only frames carrying it. A learning bridge
cannot forward through such ports, so this deployment forwards by destination IP and
rewrites both MAC addresses:

- every host has a permanent neighbour entry sending each peer's traffic to the switch
  port on its own link (`fabric/runtime/bin/host_net.sh`);
- the controller installs one static route per host — match `ipv4_dst`, set `eth_src` to
  the outgoing switch port's MAC and `eth_dst` to the host's MAC, output on that port
  (`DDOS_STATIC_ROUTES`, written to `routes.json` by the notebook).

Mitigation is unchanged: a drop rule matches `ipv4_src` at a higher priority than the routes.

## Layout

| Path (under `fabric/`) | What |
|---|---|
| `ddos_mitigation_fabric.ipynb` | the notebook |
| `fabric_ddos/testbed.py` | builds the slice, installs, configures, runs a scenario, collects the logs |
| `fabric_ddos/analysis.py` | metrics and figures from a collected run |
| `runtime/bin/` | scripts run on the nodes: install, network setup, start controller, start monitor, stop |
| `runtime/requirements-*.txt` | pinned Python packages for the monitor and the controller |
| `tests/` | analysis on synthetic runs with known answers, and a dry run of the orchestration against a fake fablib |
| `results/` | collected runs (not tracked) |

What is uploaded to the nodes besides `runtime/` comes straight from the repository:
`controller/ddos_controller.py`, the `ddos/` package, `traffic/monitor.py`, the three
traffic tools in `testbed/`, and `models/random_forest.joblib` with its schema. A change
there is deployed by the next `tb.install()`.

The model must be loaded with the library versions it was trained with; they are pinned in
`runtime/requirements-monitor.txt`. The saved model gives identical predictions on Python
3.12 (the Ubuntu 24 image) and 3.14 (where it was trained). The nodes install only from
the Ubuntu archive and PyPI, both reachable from FABRIC's IPv6-only sites.

## Validation status

Checked on a workstation: the analysis against synthetic runs and against recorded Mininet
runs, the orchestration against a fake fablib, the node scripts for shell syntax, and the
controller's static routes for valid OpenFlow 1.3 encoding. The notebook has **not yet been
run on a FABRIC slice**. The first run is the test of everything that depends on FABRIC
itself: fablib calls, the image, interface names, and forwarding through `NIC_Basic` ports.

## If something goes wrong

- **Hosts cannot reach each other** (`run_scenario` stops at "the web service is not
  reachable"). On the switch node run
  `sudo ovs-ofctl -O OpenFlow13 dump-flows br0`. The priority-10 routes should be there
  and their packet counters should grow while a host pings another. If the routes are
  missing, the controller did not read `~/ddos/routes.json` (see
  `~/ddos/runs/<scenario>/controller.log`). If they are there but the counters stay at 0,
  frames are not arriving at the switch ports: check the neighbour entries on the host
  (`ip neigh`) against the switch port MACs printed by `tb.configure_network()`.
- **The flood does not hurt availability with mitigation off.** The server link is shaped
  to 20 Mbit/s; if the flood is weaker than that, raise `attack_threads` or lower
  `server_rate_mbit` in `Config`.
- **Nothing is blocked.** Look at `results/<scenario>/monitor.log` for the model loading
  and `detections.jsonl` for decisions; `tap.log` shows whether tcpdump captured anything.
- **After a kernel restart**, run the *Set up* cells and `tb.attach()`; do not create the
  slice again.

## Safety

The flood generator (`testbed/attack.py`) uses ordinary sockets only, refuses any
target that is not a private address, and stops after its duration. It is aimed at the
slice's own server over the slice's isolated L2 networks. Do not point it elsewhere.
