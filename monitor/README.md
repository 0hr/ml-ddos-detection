# Real-time monitoring dashboard

A React + shadcn/ui dashboard for the DDoS testbed: the network topology with traffic
flowing between hosts, per-host packet rates, the model's verdict per source, the
mitigation timeline of each attack, SDN drop rules with their drop counters, and service
availability. It runs on **simulated data** with no testbed at all, or on a **real run** —
live while the testbed runs, or replayed afterwards.

```
monitor/
  server/
    engine.py  dashboard state + snapshot schema, and the scripted Simulator
    live.py    RunSource: a real run from results/runs/<scenario>/, live or replayed
    app.py     Flask API: ticks the source, streams snapshots over SSE, REST controls
  web/         Vite + React 19 + TypeScript + Tailwind + shadcn/ui
```

## Quick start (no testbed, no root)

```bash
uv run python monitor/server/app.py          # API on :8099, simulated data
cd monitor/web && npm install && npm run dev  # UI on http://localhost:5273 (proxies /api, /events)
```

Or build once and let the API serve the UI: `cd monitor/web && npm run build`, then open
http://127.0.0.1:8099. `make dashboard` does both.

## Watching a live run

```bash
make live              # terminal 1 (root): sudo python3 testbed/live.py
make dashboard-live    # terminal 2: builds the UI, then app.py --mode live → http://127.0.0.1:8099
```

`testbed/live.py` brings the whole testbed up and keeps it up (default 30 minutes, Ctrl-C
to stop): controller, topology, web service, the capture → monitor pipeline and the benign
clients. Nothing else is scripted. The header of the dashboard then offers:

| Control | What it does on the real testbed |
|---|---|
| **Launch attack** / **Stop attack** | starts a 30 s flood from `h1 h3 h5` toward the server (UDP, TCP connect or HTTP), or stops it |
| **Flash crowd** | 30 s of heavy *legitimate* traffic from the benign clients — it must not be blocked |
| **Mitigation** switch | the controller's detect-only mode: off = decisions are logged, no rule is installed |
| **block** / **unblock** (Sources), **remove** (Drop rules) | install or remove a drop rule by hand through the controller |

Every control acts on the testbed first; the dashboard shows the change only when the
controller or the session logs it, so the UI never claims something the network did not do.

`make dashboard-live` also works with a scripted `make experiment`: without `--run` it
follows `results/runs/current.json`, which the runner keeps pointed at the scenario in
progress, and switches when the next scenario starts.

## Three data sources

The header always says which one you are looking at.

| Mode | Command | Data | Controls |
|---|---|---|---|
| **Simulated data** | `app.py` | scripted attack → detect → block → recover cycle | scenario, mitigation toggle, block / unblock |
| **Live** | `app.py --mode live [--run DIR]` | tails the run in progress (or `DIR`) | mitigation toggle, block / unblock; attack and flash crowd when a live session is running |
| **Replay** | `app.py --mode replay --run results/runs/attack_mit [--speed 2]` | a finished run, on its recorded clock, looping | none (read-only) |

Live mode talks to the SDN controller's REST API (`--controller`, default
`http://127.0.0.1:8080`; `--token` or `$DDOS_API_TOKEN` if the controller requires one) and
shows two health indicators: whether the monitor is producing telemetry and how far it is
behind the wire, and whether the controller answers and how many switches it has. A
replay shows what happened, so it offers no controls. With repeated experiments, point
`--run` at one repetition, e.g. `results/runs/attack_mit/rep2`.

## What the numbers mean

- **Mitigation timeline** — one attack, stage by stage, with real timings: attack start →
  first block decision by the model → REST round trip to the controller → rule confirmed
  by every switch (OpenFlow barrier reply) → first drop-counter sample that moved.
- **Dropped at switch** — measured from the drop rules' packet counters, which the
  controller reads once per second. Blocked traffic never reaches the capture point, so
  these counters are the only place it can be counted. Runs recorded before the counters
  were logged show "—" instead of an estimate.
- **Attack at server** — attack-host packets still reaching the server link.
- **Availability** — in a real run it is **measured**: the share of benign client requests
  (`client_h*.jsonl`) that succeeded in the last 5 s. If a run has no client logs it shows
  "—", never an estimate. In simulated mode it is simulated and labelled so.
- **Time to detect / Time to mitigate** — attack start → the monitor's first block decision
  for an attacker (also logged when mitigation is off, as "would block") / → the rule
  confirmed on the switches. The attack start is the time the generators were started
  (`scenario.json`, or `session_events.jsonl` in a live session).
- **Sources** — for each host, the share of its flows the model classified as attack in
  the vote window, against the share the block rule needs (the tick mark), and its flow
  rate, which turns red above the rate limit. Either one blocks the source; the timeline
  says which ("flagged by the model" or "flagged by the rate limit"). A blocked source
  has no bar: its traffic no longer reaches the monitor.
- **Phase** — *Mitigating* while any attack source is blocked, *Under attack* while attack
  traffic reaches the server, *Attack ended* afterwards.

## Packet-level telemetry, not packet streaming

The model and the mitigation work on **flows**; the dashboard shows **packet rates**. The
live monitor (`traffic/monitor.py --telemetry`) bins every captured packet into 0.5 s
per-host windows (packets/s, bits/s). Streaming one event per packet would overwhelm the
browser at flood rates of tens of thousands of packets per second.

## Files a run provides

`run_experiment.py` and `live.py` write these into `results/runs/<scenario>/`:

| File | Used for |
|---|---|
| `telemetry.jsonl` | per-host packet rates and flow verdicts, monitor lag (topology, charts, sources) |
| `detections.jsonl` | the monitor's block decisions (activity feed, time to detect) |
| `controller_events.jsonl` | drop rules installed, confirmed, renewed, removed; drop counters; mitigation switch |
| `client_h*.jsonl` | measured availability |
| `session_events.jsonl` | attack and flash-crowd start/stop (live session only) |
| `scenario.json` | roles, mitigation setting and attack start; rewritten as the run progresses |

`results/runs/current.json` names the run in progress.

## API

`GET /events` streams one JSON snapshot four times per second; its shape is defined in
[`web/src/types.ts`](web/src/types.ts) and mirrored by `engine.py::Engine.snapshot()`.
`GET /api/state`, `GET /api/config` (mode, available controls, scenarios, topology);
`POST /api/scenario` (simulated only), `/api/mitigation`, `/api/block`, `/api/unblock`,
`/api/attack` and `/api/load` (live session only). In live mode these are forwarded to the
controller or the session. A control the current source cannot honour answers `409`.

## Stack

Vite · React 19 · TypeScript · Tailwind CSS · shadcn/ui (Radix Switch) · Recharts ·
Framer Motion · lucide-react. Backend: Flask (already a project dependency) with
Server-Sent Events.
