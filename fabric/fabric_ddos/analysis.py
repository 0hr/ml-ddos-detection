"""Turn a collected run (results/<scenario>/) into metrics and figures.

A run directory holds the same files as the Mininet testbed writes, so anything that
reads one reads the other:
  telemetry.jsonl          per-0.5 s per-source packet rates at the tap on the server link
  detections.jsonl         the monitor's block decisions
  controller_events.jsonl  drop rules installed / confirmed / renewed, their drop counters
  client_h*.jsonl          every benign HTTP request, ok or not
  scenario.json            roles, mitigation mode, attack start, clock offsets

All timestamps are on the switch node's clock. Detection is measured from the first attack
packet seen at the tap, which uses that same clock, so it does not depend on how well the
nodes' clocks agree.
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path

ATTACKING_PPS = 200.0  # a source above this rate at the tap counts as flooding

# Chart colours: the first two categorical palette slots, plus neutral inks for everything
# that is not data.
SERIES_1, SERIES_2 = "#2a78d6", "#eb6834"
SURFACE, INK, INK_2, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#8a897f", "#e6e5e0"


def read_jsonl(path: Path) -> list[dict]:
    out = []
    try:
        for line in path.read_text().splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                pass  # a line cut off when the run was stopped
    except OSError:
        pass
    return out


def load_run(run_dir: str | Path) -> dict:
    run = Path(run_dir)
    meta = json.loads((run / "scenario.json").read_text())
    return {
        "dir": run, "meta": meta,
        "telemetry": [r for r in read_jsonl(run / "telemetry.jsonl") if r.get("event") == "telemetry"],
        "detections": read_jsonl(run / "detections.jsonl"),
        "controller": read_jsonl(run / "controller_events.jsonl"),
        "requests": sorted((r for p in sorted(run.glob("client_*.jsonl")) for r in read_jsonl(p)),
                           key=lambda r: r["ts"]),
    }


def _share(items) -> float | None:
    items = list(items)
    return round(sum(items) / len(items), 4) if items else None


def _dropped(controller: list[dict]) -> tuple[int | None, list[tuple[float, float]]]:
    """(total packets dropped, [(ts, drop pps summed over rules)]) from the rule counters.

    A rule's counter is cumulative and restarts when the source is blocked again, so the
    total is the sum of the increases. The total is None when the run recorded no counters
    at all: unknown, not the same as zero.
    """
    last: dict[str, int] = {}
    total = 0
    if not any(ev.get("event") == "block_stats" for ev in controller):
        return (None if any(ev.get("event") == "block_installed" for ev in controller) else 0), []
    per_second: dict[int, float] = {}
    for ev in controller:
        if ev.get("event") != "block_stats":
            continue
        ip, count = ev["ip"], int(ev.get("dropped_packets", 0))
        prev = last.get(ip, 0)
        total += count - prev if count >= prev else count
        last[ip] = count
        sec = int(ev["ts"])
        per_second[sec] = per_second.get(sec, 0.0) + float(ev.get("drop_pps", 0))
    return total, sorted((float(s), pps) for s, pps in per_second.items())


def block_intervals(run: dict) -> list[tuple[float, float]]:
    """[start, end] periods during which at least one drop rule was active."""
    spans = []
    for ev in run["controller"]:
        if ev.get("event") in ("block_installed", "block_renewed"):
            spans.append((ev["ts"], ev["ts"] + float(ev.get("duration", 0))))
    merged: list[list[float]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    t_end = run["telemetry"][-1]["t"] if run["telemetry"] else None
    return [(s, min(e, t_end) if t_end else e) for s, e in merged]


def summarize(run: dict) -> dict:
    meta, tel, ctrl = run["meta"], run["telemetry"], run["controller"]
    attackers = set(meta.get("attacker_ips", []))

    first_pkt = next((r["t"] - r.get("window", 0.5) for r in tel
                      if any(r["hosts"].get(ip, {}).get("pps", 0) > ATTACKING_PPS for ip in attackers)), None)
    decisions = [d for d in run["detections"] if d.get("event") == "block_request" and d.get("ip") in attackers]
    first_decision = decisions[0]["ts"] if decisions else None
    sent = [d for d in decisions if not (d.get("response") or {}).get("dry_run")]  # reached the controller
    installs = [e for e in ctrl if e.get("event") == "block_installed"]
    confirms = [e for e in ctrl if e.get("event") == "block_confirmed"]
    first_confirm = next((e["ts"] for e in confirms if e.get("ip") in attackers), None)

    reached = sum(r["hosts"].get(ip, {}).get("pps", 0) * r.get("window", 0.5) for r in tel for ip in attackers)
    dropped, _ = _dropped(ctrl)
    reqs = run["requests"]
    start = first_pkt if first_pkt is not None else meta.get("attack_start")
    during = [r for r in reqs if start is not None and r["ts"] >= start]
    latencies = [r["latency_ms"] for r in during if r.get("ok")]

    def since_first(t):
        return None if t is None or first_pkt is None else round(t - first_pkt, 3)

    return {
        "scenario": meta.get("scenario"),
        "mitigation": bool(meta.get("config", {}).get("mitigate")),
        "attack": meta.get("config", {}).get("attack"),
        "detection_s": since_first(first_decision),
        "mitigation_s": since_first(first_confirm),
        "launch_to_decision_s": (None if first_decision is None or not meta.get("attack_start")
                                 else round(first_decision - meta["attack_start"], 3)),
        "api_ms": round(statistics.median(d["api_latency_ms"] for d in sent), 2) if sent else None,
        "confirm_ms": round(statistics.median(e["latency_ms"] for e in confirms), 2) if confirms else None,
        "sources_blocked": len({e["ip"] for e in installs if e["ip"] in attackers}),
        "attack_sources": len(attackers),
        "false_blocks": len({e["ip"] for e in installs if e["ip"] not in attackers and e.get("reason") != "manual (notebook)"}),
        "renewals": sum(e.get("event") == "block_renewed" for e in ctrl),
        "attack_packets_at_server": round(reached),
        "attack_packets_dropped": dropped,
        "exposure": round(reached / (reached + dropped), 4) if dropped is not None and reached + dropped else None,
        "availability_before": _share(r["ok"] for r in reqs if start is None or r["ts"] < start),
        "availability_during": _share(r["ok"] for r in during),
        "benign_requests_during": len(during),
        "latency_ms_p50_during": round(statistics.median(latencies), 1) if latencies else None,
        "monitor_lag_ms_max": max((r.get("monitor", {}).get("lag_ms", 0) for r in tel), default=None),
    }


ROWS = [
    ("mitigation", "Mitigation", lambda v: "on" if v else "off"),
    ("detection_s", "First attack packet at the tap → block decision", lambda v: f"{v:.2f} s"),
    ("mitigation_s", "First attack packet at the tap → rule on the switch", lambda v: f"{v:.2f} s"),
    ("launch_to_decision_s", "Attack launched → block decision", lambda v: f"{v:.2f} s"),
    ("api_ms", "Controller API round trip (median)", lambda v: f"{v:.1f} ms"),
    ("confirm_ms", "Rule install confirmed by the switch (median)", lambda v: f"{v:.1f} ms"),
    ("sources_blocked", "Attack sources blocked", None),
    ("false_blocks", "Benign sources blocked", None),
    ("renewals", "Rule renewals", None),
    ("attack_packets_at_server", "Attack packets that reached the server", lambda v: f"{v:,}"),
    ("attack_packets_dropped", "Attack packets dropped at the switch", lambda v: f"{v:,}"),
    ("exposure", "Share of the attack that reached the server", lambda v: f"{v:.1%}"),
    ("availability_before", "Benign requests ok before the attack", lambda v: f"{v:.1%}"),
    ("availability_during", "Benign requests ok during the attack", lambda v: f"{v:.1%}"),
    ("latency_ms_p50_during", "Benign latency during the attack (median)", lambda v: f"{v:.0f} ms"),
    ("monitor_lag_ms_max", "Largest monitor lag behind the wire", lambda v: f"{v:.0f} ms"),
]


def summary_table(summaries: list[dict]) -> str:
    """Markdown table with one column per run."""
    lines = ["| | " + " | ".join(s["scenario"] or "run" for s in summaries) + " |",
             "|---|" + "---:|" * len(summaries)]
    for key, label, fmt in ROWS:
        cells = []
        for s in summaries:
            v = s.get(key)
            if key == "sources_blocked" and v is not None:
                cells.append(f"{v} of {s['attack_sources']}")
            else:
                cells.append("—" if v is None else fmt(v) if fmt else str(v))
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


# ---------------------------------------------------------------------------- figures
def _style(ax, ylabel: str) -> None:
    ax.set_facecolor(SURFACE)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.tick_params(colors=INK_2, length=0, labelsize=9)
    ax.set_ylabel(ylabel, color=INK_2, fontsize=9)


def _context(ax, run: dict, t0: float, label: bool) -> None:
    """Shade the periods with an active drop rule and mark the attack start."""
    for i, (start, end) in enumerate(block_intervals(run)):
        ax.axvspan(start - t0, end - t0, color=MUTED, alpha=0.13, linewidth=0,
                   label="drop rule active" if label and i == 0 else None)
    attack = run["meta"].get("attack_start")
    if attack is not None:
        ax.axvline(attack - t0, color=INK_2, linewidth=1, linestyle=(0, (4, 3)))
        ax.annotate("attack starts", (attack - t0, 1.0), xycoords=("data", "axes fraction"),
                    xytext=(4, -10), textcoords="offset points", fontsize=8.5, color=INK_2)


def plot_runs(runs: list[dict]):
    """One column per run: normal-request availability on top, attack traffic below.

    Runs share the y-axes, so mitigation off and on compare directly.
    """
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(2, len(runs), figsize=(6.4 * len(runs), 6.2), sharey="row",
                             squeeze=False, facecolor=SURFACE)
    for col, run in enumerate(runs):
        meta, tel = run["meta"], run["telemetry"]
        t0 = meta.get("t_start") or (tel[0]["t"] if tel else 0.0)
        attackers = set(meta.get("attacker_ips", []))
        mitigated = bool(meta.get("config", {}).get("mitigate"))

        ax = axes[0][col]
        buckets: dict[int, list] = {}
        for r in run["requests"]:
            buckets.setdefault(int(r["ts"] - t0), []).append(bool(r["ok"]))
        xs = sorted(buckets)
        ax.plot(xs, [100 * sum(buckets[x]) / len(buckets[x]) for x in xs], color=SERIES_1, linewidth=2)
        ax.set_ylim(-3, 116)  # headroom for the attack-start label
        ax.set_yticks([0, 25, 50, 75, 100])
        _style(ax, "benign requests ok (%)" if col == 0 else "")
        _context(ax, run, t0, label=False)
        ax.set_title(f"{meta.get('scenario', 'run')}  ·  mitigation {'on' if mitigated else 'off'}",
                     loc="left", fontsize=11, fontweight="bold", color=INK)

        ax = axes[1][col]
        ax.plot([r["t"] - t0 for r in tel],
                [sum(r["hosts"].get(ip, {}).get("pps", 0) for ip in attackers) for r in tel],
                color=SERIES_1, linewidth=2, label="reaching the server")
        _, drops = _dropped(run["controller"])
        if drops:
            ax.plot([t - t0 for t, _ in drops], [pps for _, pps in drops], color=SERIES_2, linewidth=2,
                    label="dropped at the switch")
        ax.margins(y=0.16)
        _style(ax, "attack packets / s" if col == 0 else "")
        _context(ax, run, t0, label=True)
        ax.set_xlabel("seconds since the run started", color=INK_2, fontsize=9)
        ax.legend(frameon=False, fontsize=8.5, labelcolor=INK_2, loc="upper right")
    fig.tight_layout()
    return fig
