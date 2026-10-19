"""Turn the testbed runs into the final comparison figures and tables.

Reads results/runs/<scenario>/ (one run) or results/runs/<scenario>/rep*/ (from
run_experiment.py --repeat N) and writes, under results/report/:
  * confusion_matrices.png   per-flow normal/attack confusion on real testbed traffic,
                             using host roles as the truth (per attack scenario)
  * availability.png         normal request success rate over time, attack window shaded
  * attack_traffic.png       attack traffic reaching the server, mitigation off vs on, with
                             the times drop rules were active
  * latency_cdf.png          normal request latency CDF per scenario
  * summary.md / summary.json   detection + mitigation latency, attack exposure,
                             availability, per-flow detection

With repetitions, every number is a mean (min-max) over the runs, confusion matrices are
summed over all runs, availability is drawn as the mean with a min-max band, and the
attack-traffic figure shows the run with the median exposure (a typical one).

Run with the venv that has sklearn/pandas:  .venv/bin/python ml/analyze_results.py
"""

import argparse
import json
import re
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix

ROOT = Path(__file__).resolve().parents[1]


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def load_client_log(run_dir: Path) -> pd.DataFrame:
    rows = []
    for f in run_dir.glob("client_*.jsonl"):
        rows += read_jsonl(f)
    return pd.DataFrame(rows)


def flow_confusion(run_dir: Path, meta: dict):
    fp = run_dir / "flows.parquet"
    if not fp.exists():
        return None
    df = pd.read_parquet(fp)
    if not len(df) or "predicted_attack" not in df:
        return None
    attackers, benign = set(meta["attacker_ips"]), set(meta["benign_ips"])
    df = df[df["Source IP"].isin(attackers | benign)].copy()
    if not len(df):
        return None
    df["truth"] = df["Source IP"].isin(attackers).astype(int)
    cm = confusion_matrix(df["truth"], df["predicted_attack"], labels=[0, 1])
    tn, fp_, fn, tp = cm.ravel()
    return {
        "flows": len(df), "matrix": cm,
        "tn": int(tn), "fp": int(fp_), "fn": int(fn), "tp": int(tp),
        "recall": tp / max(tp + fn, 1), "precision": tp / max(tp + fp_, 1),
        "fpr": fp_ / max(fp_ + tn, 1),
    }


def availability(run_dir: Path, meta: dict, bin_s=2.0):
    clients = load_client_log(run_dir)
    if not len(clients):
        return None
    t0 = meta["t_start"]
    clients["t"] = clients["ts"] - t0
    clients["bin"] = (clients["t"] // bin_s) * bin_s
    grp = clients.groupby("bin")["ok"].agg(["mean", "size"]).rename(columns={"mean": "success", "size": "n"})
    return {"series": grp, "clients": clients,
            "attack_rel": (meta.get("attack_start") - t0) if meta.get("attack_start") else None}


def attack_window(run_dir: Path, meta: dict):
    """(first attack packet, attack end) in epoch seconds, or None for normal-only runs.

    meta["attack_start"] is when the runner *launched* attack.py; the first packet leaves a
    bit later, so detection latency is measured from the packets themselves.
    """
    if not meta.get("attack_start"):
        return None
    attackers = set(meta.get("attacker_ips", []))
    first = None
    flows = run_dir / "flows.parquet"
    if flows.exists():  # exact capture time of the first attack packet
        f = pd.read_parquet(flows, columns=["Source IP", "start_ts"])
        f = f[f["Source IP"].isin(attackers)]
        if len(f):
            first = float(f["start_ts"].min())
    if first is None:  # else fall back to the 0.5 s telemetry windows (start of the first)
        seen = [r["t"] - r.get("window", 0.5) for r in read_jsonl(run_dir / "telemetry.jsonl")
                if any(ip in attackers and v.get("pps", 0) > 0 for ip, v in r.get("hosts", {}).items())]
        first = min(seen) if seen else meta["attack_start"]
    ran = [float(m.group(1)) for f in run_dir.glob("attack_*.log")
           if (m := re.search(r"in ([\d.]+)s", f.read_text()))]
    end = meta["attack_start"] + (max(ran) if ran else meta.get("duration", 0))
    return first, end


def attack_series(run_dir: Path, meta: dict) -> pd.DataFrame:
    """Attack-host packets/s reaching the server, per telemetry window."""
    attackers = set(meta.get("attacker_ips", []))
    rows = [{"t": r["t"], "window": r.get("window", 0.5),
             "attack_pps": sum(v.get("pps", 0) for ip, v in r.get("hosts", {}).items() if ip in attackers)}
            for r in read_jsonl(run_dir / "telemetry.jsonl")]
    return pd.DataFrame(rows, columns=["t", "window", "attack_pps"])


def drop_rule_intervals(run_dir: Path) -> list[tuple[float, float]]:
    """Merged [start, end] periods during which at least one drop rule was active."""
    spans, current = [], {}  # current[ip] = index into spans of that IP's live rule
    for e in sorted(read_jsonl(run_dir / "controller_events.jsonl"), key=lambda e: e["ts"]):
        ip, ev, ts = e.get("ip"), e.get("event"), e["ts"]
        if ev in ("block_installed", "block_renewed"):
            end = ts + float(e.get("duration", 20))
            i = current.get(ip)
            if i is not None and ts <= spans[i][1]:  # renewed while still active
                spans[i] = (spans[i][0], end)
            else:  # a new rule after the last one expired: keep the gap visible
                current[ip] = len(spans)
                spans.append((ts, end))
        elif ev == "unblock" and ip in current:
            i = current.pop(ip)
            spans[i] = (spans[i][0], min(spans[i][1], ts))
    spans.sort()
    merged = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


def exposure(run_dir: Path, meta: dict, threshold_pps: float = 100.0):
    """Seconds of the attack during which attack traffic actually reached the server."""
    win = attack_window(run_dir, meta)
    if win is None:
        return None
    first, end = win
    ser = attack_series(run_dir, meta)
    hit = ser[ser["attack_pps"] > threshold_pps]
    # overlap of each telemetry window [t - window, t] with the attack window [first, end]
    overlap = (np.minimum(hit["t"], end) - np.maximum(hit["t"] - hit["window"], first)).clip(lower=0)
    duration = max(end - first, 1e-9)
    exposed = min(float(overlap.sum()), duration)
    return {"attack_duration_s": round(duration, 1), "exposed_s": round(exposed, 1),
            "exposed_share": round(exposed / duration, 3)}


def detection_latency(run_dir: Path, meta: dict):
    det = read_jsonl(run_dir / "detections.jsonl")
    ctrl = read_jsonl(run_dir / "controller_events.jsonl")
    attack_start = meta.get("attack_start")
    out = {"attack_start": attack_start}
    blocks = [e for e in det if e.get("event") == "block_request"]
    installs = [e for e in ctrl if e.get("event") == "block_installed"]
    confirms = [e for e in ctrl if e.get("event") == "block_confirmed"]
    attacker_blocks = [b for b in blocks if b["ip"] in set(meta.get("attacker_ips", []))]
    # A block request against a normal client is a false block (detect-only runs log what
    # *would* have been blocked). This is the main number for the high-load scenario.
    out["false_blocks"] = sorted({b["ip"] for b in blocks if b["ip"] in set(meta.get("benign_ips", []))})
    win = attack_window(run_dir, meta)
    if win and attacker_blocks:
        out["first_attack_packet_after_launch_s"] = round(win[0] - attack_start, 3)
        out["detection_latency_s"] = round(min(b["ts"] for b in attacker_blocks) - win[0], 3)
    real = [b for b in blocks if not (b.get("response") or {}).get("dry_run")]
    out["dry_run"] = bool(blocks) and not real
    if real:
        out["api_latency_ms_median"] = round(float(np.median([b.get("api_latency_ms", 0) for b in real])), 2)
    out["renewals"] = sum(e.get("event") == "block_renewed" for e in ctrl)
    if confirms:
        out["mitigation_confirm_ms_median"] = round(float(np.median([c["latency_ms"] for c in confirms])), 2)
    out["blocks_requested"] = len(blocks)
    out["blocks_installed"] = len(installs)
    out["blocked_ips"] = sorted({b["ip"] for b in blocks})
    return out


def tap_drops(log: Path):
    """(packets received, packets dropped by the kernel) from a tcpdump exit report."""
    txt = log.read_text() if log.exists() else ""
    got = re.search(r"(\d+) packets received by filter", txt)
    lost = re.search(r"(\d+) packets dropped by kernel", txt)
    return (int(got.group(1)), int(lost.group(1))) if got and lost else None


def discover(runs_dir: Path) -> dict[str, list[tuple[Path, dict]]]:
    """scenario -> [(run_dir, meta), ...] for both layouts (single run or rep*/)."""
    order = {"normal": 0, "highload": 1, "attack_nomit": 2, "attack_mit": 3}
    found = {}
    for d in sorted((p for p in runs_dir.glob("*") if p.is_dir()), key=lambda p: (order.get(p.name, 99), p.name)):
        if (d / "scenario.json").exists():
            dirs = [d]
        else:
            dirs = sorted((r.parent for r in d.glob("rep*/scenario.json")),
                          key=lambda r: int(re.sub(r"\D", "", r.name) or 0))
        if dirs:
            found[d.name] = [(r, json.loads((r / "scenario.json").read_text())) for r in dirs]
    return found


def run_metrics(d: Path, meta: dict) -> dict:
    """Every number the report needs, for one run."""
    m = {"run": d.name}
    av = availability(d, meta)
    if av is not None:
        c = av["clients"]
        during = c[c["t"] >= av["attack_rel"]] if av["attack_rel"] is not None else c
        m.update(requests=len(c), success_overall=float(c["ok"].mean()),
                 success_during_attack=float(during["ok"].mean()) if len(during) else None,
                 median_latency_ms=float(c.loc[c["ok"], "latency_ms"].median()) if c["ok"].any() else None)
    det = detection_latency(d, meta)
    m.update(detection_s=det.get("detection_latency_s"), api_ms=det.get("api_latency_ms_median"),
             confirm_ms=det.get("mitigation_confirm_ms_median"), dry_run=det.get("dry_run", False),
             block_requests=det.get("blocks_requested", 0), renewals=det.get("renewals", 0),
             blocked_ips=det.get("blocked_ips", []), false_block_ips=det.get("false_blocks", []),
             false_blocks=len(det.get("false_blocks", [])))
    ex = exposure(d, meta)
    if ex:
        m.update(exposed_s=ex["exposed_s"], exposed_share=ex["exposed_share"], attack_duration_s=ex["attack_duration_s"])
    cm = flow_confusion(d, meta)
    if cm:
        m.update(tp=cm["tp"], fp=cm["fp"], fn=cm["fn"], tn=cm["tn"], flows=cm["flows"])
    for key, log in (("tap", "tap.log"), ("archive", "tcpdump.log")):
        x = tap_drops(d / log)
        if x:
            m[f"{key}_received"], m[f"{key}_dropped"] = x
    f = d / "flows.parquet"
    if f.exists():
        df = pd.read_parquet(f)
        if "predicted_attack" in df:
            fp = df[df["Source IP"].isin(meta.get("benign_ips", [])) & (df["predicted_attack"] == 1)]
            m["fp_flagged"] = len(fp)
            m["fp_zero_payload"] = int(((fp["Protocol"] == 6) & (fp["Total Length of Fwd Packets"]
                                                                  + fp["Total Length of Bwd Packets"] == 0)).sum())
            m["fp_fwd_only"] = int((fp["Total Backward Packets"] == 0).sum())
            m["fp_durations_ms"] = (fp["Flow Duration"] / 1000).round(2).tolist()
    return m


def agg(runs: list[dict], key: str) -> dict | None:
    vals = [r[key] for r in runs if r.get(key) is not None]
    if not vals:
        return None
    return {"mean": float(np.mean(vals)), "min": float(np.min(vals)), "max": float(np.max(vals)), "n": len(vals)}


def cell(a: dict | None, fmt: str = "{:.2f}") -> str:
    """One value for a single run, 'mean (min-max)' over repetitions."""
    if a is None:
        return "-"
    if a["n"] == 1 or a["min"] == a["max"]:
        return fmt.format(a["mean"])
    return f"{fmt.format(a['mean'])} ({fmt.format(a['min'])}–{fmt.format(a['max'])})"


def pct(a: dict | None) -> str:
    return cell(None if a is None else {k: (v * 100 if k != "n" else v) for k, v in a.items()}, "{:.1f}%")


def representative(runs: list[tuple[Path, dict]], metrics: list[dict]) -> int:
    """Index of the run with the median attack exposure (a typical run, not the best one)."""
    ex = [(m.get("exposed_s", 0.0), i) for i, m in enumerate(metrics)]
    return sorted(ex)[len(ex) // 2][1]


STYLE = {"normal": dict(color="#8a8f98", ls=(0, (1, 2))), "highload": dict(color="#6b7fd7", ls="--"),
         "attack_nomit": dict(color="#d64545"), "attack_mit": dict(color="#1f9d6b")}


def plot_availability(scenarios, out_dir: Path, bin_s: float = 2.0) -> None:
    fig, ax = plt.subplots(figsize=(10, 4.6))
    shaded = False
    for name, runs in scenarios.items():
        per_run = []
        for d, meta in runs:
            av = availability(d, meta, bin_s)
            if av is not None:
                per_run.append(av["series"]["success"] * 100)
            win = attack_window(d, meta)
            if win and not shaded:
                ax.axvspan(win[0] - meta["t_start"], win[1] - meta["t_start"], color="#d64545",
                           alpha=0.06, lw=0, label="attack running")
                shaded = True
        if not per_run:
            continue
        table = pd.concat(per_run, axis=1)
        mean = table.mean(axis=1)
        style = STYLE.get(name, {})
        label = name + (f" (mean of {len(per_run)})" if len(per_run) > 1 else "")
        ax.plot(mean.index, mean, lw=2 if name.startswith("attack") else 1.5, label=label, **style)
        if len(per_run) > 1:
            ax.fill_between(mean.index, table.min(axis=1), table.max(axis=1),
                            color=style.get("color"), alpha=0.12, lw=0)
    ax.set(xlabel="time since scenario start (s)", ylabel="benign requests succeeding (%)",
           title=f"Service availability ({bin_s:.0f} s bins" + (", band = min–max over runs)"
                  if any(len(r) > 1 for r in scenarios.values()) else ")"), ylim=(-3, 105))
    if ax.get_legend_handles_labels()[0]:
        ax.legend(loc="lower left", frameon=False)
    ax.grid(alpha=0.25)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    fig.tight_layout()
    fig.savefig(out_dir / "availability.png", dpi=130)
    plt.close(fig)


def plot_attack_traffic(scenarios, metrics, out_dir: Path) -> None:
    names = [n for n, runs in scenarios.items() if attack_window(*runs[0])]
    stale = out_dir / "detection_timeline.png"
    if stale.exists():
        stale.unlink()
    if not names:
        return
    fig, axes = plt.subplots(len(names), 1, figsize=(10, 2.3 * len(names) + 0.6), sharex=True, squeeze=False)
    xmax = 0.0
    for ax, name in zip(axes[:, 0], names):
        runs, ms = scenarios[name], metrics[name]
        i = representative(runs, ms)
        d, meta = runs[i]
        t0 = meta["t_start"]
        xmax = max(xmax, meta["t_end"] - t0)
        first, end = attack_window(d, meta)
        ser = attack_series(d, meta)
        ax.axvspan(first - t0, end - t0, color="#d64545", alpha=0.05, lw=0)
        for k, (a, b) in enumerate(drop_rule_intervals(d)):
            ax.axvspan(a - t0, b - t0, color="#e8a33d", alpha=0.22, lw=0, label="drop rule active" if k == 0 else None)
        ax.plot(ser["t"] - t0, ser["attack_pps"], color="#d64545", lw=1.6, label="attack pps at server")
        share = agg(ms, "exposed_share")
        which = f"run {i + 1} of {len(runs)}, median exposure · " if len(runs) > 1 else ""
        ax.set_title(f"{name}: {which}attack reached the server {pct(share)} of the attack", loc="left", fontsize=10)
        ax.set_ylabel("pps")
        ax.grid(alpha=0.25)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
        if ax.get_legend_handles_labels()[0]:
            ax.legend(loc="upper right", frameon=False, fontsize=8)
    axes[-1, 0].set_xlabel("time since scenario start (s)")
    axes[-1, 0].set_xlim(0, xmax)
    fig.tight_layout()
    fig.savefig(out_dir / "attack_traffic.png", dpi=130)
    plt.close(fig)


def plot_latency_cdf(scenarios, out_dir: Path) -> None:
    fig, ax = plt.subplots(figsize=(8, 4.8))
    for name, runs in scenarios.items():
        lat = []
        for d, _ in runs:
            c = load_client_log(d)
            if len(c):
                lat += c.loc[c["ok"], "latency_ms"].tolist()
        if lat:
            lat = np.sort(lat)
            ax.plot(lat, np.linspace(0, 1, len(lat)), label=name, **STYLE.get(name, {}))
    ax.set(xlabel="latency (ms)", ylabel="CDF", xscale="log",
           title="Benign request latency (successful requests, all runs pooled)")
    if ax.get_legend_handles_labels()[0]:
        ax.legend(frameon=False)
    ax.grid(alpha=0.25)
    fig.tight_layout()
    fig.savefig(out_dir / "latency_cdf.png", dpi=130)
    plt.close(fig)


def plot_confusion(totals: dict, out_dir: Path) -> None:
    names = [n for n, t in totals.items() if t]
    if not names:
        return
    fig, axes = plt.subplots(1, len(names), figsize=(4.6 * len(names), 4.2), squeeze=False)
    for ax, name in zip(axes[0], names):
        t = totals[name]
        cm = np.array([[t["tn"], t["fp"]], [t["fn"], t["tp"]]])
        ax.imshow(cm, cmap="Blues")
        for (i, j), v in np.ndenumerate(cm):
            ax.text(j, i, f"{v:,}", ha="center", va="center", color="white" if v > cm.max() / 2 else "black")
        runs = f" · {t['runs']} runs" if t["runs"] > 1 else ""
        title = (f"{name}{runs}\nrecall={t['recall']:.3f} fpr={t['fpr']:.4f}" if t["tp"] + t["fn"]
                 else f"{name} (benign only){runs}\nfpr={t['fpr']:.4f}")
        ax.set(xticks=[0, 1], yticks=[0, 1], xticklabels=["benign", "attack"], yticklabels=["benign", "attack"],
               xlabel="predicted", ylabel="actual", title=title)
    fig.suptitle("Per-flow detection on testbed traffic (ground truth = host role)")
    fig.tight_layout()
    fig.savefig(out_dir / "confusion_matrices.png", dpi=130)
    plt.close(fig)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", default=str(ROOT / "results/runs"))
    ap.add_argument("--out", default=str(ROOT / "results/report"))
    args = ap.parse_args()
    runs_dir, out_dir = Path(args.runs), Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    scenarios = discover(runs_dir)
    if not scenarios:
        raise SystemExit(f"no runs found under {runs_dir}; run testbed/run_experiment.py first")
    metrics = {name: [run_metrics(d, meta) for d, meta in runs] for name, runs in scenarios.items()}
    n_reps = max(len(r) for r in scenarios.values())

    totals = {}  # confusion summed over runs, so rates come from all flows
    for name, ms in metrics.items():
        if not any("tp" in m for m in ms):
            totals[name] = None
            continue
        t = {k: sum(m.get(k, 0) for m in ms) for k in ("tp", "fp", "fn", "tn", "flows")}
        t.update(runs=len(ms), recall=t["tp"] / max(t["tp"] + t["fn"], 1),
                 precision=t["tp"] / max(t["tp"] + t["fp"], 1), fpr=t["fp"] / max(t["fp"] + t["tn"], 1))
        totals[name] = t

    plot_availability(scenarios, out_dir)
    plot_attack_traffic(scenarios, metrics, out_dir)
    plot_latency_cdf(scenarios, out_dir)
    plot_confusion(totals, out_dir)

    keys = ["requests", "success_overall", "success_during_attack", "median_latency_ms", "detection_s",
            "api_ms", "confirm_ms", "exposed_s", "exposed_share", "block_requests", "renewals", "false_blocks"]
    summary = {name: {"config": scenarios[name][0][1]["config"], "runs": len(ms),
                      "aggregate": {k: agg(ms, k) for k in keys}, "confusion_total": totals[name],
                      "per_run": ms} for name, ms in metrics.items()}
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, default=str))

    reps_note = (f"Each scenario was run **{n_reps} times**; values are **mean (min–max)** over the runs."
                 if n_reps > 1 else "Each scenario was run once; use `run_experiment.py --repeat N` for means and ranges.")
    lines = ["# Testbed experiment results", "",
             "Comparison of normal operation, high (benign) load, and controlled suspicious traffic "
             "with mitigation disabled vs enabled.", "", reps_note, "",
             "## Service availability", "",
             "| scenario | runs | attack | mitigation | requests | success overall | success during attack | median latency (ms) |",
             "|---|---|---|---|---|---|---|---|"]
    for name, sm in summary.items():
        a, cfg = sm["aggregate"], sm["config"]
        lines.append(f"| {name} | {sm['runs']} | {cfg['attack'] or '-'} | {'on' if cfg['mitigate'] else 'off'} | "
                     f"{cell(a['requests'], '{:.0f}')} | {pct(a['success_overall'])} | "
                     f"{pct(a['success_during_attack'])} | {cell(a['median_latency_ms'], '{:.1f}')} |")

    lines += ["", "## Detection and mitigation", "",
              "Detection latency runs from the first attack packet on the server link to the monitor's "
              "first block decision. Exposure is how much of the attack actually reached the server. "
              "Detect-only scenarios (mitigation off) log the blocks they *would* have requested "
              "(dry run), so they have no API or switch latency.", "",
              "| scenario | detection (s) | API (ms) | switch confirm (ms) | attack exposure | block requests | renewals | false blocks (benign) |",
              "|---|---|---|---|---|---|---|---|"]
    for name, sm in summary.items():
        a, ms = sm["aggregate"], metrics[name]
        dry = all(m.get("dry_run") for m in ms) and any(m.get("block_requests") for m in ms)
        false_ips = sorted({ip for m in ms for ip in m.get("false_block_ips", [])})
        exp = "-" if a["exposed_share"] is None else f"{pct(a['exposed_share'])} · {cell(a['exposed_s'], '{:.1f}')} s"
        lines.append(f"| {name} | {cell(a['detection_s'])} | {'dry run' if dry else cell(a['api_ms'])} | "
                     f"{cell(a['confirm_ms'])} | {exp} | {cell(a['block_requests'], '{:.0f}')} | "
                     f"{cell(a['renewals'], '{:.0f}')} | {', '.join(false_ips) or 'none'} |")

    lines += ["", "## Per-flow detection on testbed traffic", "",
              "Counts are summed over all runs; rates are computed from the totals.", "",
              "| scenario | flows | TP | FP | FN | TN | recall | precision | FPR |", "|---|---|---|---|---|---|---|---|---|"]
    for name, t in totals.items():
        if not t:
            continue
        if t["tp"] + t["fn"]:
            lines.append(f"| {name} | {t['flows']:,} | {t['tp']:,} | {t['fp']:,} | {t['fn']:,} | {t['tn']:,} | "
                         f"{t['recall']:.3f} | {t['precision']:.3f} | {t['fpr']:.4f} |")
        else:  # recall and precision make no sense without attack flows
            lines.append(f"| {name} | {t['flows']:,} | - | {t['fp']:,} | - | {t['tn']:,} | - | - | {t['fpr']:.4f} |")
    lines += ["", "Per-flow false positives never became blocks unless listed under *false blocks*: the "
              "monitor needs several attack flows from one source before it acts.", ""]

    lines += ["## Benign flows flagged as attack", "",
              "| scenario | flagged (all runs) | zero-payload TCP | fwd-only (no reply) | median duration (ms) |",
              "|---|---|---|---|---|"]
    for name, ms in metrics.items():
        n = sum(m.get("fp_flagged", 0) for m in ms)
        durs = [x for m in ms for x in m.get("fp_durations_ms", [])]
        lines.append(f"| {name} | {n} | {sum(m.get('fp_zero_payload', 0) for m in ms)} | "
                     f"{sum(m.get('fp_fwd_only', 0) for m in ms)} | {np.median(durs):.1f} |" if n else f"| {name} | 0 | - | - | - |")
    lines += ["", "Zero-payload TCP flows carry no request data: connection tails left over when a flow is "
              "closed at FIN (as CICFlowMeter does), and SYN retransmissions from clients whose packets "
              "are being dropped by the flooded link. Both look like the SYN-flood class the model "
              "learned from CIC-DDoS2019.", ""]

    lines += ["## Capture health", "",
              "The live monitor reads its own copy of the traffic (tap); `capture.pcap` is a separate archive "
              "capture. If the monitor cannot keep up, the kernel drops tap packets and its telemetry, "
              "detections and blocks are based on partial data.", "",
              "| scenario | live monitor (tap) dropped | archive capture dropped |", "|---|---|---|"]
    lossy = []
    for name, ms in metrics.items():
        def fmt(key):
            got = sum(m.get(f"{key}_received", 0) for m in ms)
            lost = sum(m.get(f"{key}_dropped", 0) for m in ms)
            return "-" if not got else f"{lost:,} of {got:,} ({lost / got:.1%})"
        lines.append(f"| {name} | {fmt('tap')} | {fmt('archive')} |")
        if sum(m.get("tap_dropped", 0) for m in ms):
            lossy.append(name)
    if lossy:
        lines += ["", f"**{', '.join(lossy)}: the live monitor lost packets**, so their telemetry (attack-traffic "
                  "figure, exposure) and detection timing are lower bounds. Per-flow results use the "
                  "loss-free archive capture."]
    lines += ["", "![attack traffic](attack_traffic.png)", "", "![availability](availability.png)", "",
              "![latency](latency_cdf.png)", "", "![confusion](confusion_matrices.png)", ""]
    (out_dir / "summary.md").write_text("\n".join(lines))
    print(f"wrote {out_dir}/summary.md and figures ({len(scenarios)} scenarios, up to {n_reps} run(s) each)")


if __name__ == "__main__":
    main()
