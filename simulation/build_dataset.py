"""Merge collected sessions into one labelled, cleaned flow dataset.

    uv run python simulation/build_dataset.py simulation/data/<collection>
    uv run python simulation/build_dataset.py simulation/data/runs --from-runs results/runs

Labels come from each session's record, not from the packets: in a session with an attack,
flows started by an attacker host (the flow's Source IP, the sender of its first packet)
get that session's attack label; every other flow is BENIGN.

In-progress snapshots (--snapshots, default 1,2,5,10 s): the live monitor does not wait for
a flow to end, it scores flows while they still run. A dataset of finished flows only teaches
a model what a 30-second flood flow looks like at the end, and that model cannot recognise
the same flow 2 seconds in. So each capture is replayed and every flow still running at those
ages is also recorded as it looked then (column `snapshot_s`; 0 = the finished flow), with
the same label. Benign flows get snapshots too, so a snapshot says nothing about the class.
Evaluation uses finished flows only (snapshot_s == 0), the same unit as CIC-DDoS2019.
--snapshots "" turns this off.

Cleaning follows the CIC-DDoS2019 steps (ml/clean.py) so the two datasets are prepared the
same way: rows with a non-finite feature are dropped, and duplicate (features, label) rows
are removed. --from-runs imports the testbed experiment runs (results/runs/...) as sessions,
a quick way to try the comparison before collecting.

Writes <collection>/dataset.parquet and dataset_summary.md / .json.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

from ddos.features import FEATURES, LABEL_COL, fix_rates
from ddos.flowmeter import FlowMeter
from ddos.pcapio import iter_packets
from plan import ATTACK_LABELS, BENIGN

META = ["session", "rep", "scenario", "source", "snapshot_s", "Source IP", "Destination IP", "Destination Port",
        "start_ts"]
DEFAULT_SNAPSHOTS = "1,2,5,10"


def label_flows(flows: pd.DataFrame, attacker_ips: list[str], label: str) -> pd.Series:
    if label == BENIGN or not attacker_ips:
        return pd.Series(BENIGN, index=flows.index)
    return flows["Source IP"].isin(attacker_ips).map({True: label, False: BENIGN})


def snapshot_flows(pcap: Path, ages: list[float]) -> pd.DataFrame:
    """Every flow as it looked `ages` seconds after its first packet (only flows still
    running then, with at least 2 packets). One record per flow and age."""
    meter, nxt, recs = FlowMeter(), {}, []
    with open(pcap, "rb") as fh:
        for pkt in iter_packets(fh):
            meter.add(pkt)
            flow = meter.active.get(meter._key(pkt))
            if flow is None:  # it just ended (FIN); finished flows are already in flows.parquet
                continue
            fid = (flow.src, flow.sport, flow.dst, flow.dport, flow.proto, flow.start)
            i = nxt.get(fid, 0)
            if i >= len(ages) or pkt.ts - flow.start < ages[i]:
                continue
            while i < len(ages) and pkt.ts - flow.start >= ages[i]:
                i += 1
            nxt[fid] = i
            if flow.packets >= 2:
                recs.append({**flow.record(), "snapshot_s": ages[i - 1]})
    df = pd.DataFrame.from_records(recs)
    if len(df):
        fix_rates(df)
    return df


def from_collection(coll: Path, ages: list[float]) -> list[pd.DataFrame]:
    parts = []
    for meta_f in sorted((coll / "sessions").glob("*/session.json")):
        meta = json.loads(meta_f.read_text())
        flows_f = meta_f.parent / "flows.parquet"
        if not flows_f.exists():
            print(f"  {meta['id']}: no flows.parquet, skipped", file=sys.stderr)
            continue
        df = pd.read_parquet(flows_f).assign(snapshot_s=0.0)
        pcap = meta_f.parent / "capture.pcap"
        if ages and pcap.exists():
            snaps = snapshot_flows(pcap, ages)
            df = pd.concat([df, snaps], ignore_index=True) if len(snaps) else df
        elif ages:
            print(f"  {meta['id']}: no capture.pcap, finished flows only", file=sys.stderr)
        if df.empty:
            continue
        df[LABEL_COL] = label_flows(df, meta.get("attacker_ips", []), meta["label"])
        parts.append(df.assign(session=meta["id"], rep=meta["rep"], scenario=meta["name"], source="simulation"))
        print(f"  {meta['id']}: {int((df['snapshot_s'] == 0).sum()):,} flows + "
              f"{int((df['snapshot_s'] > 0).sum()):,} snapshots", flush=True)
    return parts


def from_runs(runs: Path) -> list[pd.DataFrame]:
    """Testbed runs: results/runs/<scenario>[/rep<k>]/{scenario.json, flows.parquet}."""
    parts = []
    for meta_f in sorted(runs.glob("**/scenario.json")):
        run = meta_f.parent
        if not (run / "flows.parquet").exists():
            continue
        meta = json.loads(meta_f.read_text())
        attack = (meta.get("config") or {}).get("attack")
        if meta.get("mode") == "session":  # interactive sessions have no single label
            continue
        label = ATTACK_LABELS.get(attack, BENIGN) if attack else BENIGN
        df = pd.read_parquet(run / "flows.parquet")
        if df.empty:
            continue
        df[LABEL_COL] = label_flows(df, meta.get("attacker_ips", []), label)
        df["snapshot_s"] = 0.0
        name = str(run.relative_to(runs)).replace("/", "_")
        parts.append(df.assign(session=f"run_{name}", rep=meta.get("repeat", 1), scenario=meta.get("scenario", name),
                               source="experiment"))
    return parts


def clean(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    steps = {"flows": len(df)}
    X = df[FEATURES].to_numpy(dtype=np.float64)
    df = df[np.isfinite(X).all(axis=1)]
    steps["finite"] = len(df)
    df = df.drop_duplicates(subset=FEATURES + [LABEL_COL])
    steps["deduplicated"] = len(df)
    return df.reset_index(drop=True), steps


def summarize(df: pd.DataFrame, steps: dict) -> tuple[str, dict]:
    snaps = df[df["snapshot_s"] > 0]
    df = df[df["snapshot_s"] == 0]  # tables count finished flows, the CIC-DDoS2019 unit
    by_label = df[LABEL_COL].value_counts()
    by_session = df.groupby(["session", LABEL_COL]).size().unstack(fill_value=0)
    proto = df.groupby([LABEL_COL, "Protocol"]).size().unstack(fill_value=0).rename(columns={6: "TCP", 17: "UDP"})
    summary = {"flows": len(df), "cleaning": steps, "labels": by_label.to_dict(),
               "sessions": int(df["session"].nunique()), "reps": sorted(map(int, df["rep"].unique())),
               "sources": df["source"].value_counts().to_dict(),
               "snapshots": {"rows": len(snaps), "by_age": snaps["snapshot_s"].value_counts().sort_index().to_dict(),
                             "by_label": snaps[LABEL_COL].value_counts().to_dict()}}
    lines = ["# Collected dataset", "",
             f"{len(df):,} flows from {summary['sessions']} sessions "
             f"({', '.join(f'{k}: {v}' for k, v in summary['sources'].items())}).", "",
             f"Cleaning: {steps['flows']:,} flows → {steps['finite']:,} with finite features → "
             f"{steps['deduplicated']:,} after removing duplicate (features, label) rows "
             f"(finished flows and in-progress snapshots together).", "",
             f"In-progress snapshots (training only): {len(snaps):,} rows"
             + (" at " + ", ".join(f"{a:g} s: {n:,}" for a, n in summary["snapshots"]["by_age"].items()) if len(snaps) else "")
             + ". The tables below count finished flows.", "",
             "| label | flows | share |", "|---|---:|---:|",
             *[f"| {k} | {v:,} | {v / len(df):.1%} |" for k, v in by_label.items()], "",
             "## Protocol per label", "", "| label | " + " | ".join(map(str, proto.columns)) + " |",
             "|---|" + "---:|" * len(proto.columns),
             *[f"| {k} | " + " | ".join(f"{int(v):,}" for v in r) + " |" for k, r in proto.iterrows()], "",
             "## Flows per session", "", "| session | " + " | ".join(by_session.columns) + " |",
             "|---|" + "---:|" * len(by_session.columns),
             *[f"| {k} | " + " | ".join(f"{int(v):,}" for v in r) + " |" for k, r in by_session.iterrows()], ""]
    return "\n".join(lines), summary


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("collection", help="collection directory (output goes here)")
    ap.add_argument("--from-runs", help="also import testbed experiment runs from this directory")
    ap.add_argument("--snapshots", default=DEFAULT_SNAPSHOTS,
                    help='flow ages (s) at which running flows are also recorded; "" = finished flows only')
    args = ap.parse_args()
    coll = Path(args.collection)
    coll.mkdir(parents=True, exist_ok=True)
    ages = sorted(float(a) for a in args.snapshots.split(",") if a.strip())
    parts = from_collection(coll, ages)
    if args.from_runs:
        parts += from_runs(Path(args.from_runs))
    if not parts:
        sys.exit("no sessions with flows found")
    df = pd.concat(parts, ignore_index=True)
    df, steps = clean(df)
    df = df[FEATURES + [LABEL_COL] + [c for c in META if c in df.columns]]
    df.to_parquet(coll / "dataset.parquet", index=False)
    text, summary = summarize(df, steps)
    (coll / "dataset_summary.md").write_text(text)
    (coll / "dataset_summary.json").write_text(json.dumps(summary, indent=2, default=int))
    print(f"wrote {coll / 'dataset.parquet'}: {summary['flows']:,} finished flows "
          f"({', '.join(f'{k} {v:,}' for k, v in summary['labels'].items())}) "
          f"+ {summary['snapshots']['rows']:,} in-progress snapshots")


if __name__ == "__main__":
    main()
