"""Offline: convert a captured pcap into flow features and (optionally) model predictions.

Produces exactly the FEATURES schema the models were trained on, so a flow CSV/parquet
written here can be fed straight to the model, or appended to training data via
`ml/train.py --extra-flows`.

    uv run python traffic/pcap_to_flows.py results/runs/foo/capture.pcap \
        --out results/runs/foo/flows.parquet --model models/random_forest.joblib
"""

import argparse
import sys
import time
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ddos.features import fix_rates
from ddos.flowmeter import FlowMeter
from ddos.pcapio import iter_packets


def pcap_to_frame(path: str, flow_timeout: float = 120.0) -> pd.DataFrame:
    meter = FlowMeter(flow_timeout=flow_timeout)
    records, packets = [], 0
    t0 = time.time()
    with open(path, "rb") as fh:
        for pkt in iter_packets(fh):
            packets += 1
            for flow in meter.add(pkt):
                records.append(flow.record())
    for flow in meter.flush():
        records.append(flow.record())
    df = pd.DataFrame.from_records(records)
    if len(df):
        fix_rates(df)
    print(f"{packets:,} packets -> {len(df):,} flows in {time.time() - t0:.1f}s", file=sys.stderr)
    return df


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--out", required=True)
    ap.add_argument("--model", help="optional model bundle; adds attack_proba / predicted_attack")
    ap.add_argument("--label", help="attach this ground-truth Label column to every flow")
    ap.add_argument("--attackers", help="comma-separated attacker IPs: flows from them get "
                    "--attack-label, all others BENIGN (use for mixed captures)")
    ap.add_argument("--attack-label", default="Testbed-flood")
    ap.add_argument("--flow-timeout", type=float, default=120.0)
    args = ap.parse_args()

    df = pcap_to_frame(args.pcap, args.flow_timeout)
    if len(df) == 0:
        print("no IPv4 TCP/UDP flows found", file=sys.stderr)
    if args.label and args.attackers:
        ap.error("use either --label (whole capture) or --attackers (per source IP), not both")
    if args.label:
        df["Label"] = args.label
    elif args.attackers and len(df):
        attackers = {ip.strip() for ip in args.attackers.split(",") if ip.strip()}
        df["Label"] = df["Source IP"].isin(attackers).map({True: args.attack_label, False: "BENIGN"})
        print(f"labelled {(df['Label'] != 'BENIGN').sum():,} attack / "
              f"{(df['Label'] == 'BENIGN').sum():,} benign flows", file=sys.stderr)
    if args.model and len(df):
        from ddos.model_io import load_bundle

        bundle = load_bundle(args.model)
        df["attack_proba"] = bundle.predict_proba(df)
        df["predicted_attack"] = (df["attack_proba"] >= bundle.threshold).astype(int)
        print(f"model {bundle.name}: {df['predicted_attack'].mean():.1%} of flows flagged as attack", file=sys.stderr)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.suffix == ".csv":
        df.to_csv(out, index=False)
    else:
        df.to_parquet(out, index=False)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
