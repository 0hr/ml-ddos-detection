"""Inspect and clean the sampled CIC-DDoS2019 data.

Inputs : dataset/processed/sampled.parquet, results/data/raw_stats.json (ml/prepare_data.py)
Outputs: dataset/processed/clean.parquet   model-ready rows (FEATURES + META_COLS + Label)
         results/data/eda_report.md        attack types, columns, missing/inf, imbalance
         results/data/*.png                figures

Usage:
    uv run python ml/clean.py
"""

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from ddos.features import BENIGN, FEATURES, LABEL_COL, META_COLS, SUPPORTED_PROTOCOLS, fix_rates

ROOT = Path(__file__).resolve().parents[1]

DROP_REASONS = {
    "Unnamed: 0": "row index of the original export",
    "Flow ID": "identifier (5-tuple string)",
    "SimillarHTTP": "dataset-specific string, mostly 0",
    "Source IP": "identifier, kept as metadata only",
    "Source Port": "identifier, kept as metadata only",
    "Destination IP": "identifier, kept as metadata only",
    "Destination Port": "identifier, kept as metadata only (attack-specific in CIC, would not transfer)",
    "Timestamp": "identifier, kept as metadata only",
    "Inbound": "testbed-specific direction flag",
    "Fwd Header Length": "CICFlowMeter bug (negative values for UDP)",
    "Bwd Header Length": "CICFlowMeter bug (negative values for UDP)",
    "Fwd Header Length.1": "duplicate of Fwd Header Length",
    "min_seg_size_forward": "derived from header length, unreliable",
    "act_data_pkt_fwd": "inconsistent (0 for UDP flows with payload)",
    "Subflow Fwd Packets": "identical to Total Fwd Packets",
    "Subflow Fwd Bytes": "identical to Total Length of Fwd Packets",
    "Subflow Bwd Packets": "identical to Total Backward Packets",
    "Subflow Bwd Bytes": "identical to Total Length of Bwd Packets",
    "Active Mean": "depends on CICFlowMeter 5 s activity timeout, not reproduced",
    "Active Std": "depends on CICFlowMeter 5 s activity timeout, not reproduced",
    "Active Max": "depends on CICFlowMeter 5 s activity timeout, not reproduced",
    "Active Min": "depends on CICFlowMeter 5 s activity timeout, not reproduced",
    "Idle Mean": "depends on CICFlowMeter 5 s activity timeout, not reproduced",
    "Idle Std": "depends on CICFlowMeter 5 s activity timeout, not reproduced",
    "Idle Max": "depends on CICFlowMeter 5 s activity timeout, not reproduced",
    "Idle Min": "depends on CICFlowMeter 5 s activity timeout, not reproduced",
}
FLAG_COLS = [
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
]
BULK_COLS = [
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
]
# Init_Win_* use -1 for "no packet in that direction"; any other negative is corrupt.
NEGATIVE_OK = {"Init_Win_bytes_forward", "Init_Win_bytes_backward"}


def md_table(df: pd.DataFrame) -> str:
    cols = [str(c) for c in df.columns]
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for row in df.itertuples(index=False):
        cells = [f"{v:,}" if isinstance(v, (int, np.integer)) else
                 f"{v:.4g}" if isinstance(v, (float, np.floating)) else str(v) for v in row]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sample", default=str(ROOT / "dataset/processed/sampled.parquet"))
    ap.add_argument("--stats", default=str(ROOT / "results/data/raw_stats.json"))
    ap.add_argument("--out", default=str(ROOT / "dataset/processed/clean.parquet"))
    ap.add_argument("--report-dir", default=str(ROOT / "results/data"))
    args = ap.parse_args()

    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    stats = json.loads(Path(args.stats).read_text())
    df = pd.read_parquet(args.sample)
    rep: list[str] = ["# CIC-DDoS2019 (01-12) - data inspection and cleaning report", ""]

    # 1. Attack types -------------------------------------------------------------
    pop = pd.Series(stats["labels"], name="rows").sort_values(ascending=False)
    per_file = pd.DataFrame(
        {Path(f).name: v["labels"] for f, v in stats["per_file"].items()}
    ).fillna(0).astype(int)
    rep += [
        "## 1. Attack types",
        f"Total rows in the 11 CSV files: **{stats['total_rows']:,}**. "
        f"Distinct labels: **{len(pop)}** ({len(pop) - 1} attack types + BENIGN).",
        "",
        md_table(pop.rename_axis("Label").reset_index().assign(
            share=lambda d: d["rows"] / d["rows"].sum())),
        "",
        "Labels found per source file (each file is dominated by its own attack, "
        "BENIGN rows are spread across files):",
        "",
        md_table(per_file.rename_axis("Label").reset_index()),
        "",
    ]

    # 2. Columns ------------------------------------------------------------------
    flag_by_label = df.groupby(LABEL_COL)[["SYN Flag Count", "ACK Flag Count"]].mean()
    reasons = dict(DROP_REASONS)
    reasons.update({c: "CICFlowMeter flag counting is unreliable (see table below)" for c in FLAG_COLS})
    reasons.update({
        c: f"bulk feature, {'constant 0' if (df[c] == 0).all() else 'almost always 0'} in the sample"
        for c in BULK_COLS
    })
    all_cols = [c for c in df.columns if not c.startswith("_")] + ["Unnamed: 0", "Flow ID", "SimillarHTTP"]
    col_rows = []
    for c in all_cols:
        if c == LABEL_COL:
            status, why = "target", "attack label"
        elif c in FEATURES:
            status, why = "feature", "reproducible from pcap by ddos.flowmeter"
        else:
            status, why = ("metadata" if c in META_COLS else "dropped"), reasons.get(c, "not reproducible")
        col_rows.append((c, status, why))
    col_df = pd.DataFrame(col_rows, columns=["column", "status", "reason"])
    rep += [
        "## 2. Columns",
        f"The CSVs have 88 columns. **{len(FEATURES)}** are used as model features; "
        "the rest are identifiers (kept as metadata for inspection) or dropped:",
        "",
        md_table(col_df),
        "",
        "Why flag counts are dropped - mean SYN/ACK flag count per label in the sample "
        "(a SYN flood with SYN=0 and ACK=1 shows the counters are wrong):",
        "",
        md_table(flag_by_label.reset_index()),
        "",
    ]

    # 3. Missing / infinite values (population) --------------------------------------
    total = stats["total_rows"]
    bad = pd.DataFrame({
        "NaN": pd.Series(stats["nan"]),
        "+inf": pd.Series(stats["pos_inf"]),
        "-inf": pd.Series(stats["neg_inf"]),
    }).fillna(0).astype(int)
    bad = bad[(bad > 0).any(axis=1)]
    bad["share_of_rows"] = bad.sum(axis=1) / total
    neg = pd.Series(stats["negative"])
    neg = neg[(neg > 0) & neg.index.isin(FEATURES) & ~neg.index.isin(NEGATIVE_OK)]

    zero_dur = int((df["Flow Duration"] == 0).sum())
    rep += [
        "## 3. Missing and infinite values",
        "Counts over the full population (all rows of all files):",
        "",
        md_table(bad.rename_axis("column").reset_index()),
        "",
        "All NaN/inf values come from flows with `Flow Duration == 0`: CICFlowMeter divides "
        "bytes and packets by a zero duration (0/0 = NaN, x/0 = inf), while `Fwd/Bwd Packets/s` "
        "are written as 0 for the same rows. Rates for those flows are recomputed with a 1 us "
        "duration floor (`ddos.features.fix_rates`); the identical convention is used by the pcap "
        "flow meter, so training and inference agree. For every other row the recomputed rates "
        "equal the CSV values exactly.",
        "",
        f"Zero-duration flows in the sample: {zero_dur:,} ({zero_dur / len(df):.2%}).",
        "",
        "Negative values in model features (population; `Init_Win_bytes_* = -1` is a valid "
        "'no packet' marker and excluded):",
        "",
        md_table(neg.rename("rows").rename_axis("column").reset_index()) if len(neg) else "none",
        "",
    ]

    # 4. Cleaning -----------------------------------------------------------------
    steps = [("sampled rows", len(df))]
    df = df[df["Protocol"].isin(SUPPORTED_PROTOCOLS)].copy()
    steps.append(("keep TCP/UDP only (Protocol 0 = unparsed traffic)", len(df)))
    df[FEATURES] = df[FEATURES].astype("float64")
    fix_rates(df)
    feat = df[FEATURES].to_numpy()
    finite = np.isfinite(feat).all(axis=1)
    df = df[finite]
    steps.append(("drop rows still containing NaN/inf", len(df)))
    neg_mask = np.zeros(len(df), dtype=bool)
    for c in FEATURES:
        if c in NEGATIVE_OK:
            neg_mask |= df[c].to_numpy() < -1
        else:
            neg_mask |= df[c].to_numpy() < 0
    df = df[~neg_mask]
    steps.append(("drop rows with impossible negative values", len(df)))
    df = df.drop_duplicates(subset=FEATURES + [LABEL_COL])
    steps.append(("drop duplicate (features, label) rows", len(df)))

    is_attack = df[LABEL_COL] != BENIGN
    by_vec = df.assign(_atk=is_attack).groupby(FEATURES, sort=False)["_atk"].agg(["min", "max"])
    conflicts = int(((by_vec["min"] == 0) & (by_vec["max"] == 1)).sum())
    rep += [
        "## 4. Cleaning steps (on the sample)",
        "",
        md_table(pd.DataFrame(steps, columns=["step", "rows remaining"])),
        "",
        f"Feature vectors that appear with both a BENIGN and an attack label: **{conflicts:,}**. "
        "They are kept (they are genuinely ambiguous) and bound the achievable accuracy.",
        "",
    ]

    # 5. Class imbalance --------------------------------------------------------------
    pop_benign = int(pop.get(BENIGN, 0))
    clean_counts = df[LABEL_COL].value_counts()
    n_benign = int(clean_counts.get(BENIGN, 0))
    imb = pd.DataFrame({
        "population": pop,
        "sample": pd.Series(stats["sample_labels"]),
        "clean": clean_counts,
    }).fillna(0).astype(int).sort_values("population", ascending=False)
    rep += [
        "## 5. Class imbalance",
        f"Population: {pop_benign:,} BENIGN vs {total - pop_benign:,} attack rows - "
        f"imbalance ratio **1 : {(total - pop_benign) / max(pop_benign, 1):,.0f}**.",
        "",
        f"Handling: (a) per-label uniform sampling with K = {stats['per_label_k']:,} rows "
        "(rare labels kept entirely), which also balances the attack types against each other; "
        f"(b) class weights in training. After cleaning: {n_benign:,} BENIGN vs "
        f"{len(df) - n_benign:,} attack rows (1 : {(len(df) - n_benign) / max(n_benign, 1):.1f}).",
        "",
        md_table(imb.rename_axis("Label").reset_index()),
        "",
    ]

    # Figures ---------------------------------------------------------------------
    fig, ax = plt.subplots(1, 2, figsize=(13, 4.5))
    imb["population"].plot.barh(ax=ax[0], logx=True, color="#4C72B0")
    ax[0].set_title("Rows per label - full dataset (log scale)")
    ax[0].invert_yaxis()
    imb["clean"].plot.barh(ax=ax[1], color="#55A868")
    ax[1].set_title("Rows per label - cleaned training sample")
    ax[1].invert_yaxis()
    fig.tight_layout()
    fig.savefig(report_dir / "class_distribution.png", dpi=130)
    plt.close(fig)

    if len(bad):
        fig, ax = plt.subplots(figsize=(7, 3))
        bad[["NaN", "+inf", "-inf"]].plot.barh(ax=ax, stacked=True)
        ax.set_title("NaN / inf values per column (full dataset)")
        ax.set_xlabel("rows")
        fig.tight_layout()
        fig.savefig(report_dir / "missing_infinite.png", dpi=130)
        plt.close(fig)
    rep += ["![class distribution](class_distribution.png)", "", "![missing/inf](missing_infinite.png)", ""]

    keep = FEATURES + [c for c in META_COLS if c in df.columns] + [LABEL_COL, "_source_file"]
    out = Path(args.out)
    df[keep].reset_index(drop=True).to_parquet(out, index=False)
    (report_dir / "eda_report.md").write_text("\n".join(rep))
    print("\n".join(f"{s}: {n:,}" for s, n in steps))
    print(f"wrote {out} and {report_dir / 'eda_report.md'}")


if __name__ == "__main__":
    main()
