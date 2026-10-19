"""Stream CIC-DDoS2019 CSVs out of the zip and build a class-balanced sample.

The archive is ~22 GB uncompressed, so it is never extracted. Each CSV is read in
chunks; every row gets a uniform random key and, per label, the K rows with the
smallest keys are kept (bottom-K = uniform sample without replacement in one pass).
Rare labels (BENIGN, WebDDoS) are kept entirely because K exceeds their count.

While streaming, population statistics are collected over *all* rows: label
counts per file, NaN / +-inf counts per column, and negative-value counts.

Usage:
    uv run python ml/prepare_data.py --zip dataset/raw/CSV-01-12.zip
"""

import argparse
import json
import time
import zipfile
import zlib
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DROP_ON_READ = ["Unnamed: 0", "Flow ID", "SimillarHTTP"]


def _bottom_k(df: pd.DataFrame, k: int) -> pd.DataFrame:
    if len(df) <= k:
        return df
    idx = np.argpartition(df["_key"].to_numpy(), k - 1)[:k]
    return df.iloc[idx]


def sample_member(zip_path: str, member: str, k: int, chunksize: int, seed: int) -> dict:
    rng = np.random.default_rng([seed, zlib.crc32(member.encode())])
    kept: dict[str, pd.DataFrame] = {}
    labels = Counter()
    nan = Counter()
    pos_inf = Counter()
    neg_inf = Counter()
    negative = Counter()
    rows = 0
    t0 = time.time()
    with zipfile.ZipFile(zip_path) as zf, zf.open(member) as fh:
        for chunk in pd.read_csv(fh, chunksize=chunksize, low_memory=False):
            chunk.columns = chunk.columns.str.strip()
            chunk = chunk.drop(columns=[c for c in DROP_ON_READ if c in chunk.columns])
            rows += len(chunk)
            labels.update(chunk["Label"].value_counts().to_dict())
            num = chunk.select_dtypes("number")
            arr = num.to_numpy(dtype=float)
            for col, n_nan, n_pinf, n_ninf, n_neg in zip(
                num.columns,
                np.isnan(arr).sum(0),
                np.isposinf(arr).sum(0),
                np.isneginf(arr).sum(0),
                (arr < 0).sum(0),
            ):
                nan[col] += int(n_nan)
                pos_inf[col] += int(n_pinf)
                neg_inf[col] += int(n_ninf)
                negative[col] += int(n_neg)
            chunk["_key"] = rng.random(len(chunk))
            chunk["_source_file"] = Path(member).name
            for label, part in chunk.groupby("Label", sort=False):
                prev = kept.get(label)
                part = part if prev is None else pd.concat([prev, part], ignore_index=True)
                kept[label] = _bottom_k(part, k)
    sample = pd.concat(kept.values(), ignore_index=True)
    return {
        "member": member,
        "rows": rows,
        "seconds": round(time.time() - t0, 1),
        "labels": dict(labels),
        "nan": dict(nan),
        "pos_inf": dict(pos_inf),
        "neg_inf": dict(neg_inf),
        "negative": dict(negative),
        "sample": sample,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--zip", default=str(ROOT / "dataset/raw/CSV-01-12.zip"))
    ap.add_argument("--out", default=str(ROOT / "dataset/processed/sampled.parquet"))
    ap.add_argument("--stats", default=str(ROOT / "results/data/raw_stats.json"))
    ap.add_argument("--per-label", type=int, default=150_000, help="rows kept per label (K)")
    ap.add_argument("--chunksize", type=int, default=250_000)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    with zipfile.ZipFile(args.zip) as zf:
        members = [m.filename for m in zf.infolist() if m.filename.endswith(".csv")]
    # Biggest first so the long TFTP file starts immediately.
    with zipfile.ZipFile(args.zip) as zf:
        members.sort(key=lambda m: zf.getinfo(m).file_size, reverse=True)

    results = []
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = [
            pool.submit(sample_member, args.zip, m, args.per_label, args.chunksize, args.seed)
            for m in members
        ]
        for fut in as_completed(futures):
            res = fut.result()
            print(f"{res['member']}: {res['rows']:,} rows in {res['seconds']}s {res['labels']}", flush=True)
            results.append(res)

    # Per-file bottom-K -> global bottom-K per label (exact, keys are i.i.d. uniform).
    sample = pd.concat([r.pop("sample") for r in results], ignore_index=True)
    sample = (
        pd.concat([_bottom_k(g, args.per_label) for _, g in sample.groupby("Label", sort=False)])
        .drop(columns="_key")
        .reset_index(drop=True)
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    sample.to_parquet(out, index=False)

    totals = defaultdict(Counter)
    for r in results:
        for key in ("labels", "nan", "pos_inf", "neg_inf", "negative"):
            totals[key].update(r[key])
    stats = {
        "total_rows": sum(r["rows"] for r in results),
        "per_file": {r["member"]: {"rows": r["rows"], "labels": r["labels"]} for r in results},
        **{k: dict(v.most_common()) for k, v in totals.items()},
        "sample_rows": len(sample),
        "sample_labels": sample["Label"].value_counts().to_dict(),
        "per_label_k": args.per_label,
        "seed": args.seed,
    }
    Path(args.stats).parent.mkdir(parents=True, exist_ok=True)
    Path(args.stats).write_text(json.dumps(stats, indent=2))
    print(f"wrote {out} ({len(sample):,} rows) and {args.stats}")


if __name__ == "__main__":
    main()
