"""Train a deployable model on CIC-DDoS2019 + the collected dataset (or the collected one alone).

    uv run python simulation/train_model.py                    # CIC + newest collection, evaluated
    uv run python simulation/train_model.py --all-reps         # the same, final model on every rep
    uv run python simulation/train_model.py --mode sim         # collected data only

The model is the project's Random Forest (ml/train.py settings), saved with its feature
schema like the main model, so the monitor, the experiments and the live session can use it
directly:

    sudo python3 testbed/live.py --model models/random_forest_cic_sim.joblib
    sudo python3 testbed/run_experiment.py --model models/random_forest_cic_sim.joblib

It never overwrites models/random_forest.joblib.

The collected data is split the way simulation/compare.py splits it: by repetition, not by
flow, because flows of one session are near-copies of each other. By default the last
repetition is held out and the report shows how the model does on it. --all-reps trains the
final model on every repetition (keeping 20 % of the flows for the threshold); it has no
held-out collected test set, so run it after the evaluated one. CIC-DDoS2019 always uses the
ml/train.py split, so its test set is never trained on.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "ml"))
sys.path.insert(0, str(HERE))

import plotstyle as S
from compare import evaluate, fit_rf, sim_split
from ddos.features import BENIGN, FEATURES, LABEL_COL, binary_target
from ddos.model_io import build_schema, load_bundle, save_bundle
from report import split

CIC, SIM = "CIC-DDoS2019", "Simulated"


def stratified_val(labels: np.ndarray, share: float, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    mask = np.zeros(len(labels), bool)
    for lab in np.unique(labels):
        idx = np.flatnonzero(labels == lab)
        mask[rng.choice(idx, size=max(1, round(share * len(idx))), replace=False)] = True
    return mask


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sim", help="collected dataset.parquet (default: newest collection)")
    ap.add_argument("--cic", default=str(ROOT / "dataset/processed/clean.parquet"))
    ap.add_argument("--mode", choices=["combined", "sim"], default="combined",
                    help="combined = CIC-DDoS2019 + collected (default), sim = collected only")
    ap.add_argument("--all-reps", action="store_true", help="final model: train on every collected repetition")
    ap.add_argument("--test-rep", type=int, help="collected repetition held out for evaluation (default: last)")
    ap.add_argument("--name", help="model name (default random_forest_cic_sim or random_forest_sim)")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    sim_path = Path(args.sim) if args.sim else None
    if sim_path is None:
        latest = HERE / "data/latest.json"
        if not latest.exists():
            sys.exit("no --sim given and no collection yet: run simulation/collect.py first")
        sim_path = Path(json.loads(latest.read_text())["collection"]) / "dataset.parquet"
    name = args.name or ("random_forest_cic_sim" if args.mode == "combined" else "random_forest_sim")
    if name == "random_forest":
        sys.exit("refusing to overwrite the main model models/random_forest.joblib; pick another --name")

    sim = pd.read_parquet(sim_path).reset_index(drop=True)
    if "snapshot_s" not in sim:
        sim["snapshot_s"] = 0.0
    finished = sim["snapshot_s"].to_numpy() == 0  # in-progress snapshots train, never test
    cic = pd.read_parquet(args.cic)
    X = lambda df, idx: df[FEATURES].iloc[idx].astype("float64")
    y = lambda df, idx: binary_target(df[LABEL_COL].iloc[idx])
    lab = lambda df, idx: df[LABEL_COL].iloc[idx].to_numpy()

    c_va, c_te = split(cic, args.seed)
    c_tr = np.setdiff1d(np.arange(len(cic)), np.r_[c_va, c_te])
    if args.all_reps:
        val_mask = stratified_val(sim[LABEL_COL].to_numpy(), 0.2, args.seed)
        s_tr, s_va, s_te = np.flatnonzero(~val_mask), np.flatnonzero(val_mask), np.array([], int)
        how = "every repetition used for training (20 % of the flows kept for the threshold); no collected test set"
    else:
        s_tr, s_va, s_te, how = sim_split(sim, args.test_rep, args.seed)
        s_te = s_te[finished[s_te]]

    if args.mode == "combined":
        X_tr, y_tr = pd.concat([X(cic, c_tr), X(sim, s_tr)]), np.r_[y(cic, c_tr), y(sim, s_tr)]
        X_va, y_va = pd.concat([X(cic, c_va), X(sim, s_va)]), np.r_[y(cic, c_va), y(sim, s_va)]
    else:
        X_tr, y_tr, X_va, y_va = X(sim, s_tr), y(sim, s_tr), X(sim, s_va), y(sim, s_va)
    print(f"collected data ({sim_path}): {how}")
    print(f"training {name} on {len(X_tr):,} flows ({args.mode}) ...", flush=True)
    t0 = time.time()
    model, threshold = fit_rf(X_tr, y_tr, X_va, y_va, args.seed)
    fit_s = time.time() - t0

    results = []
    tests = [(CIC, cic, c_te)] + ([(SIM, sim, s_te)] if len(s_te) else [])
    for test_name, df, idx in tests:
        results.append(evaluate(args.mode, test_name, y(df, idx), model.predict_proba(X(df, idx))[:, 1], threshold,
                                lab(df, idx)))
    # The main model on the same test sets, for comparison.
    main_model = load_bundle(ROOT / "models/random_forest.joblib")
    baseline = [evaluate("main model", t, y(df, idx), main_model.predict_proba(df.iloc[idx]), main_model.threshold,
                         lab(df, idx)) for t, df, idx in tests]

    metrics = {"mode": args.mode, "sim_dataset": str(sim_path), "split": how, "fit_seconds": round(fit_s, 1),
               "train_flows": len(X_tr), "cic_train_flows": len(c_tr) if args.mode == "combined" else 0,
               "sim_train_flows": len(s_tr), "threshold": threshold,
               "test": {r["test"]: {k: r[k] for k in ("accuracy", "precision", "recall", "f1", "fpr", "roc_auc",
                                                      "pr_auc", "per_label")} for r in results}}
    out = ROOT / "models" / f"{name}.joblib"
    save_bundle(out, model, name, threshold, build_schema(X_tr), metrics)

    header = ["test set", "model", "accuracy", "precision", "recall", "F1", "FPR"]
    rows = []
    for r_new, r_old in zip(results, baseline):
        for r, who in ((r_old, "main model (CIC only)"), (r_new, name)):
            rows.append([r["test"], who, f"{r['accuracy']:.4f}", f"{r['precision']:.4f}", f"{r['recall']:.4f}",
                         f"{r['f1']:.4f}", f"{r['fpr']:.2%}"])
    md = [f"# {name}", "",
          f"Random Forest (ml/train.py settings) trained on {len(X_tr):,} flows: "
          + (f"{len(c_tr):,} from CIC-DDoS2019 + {len(s_tr):,} collected." if args.mode == "combined"
             else f"{len(s_tr):,} collected."), "",
          f"Collected data: `{sim_path}`; {how}.", f"Threshold {threshold:.2f} (validation, max TPR − FPR with FPR ≤ 1 %). "
          f"Training took {fit_s:.0f} s.", "", "## Test results, against the main model", "", S.md_table(header, rows), ""]
    if len(s_te):
        sim_res, sim_base = results[-1], baseline[-1]
        labels = sorted(sim_res["per_label"], key=lambda x: (x == BENIGN, x))
        md += ["## Collected test set, per class", "",
               S.md_table(["class", "test flows", "main model", name],
                          [[lb, f"{int((lab(sim, s_te) == lb).sum()):,}", f"{sim_base['per_label'].get(lb, 0):.1%}",
                            f"{sim_res['per_label'].get(lb, 0):.1%}"] for lb in labels]), "",
               "For BENIGN the rate is the false-positive rate; for every other class it is recall.", ""]
    md += ["## Use it", "", "```bash",
           f"sudo python3 testbed/live.py --model models/{name}.joblib",
           f"sudo python3 testbed/run_experiment.py --model models/{name}.joblib", "```", ""]
    report = ROOT / "results/ml" / f"{name}.md"
    report.write_text("\n".join(md))
    (ROOT / "results/ml" / f"{name}.json").write_text(json.dumps(metrics, indent=2, default=float))

    print(f"\nsaved {out.relative_to(ROOT)} (+ .schema.json), report {report.relative_to(ROOT)}\n")
    print(S.md_table(header, rows))
    print(f"\nuse it:  sudo python3 testbed/live.py --model models/{name}.joblib")


if __name__ == "__main__":
    main()
