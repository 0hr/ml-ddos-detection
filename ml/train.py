"""Train the baseline Decision Tree and the main Random Forest (normal vs attack).

Input : dataset/processed/clean.parquet (ml/clean.py)
Output: models/{decision_tree,random_forest}.joblib (+ .schema.json)  model + feature schema
        results/ml/metrics.json, report.md, *.png                       evaluation
        results/ml/false_positives_*.csv                                inspected false positives

Split is stratified by the original label: 70 % train / 15 % validation / 15 % test. The
threshold is tuned on validation: highest TPR - FPR (Youden's J) with a normal false-positive
rate <= --max-fpr (a false positive blocks a real user).

Usage:
    uv run python ml/train.py
    uv run python ml/train.py --extra-flows results/runs/*/flows_labeled.parquet   # add testbed flows
"""

import argparse
import glob
import json
import time
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

from ddos.features import BENIGN, FEATURES, LABEL_COL, binary_target
from ddos.model_io import build_schema, save_bundle

ROOT = Path(__file__).resolve().parents[1]


def make_models(seed: int) -> dict:
    return {
        "decision_tree": DecisionTreeClassifier(
            max_depth=12, min_samples_leaf=5, class_weight="balanced", random_state=seed
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=100,
            max_depth=24,
            min_samples_leaf=2,
            max_features="sqrt",
            class_weight="balanced_subsample",
            n_jobs=-1,
            random_state=seed,
        ),
    }


def tune_threshold(y: np.ndarray, p: np.ndarray, max_fpr: float) -> float:
    """Threshold with the highest TPR - FPR (Youden's J) and FPR <= max_fpr.

    J weighs both kinds of error equally, whatever the class mix. F1 does not: on a split
    that is ~88 % attack it favours recall and picks thresholds that raise the false-positive
    rate a lot for a tiny F1 gain, which is wrong when a false positive blocks a real user.
    Ties go to the threshold nearest 0.5.
    """
    benign, attack = p[y == 0], p[y == 1]
    best_t, best_j = 0.5, -np.inf
    for t in sorted(np.unique(np.round(np.r_[np.linspace(0.05, 0.95, 91), 0.5], 3)), key=lambda t: abs(t - 0.5)):
        fpr = (benign >= t).mean() if len(benign) else 0.0
        if fpr > max_fpr:
            continue
        j = ((attack >= t).mean() if len(attack) else 0.0) - fpr
        if j > best_j + 1e-12:
            best_t, best_j = float(t), j
    return best_t


def scores(y: np.ndarray, p: np.ndarray, t: float) -> dict:
    yhat = (p >= t).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, yhat, labels=[0, 1]).ravel()
    return {
        "threshold": t,
        "accuracy": float((yhat == y).mean()),
        "precision": float(precision_score(y, yhat, zero_division=0)),
        "recall": float(recall_score(y, yhat, zero_division=0)),
        "f1": float(f1_score(y, yhat, zero_division=0)),
        "fpr": float(fp / max(fp + tn, 1)),
        "roc_auc": float(roc_auc_score(y, p)),
        "pr_auc": float(average_precision_score(y, p)),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def load_extra(patterns: list[str]) -> pd.DataFrame:
    paths = sorted({p for pat in patterns for p in glob.glob(pat)})
    if not paths:
        return pd.DataFrame()
    extra = pd.concat([pd.read_parquet(p) for p in paths], ignore_index=True)
    extra["_source_file"] = "testbed"
    print(f"added {len(extra):,} testbed flows from {len(paths)} files")
    return extra


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default=str(ROOT / "dataset/processed/clean.parquet"))
    ap.add_argument("--models-dir", default=str(ROOT / "models"))
    ap.add_argument("--out-dir", default=str(ROOT / "results/ml"))
    ap.add_argument("--max-fpr", type=float, default=0.01)
    ap.add_argument("--extra-flows", nargs="*", default=[], help="labeled testbed flow parquet files/globs")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    out_dir, models_dir = Path(args.out_dir), Path(args.models_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    df = pd.read_parquet(args.data)
    extra = load_extra(args.extra_flows)
    if len(extra):
        df = pd.concat([df, extra[[c for c in df.columns if c in extra.columns]]], ignore_index=True)

    y_all = binary_target(df[LABEL_COL])
    idx = np.arange(len(df))
    tr, rest = train_test_split(idx, test_size=0.30, stratify=df[LABEL_COL], random_state=args.seed)
    va, te = train_test_split(rest, test_size=0.50, stratify=df[LABEL_COL].iloc[rest], random_state=args.seed)
    X = df[FEATURES].astype("float64")
    print(f"train {len(tr):,}  val {len(va):,}  test {len(te):,}  attack share {y_all.mean():.3f}")

    schema = build_schema(X.iloc[tr])
    test_labels = df[LABEL_COL].iloc[te].to_numpy()
    all_metrics = {
        "data": {
            "rows": len(df), "train": len(tr), "val": len(va), "test": len(te),
            "benign_rows": int((y_all == 0).sum()), "attack_rows": int(y_all.sum()),
            "extra_testbed_flows": len(extra),
        },
        "sklearn_version": sklearn.__version__,
        "models": {},
    }
    report = ["# Model training and evaluation", "",
              f"Rows: {len(df):,} (train {len(tr):,} / val {len(va):,} / test {len(te):,}). "
              f"Features: {len(FEATURES)}. Threshold tuned on validation: max TPR - FPR with benign FPR <= {args.max_fpr:.1%}.", "",
              "**Caveat:** the split is random over flows captured on a single day, so near-identical flows "
              "of one attack land in both train and test. These scores measure in-distribution accuracy; "
              "transfer to new traffic is evaluated on the live testbed (results/report).", ""]

    fig_cm, ax_cm = plt.subplots(1, 2, figsize=(10, 4.2))
    fig_roc, ax_roc = plt.subplots(1, 2, figsize=(11, 4.2))
    per_type = {}

    for i, (name, model) in enumerate(make_models(args.seed).items()):
        t0 = time.time()
        model.fit(X.iloc[tr], y_all[tr])
        fit_s = time.time() - t0
        p_val = model.predict_proba(X.iloc[va])[:, 1]
        threshold = tune_threshold(y_all[va], p_val, args.max_fpr)
        t0 = time.time()
        p_test = model.predict_proba(X.iloc[te])[:, 1]
        pred_us = (time.time() - t0) / len(te) * 1e6
        m = {
            "fit_seconds": round(fit_s, 1),
            "predict_us_per_flow": round(pred_us, 2),
            "val": scores(y_all[va], p_val, threshold),
            "test": scores(y_all[te], p_test, threshold),
            "test_at_0.5": scores(y_all[te], p_test, 0.5),
        }
        yhat = p_test >= threshold
        per_type[name] = (
            pd.DataFrame({"label": test_labels, "flagged": yhat})
            .groupby("label")["flagged"].agg(["size", "mean"])
            .rename(columns={"size": "test_rows", "mean": "flagged_as_attack"})
        )
        m["per_label_flagged_rate"] = per_type[name]["flagged_as_attack"].round(5).to_dict()
        if hasattr(model, "feature_importances_"):
            imp = pd.Series(model.feature_importances_, index=FEATURES).sort_values(ascending=False)
            m["feature_importance_top15"] = imp.head(15).round(5).to_dict()
        all_metrics["models"][name] = m

        save_bundle(models_dir / f"{name}.joblib", model, name, threshold, schema, m)

        # False positives / negatives on the test set.
        test_df = df.iloc[te].assign(attack_proba=p_test, predicted_attack=yhat.astype(int))
        fp = test_df[(test_df[LABEL_COL] == BENIGN) & yhat].sort_values("attack_proba", ascending=False)
        fn = test_df[(test_df[LABEL_COL] != BENIGN) & ~yhat]
        fp.to_csv(out_dir / f"false_positives_{name}.csv", index=False)
        tn = test_df[(test_df[LABEL_COL] == BENIGN) & ~yhat]
        inspect_cols = ["Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
                        "Fwd Packet Length Mean", "Flow Packets/s", "Init_Win_bytes_forward",
                        "Init_Win_bytes_backward"]
        comp = pd.DataFrame({
            "false positives (median)": fp[inspect_cols].median(),
            "true negatives (median)": tn[inspect_cols].median(),
            "attacks (median)": test_df[test_df[LABEL_COL] != BENIGN][inspect_cols].median(),
        })
        s = m["test"]
        report += [
            f"## {name}", "",
            f"Fit {fit_s:.0f} s, prediction {pred_us:.1f} us/flow, threshold **{threshold:.2f}**.", "",
            "| split | accuracy | precision | recall | F1 | FPR | ROC-AUC | PR-AUC |", "|---|---|---|---|---|---|---|---|",
            *[f"| {k} | {v['accuracy']:.4f} | {v['precision']:.4f} | {v['recall']:.4f} | {v['f1']:.4f} | "
              f"{v['fpr']:.4f} | {v['roc_auc']:.4f} | {v['pr_auc']:.4f} |"
              for k, v in (("val", m["val"]), ("test", s), ("test @0.5", m["test_at_0.5"]))],
            "",
            f"Test confusion matrix: TN={s['confusion_matrix']['tn']:,} FP={s['confusion_matrix']['fp']:,} "
            f"FN={s['confusion_matrix']['fn']:,} TP={s['confusion_matrix']['tp']:,}", "",
            "Share of test flows flagged as attack, per original label (BENIGN row = FPR):", "",
            "| label | test rows | flagged |", "|---|---|---|",
            *[f"| {lab} | {int(r.test_rows):,} | {r.flagged_as_attack:.4f} |" for lab, r in per_type[name].iterrows()],
            "",
            f"### False positives ({len(fp):,} benign test flows flagged)", "",
            "By protocol: " + ", ".join(f"{int(k)}: {v}" for k, v in fp["Protocol"].value_counts().items()) + ". "
            "Top destination ports: " + ", ".join(
                f"{int(k)} ({v})" for k, v in fp["Destination Port"].value_counts().head(8).items()) + ".", "",
            "| feature | false positives | true negatives | attacks |", "|---|---|---|---|",
            *[f"| {c} | {r.iloc[0]:.4g} | {r.iloc[1]:.4g} | {r.iloc[2]:.4g} |" for c, r in comp.iterrows()],
            "",
            (f"Pattern: {(fp['Flow Duration'] <= 10).mean():.0%} of false positives are flows lasting "
             f"<= 10 us (vs {(tn['Flow Duration'] <= 10).mean():.0%} of true negatives). With the 1 us "
             "duration floor their packet rates reach ~10^6 pps, the same signature as a flood burst, "
             "and two packets carry too little evidence to separate them. The monitor's per-source "
             "voting (several attack flows required before a block) is the safeguard against acting "
             "on these single-flow errors." if len(fp) else ""),
            "",
            "False negatives by attack type: " + (", ".join(
                f"{k}: {v}" for k, v in fn[LABEL_COL].value_counts().items()) or "none") + ".",
            "",
        ]

        ConfusionMatrixDisplay(
            confusion_matrix(y_all[te], yhat, labels=[0, 1]), display_labels=["benign", "attack"]
        ).plot(ax=ax_cm[i], colorbar=False, values_format=",d", cmap="Blues")
        ax_cm[i].set_title(f"{name} (t={threshold:.2f})")
        fpr_c, tpr_c, _ = roc_curve(y_all[te], p_test)
        ax_roc[0].plot(fpr_c, tpr_c, label=f"{name} AUC={s['roc_auc']:.4f}")
        prec_c, rec_c, _ = precision_recall_curve(y_all[te], p_test)
        ax_roc[1].plot(rec_c, prec_c, label=f"{name} AP={s['pr_auc']:.4f}")
        print(f"{name}: test F1={s['f1']:.4f} FPR={s['fpr']:.4f} recall={s['recall']:.4f} (t={threshold})")

    fig_cm.tight_layout()
    fig_cm.savefig(out_dir / "confusion_matrices.png", dpi=130)
    ax_roc[0].set(xscale="log", xlabel="false positive rate (log)", ylabel="true positive rate", title="ROC")
    ax_roc[1].set(xlabel="recall", ylabel="precision", title="Precision-recall")
    for a in ax_roc:
        a.legend(loc="lower right")
        a.grid(alpha=0.3)
    fig_roc.tight_layout()
    fig_roc.savefig(out_dir / "roc_pr.png", dpi=130)

    rf = all_metrics["models"]["random_forest"]["feature_importance_top15"]
    fig, ax = plt.subplots(figsize=(7, 5))
    pd.Series(rf).sort_values().plot.barh(ax=ax, color="#4C72B0")
    ax.set_title("Random Forest - top 15 feature importances")
    fig.tight_layout()
    fig.savefig(out_dir / "feature_importance.png", dpi=130)

    rates = pd.DataFrame({k: v["flagged_as_attack"] for k, v in per_type.items()})
    fig, ax = plt.subplots(figsize=(9, 4.5))
    rates.plot.bar(ax=ax)
    ax.set_ylabel("share flagged as attack")
    ax.set_title("Per-label detection rate on test set (BENIGN = false-positive rate)")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_dir / "per_label_detection.png", dpi=130)

    report += ["![confusion matrices](confusion_matrices.png)", "", "![ROC / PR](roc_pr.png)", "",
               "![per-label detection](per_label_detection.png)", "", "![importance](feature_importance.png)", ""]
    (out_dir / "metrics.json").write_text(json.dumps(all_metrics, indent=2))
    (out_dir / "report.md").write_text("\n".join(report))
    print(f"saved models to {models_dir} and report to {out_dir / 'report.md'}")


if __name__ == "__main__":
    main()
