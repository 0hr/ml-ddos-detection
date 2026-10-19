"""Slide figures and tables for the trained models (Decision Tree vs Random Forest).

Reloads the saved models, rebuilds the same validation/test split as ml/train.py (same
data, same seed), checks the reproduced test scores match results/ml/metrics.json, and
writes slide-ready figures and tables to results/ml/presentation/:

  01_metrics_table.png      accuracy, precision, recall, F1, FPR, AUCs, timing
  02_metrics_compare.png    the headline metrics side by side + misclassified test flows
  03_confusion_matrices.png counts and row percentages
  04_roc_pr.png             ROC (log FPR axis) and precision-recall curves, operating points marked
  05_threshold.png          how the decision threshold was chosen (validation set)
  06_per_attack.png         detection rate per attack type
  07_feature_importance.png the features the Random Forest relies on most
  08_robustness.png         detection of attack types never seen in training
  09_dataset.png            flows per class after cleaning
  tables.md                 every table above, as Markdown

    uv run python ml/report.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_recall_curve, roc_curve
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "ml"))

import plotstyle as S
from ddos.features import BENIGN, LABEL_COL, binary_target
from ddos.model_io import load_bundle

MODELS = [("decision_tree", "Decision Tree"), ("random_forest", "Random Forest")]
COLOR = {"decision_tree": S.SERIES[1], "random_forest": S.SERIES[0]}  # RF gets slot 0, the main model


def split(df: pd.DataFrame, seed: int):
    """The validation and test indices from ml/train.py (same calls, same seed)."""
    idx = np.arange(len(df))
    _, rest = train_test_split(idx, test_size=0.30, stratify=df[LABEL_COL], random_state=seed)
    va, te = train_test_split(rest, test_size=0.50, stratify=df[LABEL_COL].iloc[rest], random_state=seed)
    return va, te


def scores(y, p, t) -> dict:
    yhat = (p >= t).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, yhat, labels=[0, 1]).ravel()
    prec = tp / max(tp + fp, 1)
    rec = tp / max(tp + fn, 1)
    return {"accuracy": (tp + tn) / len(y), "precision": prec, "recall": rec,
            "f1": 2 * prec * rec / max(prec + rec, 1e-12), "fpr": fp / max(fp + tn, 1),
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}


# ---------------------------------------------------------------------------------- figures
def fig_metrics_compare(res: dict, out: Path) -> None:
    keys = [("accuracy", "Accuracy"), ("precision", "Precision"), ("recall", "Recall (detection rate)"), ("f1", "F1 score")]
    fig, (ax, ax2) = plt.subplots(1, 2, figsize=(11.5, 3.9), gridspec_kw={"width_ratios": [1.35, 1]})
    ys = np.arange(len(keys))[::-1]
    for off, (name, label) in zip((0.13, -0.13), MODELS):
        vals = [res[name]["test"][k] for k, _ in keys]
        ax.scatter(vals, ys + off, s=70, color=COLOR[name], label=label, zorder=3, edgecolor=S.SURFACE, linewidth=1.5)
        for v, y in zip(vals, ys + off):
            ax.annotate(f"{v:.4f}", (v, y), xytext=(8, 0), textcoords="offset points", va="center",
                        fontsize=9, color=S.INK_2)
    ax.set_yticks(ys, [lab for _, lab in keys])
    lo = min(res[n]["test"][k] for n, _ in MODELS for k, _ in keys)
    start = np.floor(lo * 1000) / 1000 - 0.0005
    ax.set_xlim(start, 1.0007)
    ax.set_xticks(np.arange(np.ceil(start * 1000) / 1000, 1.00001, 0.001))
    ax.grid(axis="y", visible=False)
    ax.set_title("Test-set scores")
    ax.set_xlabel(f"score  (axis starts at {start:.4f})")
    ax.legend(loc="lower left")

    cats = [("fp", "False positives\n(benign flagged)"), ("fn", "False negatives\n(attacks missed)")]
    x = np.arange(len(cats))
    for off, (name, label) in zip((-0.19, 0.19), MODELS):
        vals = [res[name]["test"][k] for k, _ in cats]
        bars = ax2.bar(x + off, vals, width=0.36, color=COLOR[name], label=label, zorder=3)
        ax2.bar_label(bars, labels=[f"{v:,}" for v in vals], padding=3, fontsize=9, color=S.INK_2)
    ax2.set_xticks(x, [c for _, c in cats])
    ax2.grid(axis="x", visible=False)
    ax2.set_ylabel("test flows")
    ax2.set_title(f"Misclassified flows (of {res['n_test']:,})")
    ax2.margins(y=0.15)
    fig.tight_layout()
    S.save(fig, out / "02_metrics_compare.png")


def fig_confusion(res: dict, out: Path) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.2))
    names = ["benign", "attack"]
    for ax, (name, label) in zip(axes, MODELS):
        t = res[name]["test"]
        cm = np.array([[t["tn"], t["fp"]], [t["fn"], t["tp"]]])
        pct = cm / cm.sum(axis=1, keepdims=True)
        ax.imshow(pct, cmap=S.BLUES, vmin=0, vmax=1)
        for i in range(2):
            for j in range(2):
                dark = pct[i, j] > 0.55
                ax.text(j, i - 0.08, f"{cm[i, j]:,}", ha="center", va="center", fontsize=13, fontweight="bold",
                        color="white" if dark else S.INK)
                ax.text(j, i + 0.17, f"{pct[i, j]:.2%} of row", ha="center", va="center", fontsize=9,
                        color="white" if dark else S.INK_2)
        ax.set_xticks([0, 1], names)
        ax.set_yticks([0, 1], names)
        ax.set_xlabel("predicted")
        ax.set_ylabel("actual")
        ax.grid(False)
        for s in ax.spines.values():
            s.set_visible(False)
        ax.set_title(f"{label}  ·  threshold {res[name]['threshold']:.2f}")
    fig.tight_layout()
    S.note(fig, f"Test set: {res['n_test']:,} flows. Shading = share of the actual class.")
    S.save(fig, out / "03_confusion_matrices.png")


def fig_roc_pr(res: dict, y_te: np.ndarray, out: Path) -> None:
    fig, (ax, ax2) = plt.subplots(1, 2, figsize=(11.5, 4.3))
    for name, label in MODELS:
        p = res[name]["p_test"]
        fpr, tpr, _ = roc_curve(y_te, p)
        ax.plot(np.clip(fpr, 1e-5, 1), tpr, color=COLOR[name], label=f"{label}  AUC {res[name]['roc_auc']:.4f}")
        t = res[name]["test"]
        ax.scatter([max(t["fpr"], 1e-5)], [t["recall"]], s=60, color=COLOR[name], zorder=4,
                   edgecolor=S.SURFACE, linewidth=1.5)
        prec, rec, _ = precision_recall_curve(y_te, p)
        ax2.plot(rec, prec, color=COLOR[name], label=f"{label}  AP {res[name]['pr_auc']:.4f}")
        ax2.scatter([t["recall"]], [t["precision"]], s=60, color=COLOR[name], zorder=4,
                    edgecolor=S.SURFACE, linewidth=1.5)
    ax.set_xscale("log")
    ax.set_xlim(1e-4, 1)
    ax.set_ylim(0.95, 1.002)
    ax.set_xlabel("false-positive rate (log scale)")
    ax.set_ylabel("true-positive rate (recall)")
    ax.set_title("ROC curve")
    ax.legend(loc="lower right")
    ax2.set_xlim(0.95, 1.002)
    ax2.set_ylim(0.95, 1.002)
    ax2.set_xlabel("recall")
    ax2.set_ylabel("precision")
    ax2.set_title("Precision-recall curve")
    ax2.legend(loc="lower left")
    fig.tight_layout()
    S.note(fig, "Dots = the operating point at each model's chosen threshold. Both axes are zoomed: "
                "the curves sit in the top corner.")
    S.save(fig, out / "04_roc_pr.png")


def fig_threshold(res: dict, y_va: np.ndarray, out: Path) -> None:
    name = "random_forest"
    p = res[name]["p_val"]
    ts = np.round(np.linspace(0.05, 0.95, 91), 3)
    rows = [scores(y_va, p, t) for t in ts]
    fig, (ax, ax2) = plt.subplots(1, 2, figsize=(11.5, 4.0))
    for (k, lab), c in zip((("precision", "precision"), ("recall", "recall"), ("f1", "F1")), S.SERIES):
        vals = [r[k] for r in rows]
        ax.plot(ts, vals, color=c)
        ax.annotate(lab, (ts[-1], vals[-1]), xytext=(6, 0), textcoords="offset points", va="center",
                    fontsize=9.5, color=S.INK_2)
    chosen = res[name]["threshold"]
    for a in (ax, ax2):
        a.axvline(chosen, color=S.INK_2, linewidth=1, linestyle=(0, (4, 3)))
        a.annotate(f"chosen {chosen:.2f}", (chosen, 1.0), xycoords=("data", "axes fraction"),
                   xytext=(4, -12), textcoords="offset points", fontsize=9, color=S.INK_2)
    ax.set_xlim(0, 1.06)
    ax.set_xlabel("decision threshold")
    ax.set_title("Random Forest: score vs threshold")
    lo = min(min(r["precision"], r["recall"], r["f1"]) for r in rows)
    ax.set_ylim(np.floor(lo * 100) / 100 - 0.002, 1.001)
    ax.set_ylabel(f"score (axis starts at {ax.get_ylim()[0]:.3f})")
    ax2.plot(ts, [100 * r["fpr"] for r in rows], color=S.SERIES[0])
    ax2.axhline(1.0, color=S.MUTED, linewidth=1)
    ax2.annotate("limit: 1 % of benign flows", (0.22, 1.0), xytext=(0, 4), textcoords="offset points",
                 ha="left", fontsize=9, color=S.INK_2)
    ax2.set_xlim(0, 1)
    ax2.set_ylim(0, None)
    ax2.set_xlabel("decision threshold")
    ax2.set_ylabel("false-positive rate (%)")
    ax2.set_title("Benign flows wrongly flagged")
    fig.tight_layout()
    S.note(fig, "Validation set. The threshold maximises TPR − FPR with the false-positive rate at "
                "or below 1 %; a false positive would block a legitimate user.")
    S.save(fig, out / "05_threshold.png")


def fig_per_attack(per: pd.DataFrame, out: Path) -> None:
    att = per[per.index != BENIGN].sort_values("random_forest")
    fig, ax = plt.subplots(figsize=(9.5, 0.42 * len(att) + 1.4))
    ys = np.arange(len(att))
    for off, (name, label) in zip((-0.14, 0.14), MODELS):
        ax.scatter(att[name], ys + off, s=55, color=COLOR[name], label=label, zorder=3,
                   edgecolor=S.SURFACE, linewidth=1.2)
    for y, (lab, r) in zip(ys, att.iterrows()):
        ax.annotate(f"{r['random_forest']:.2%}", (r["random_forest"], y + 0.14), xytext=(8, 0),
                    textcoords="offset points", va="center", fontsize=8.5, color=S.INK_2)
    ax.set_yticks(ys, [f"{lab}  ({int(n):,})" for lab, n in zip(att.index, att["test_flows"])])
    ax.grid(axis="y", visible=False)
    lo = att[["decision_tree", "random_forest"]].min().min()
    ax.set_xlim(np.floor(lo * 20) / 20, 1.012)
    ax.set_xlabel(f"share of the class's test flows flagged as attack  (axis starts at {ax.get_xlim()[0]:.2f})")
    ax.set_title("Detection rate per attack type")
    ax.legend(loc="lower right")
    b = per.loc[BENIGN]
    S.note(fig, f"Test flows per class in brackets. Benign flows flagged: Decision Tree {b['decision_tree']:.2%}, "
                f"Random Forest {b['random_forest']:.2%}.")
    fig.tight_layout()
    S.save(fig, out / "06_per_attack.png")


def fig_importance(model, features: list[str], out: Path) -> pd.Series:
    imp = pd.Series(model.feature_importances_, index=features).sort_values(ascending=False).head(15)[::-1]
    fig, ax = plt.subplots(figsize=(9, 5.4))
    bars = ax.barh(imp.index, imp.values, color=S.SERIES[0], height=0.62, zorder=3)
    ax.bar_label(bars, labels=[f"{v:.3f}" for v in imp.values], padding=3, fontsize=8.5, color=S.INK_2)
    ax.grid(axis="y", visible=False)
    ax.set_xlabel("mean decrease in impurity (share of the forest's splitting gain)")
    ax.set_title("Random Forest: 15 most important features (of 43)")
    ax.margins(x=0.12)
    fig.tight_layout()
    S.save(fig, out / "07_feature_importance.png")
    return imp[::-1]


def fig_robustness(rob: dict, out: Path) -> None:
    lo = pd.DataFrame(rob["loao"]).sort_values("detected")
    fig, ax = plt.subplots(figsize=(9.5, 0.42 * len(lo) + 1.4))
    bars = ax.barh(lo["attack"], lo["detected"], color=S.SERIES[0], height=0.62, zorder=3)
    ax.bar_label(bars, labels=[f"{v:.1%}" for v in lo["detected"]], padding=3, fontsize=8.5, color=S.INK_2)
    ax.set_xlim(0, 1.1)
    ax.axvline(0.95, color=S.MUTED, linewidth=1, linestyle=(0, (4, 3)))
    ax.annotate("95 %", (0.95, 1.0), xycoords=("data", "axes fraction"), xytext=(3, -10),
                textcoords="offset points", fontsize=9, color=S.INK_2)
    ax.grid(axis="y", visible=False)
    ax.set_xlabel("share of the hidden attack's flows still detected")
    ax.set_title("Leave-one-attack-out: detecting an attack type never seen in training")
    fig.tight_layout()
    S.note(fig, "Random Forest retrained 12 times, each time without one attack type; "
                "that type is then used as the test set.")
    S.save(fig, out / "08_robustness.png")


def fig_dataset(df: pd.DataFrame, out: Path) -> pd.Series:
    counts = df[LABEL_COL].value_counts().sort_values()
    fig, ax = plt.subplots(figsize=(9.5, 0.42 * len(counts) + 1.3))
    ys = np.arange(len(counts))
    colors = [S.SERIES[1] if lab == BENIGN else S.SERIES[0] for lab in counts.index]
    ax.hlines(ys, 1, counts.values, color=S.GRID, linewidth=2, zorder=2)
    ax.scatter(counts.values, ys, s=55, color=colors, zorder=3, edgecolor=S.SURFACE, linewidth=1.2)
    for y, v in zip(ys, counts.values):
        ax.annotate(f"{v:,}", (v, y), xytext=(8, 0), textcoords="offset points", va="center", fontsize=8.5,
                    color=S.INK_2)
    ax.set_yticks(ys, counts.index)
    ax.set_xscale("log")
    ax.set_xlim(100, counts.max() * 6)
    ax.grid(axis="y", visible=False)
    ax.set_xlabel("flows after cleaning (log scale)")
    ax.set_title(f"Training data: {len(df):,} flows, {len(counts) - 1} attack types + benign")
    ax.scatter([], [], color=S.SERIES[1], label="benign")
    ax.scatter([], [], color=S.SERIES[0], label="attack")
    ax.legend(loc="lower right")
    fig.tight_layout()
    S.save(fig, out / "09_dataset.png")
    return counts[::-1]


# ---------------------------------------------------------------------------------- main
def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default=str(ROOT / "dataset/processed/clean.parquet"))
    ap.add_argument("--models-dir", default=str(ROOT / "models"))
    ap.add_argument("--metrics", default=str(ROOT / "results/ml/metrics.json"))
    ap.add_argument("--robustness", default=str(ROOT / "results/ml/robustness.json"))
    ap.add_argument("--out", default=str(ROOT / "results/ml/presentation"))
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    out = Path(args.out)
    S.apply()

    df = pd.read_parquet(args.data)
    va, te = split(df, args.seed)
    y_va, y_te = binary_target(df[LABEL_COL].iloc[va]), binary_target(df[LABEL_COL].iloc[te])
    saved = json.loads(Path(args.metrics).read_text())["models"]
    res: dict = {"n_test": len(te)}
    per = pd.DataFrame({"test_flows": df[LABEL_COL].iloc[te].value_counts()})
    print(f"rebuilt split: val {len(va):,}  test {len(te):,}")
    for name, label in MODELS:
        b = load_bundle(Path(args.models_dir) / f"{name}.joblib")
        X_va, X_te = df.iloc[va], df.iloc[te]
        p_va, p_te = b.predict_proba(X_va), b.predict_proba(X_te)
        t = scores(y_te, p_te, b.threshold)
        ref = saved[name]["test"]
        if abs(t["f1"] - ref["f1"]) > 1e-9 or t["fp"] != ref["confusion_matrix"]["fp"]:
            sys.exit(f"{name}: reproduced test scores differ from {args.metrics} - was the model retrained "
                     "on different data? Re-run ml/train.py first.")
        res[name] = {"model": b.model, "threshold": b.threshold, "p_val": p_va, "p_test": p_te, "test": t,
                     "roc_auc": ref["roc_auc"], "pr_auc": ref["pr_auc"],
                     "fit_s": saved[name]["fit_seconds"], "pred_us": saved[name]["predict_us_per_flow"]}
        per[name] = pd.Series(p_te >= b.threshold, index=X_te.index).groupby(df[LABEL_COL].iloc[te]).mean()
        print(f"  {label}: test F1 {t['f1']:.4f} matches the saved metrics")

    # ---- tables
    def row(lab, fn):
        return [lab] + [fn(res[n]) for n, _ in MODELS]
    metric_rows = [
        row("Accuracy", lambda r: f"{r['test']['accuracy']:.4f}"),
        row("Precision", lambda r: f"{r['test']['precision']:.4f}"),
        row("Recall (detection rate)", lambda r: f"{r['test']['recall']:.4f}"),
        row("F1 score", lambda r: f"{r['test']['f1']:.4f}"),
        row("False-positive rate", lambda r: f"{r['test']['fpr']:.4%}"),
        row("ROC-AUC", lambda r: f"{r['roc_auc']:.4f}"),
        row("PR-AUC (average precision)", lambda r: f"{r['pr_auc']:.4f}"),
        row("False positives / false negatives", lambda r: f"{r['test']['fp']:,} / {r['test']['fn']:,}"),
        row("Decision threshold", lambda r: f"{r['threshold']:.2f}"),
        row("Training time", lambda r: f"{r['fit_s']:.1f} s"),
        row("Prediction time per flow", lambda r: f"{r['pred_us']:.2f} µs"),
    ]
    header = ["Test set (62,402 flows)", "Decision Tree", "Random Forest"]
    header[0] = f"Test set ({len(te):,} flows)"
    S.table_png(metric_rows, header, out / "01_metrics_table.png", "Model comparison",
                highlight_col=2, col_widths=[2.3, 1.2, 1.2])

    fig_metrics_compare(res, out)
    fig_confusion(res, out)
    fig_roc_pr(res, y_te, out)
    fig_threshold(res, y_va, out)
    fig_per_attack(per, out)
    imp = fig_importance(res["random_forest"]["model"], list(res["random_forest"]["model"].feature_names_in_), out)
    rob = json.loads(Path(args.robustness).read_text()) if Path(args.robustness).exists() else None
    if rob:
        fig_robustness(rob, out)
    counts = fig_dataset(df, out)

    md = ["# Model results", "",
          "Generated by `ml/report.py` from the saved models and the same test split as `ml/train.py`.", "",
          "## Overall (test set)", "", S.md_table(header, metric_rows), "",
          "## Confusion matrices (test set)", "",
          S.md_table(["", "predicted benign", "predicted attack"], [
              [f"{label}: actual benign", f"{res[n]['test']['tn']:,}", f"{res[n]['test']['fp']:,}"] for n, label in MODELS
          ] + [[f"{label}: actual attack", f"{res[n]['test']['fn']:,}", f"{res[n]['test']['tp']:,}"] for n, label in MODELS]),
          "", "## Detection rate per class (test set)", "",
          S.md_table(["class", "test flows", "Decision Tree", "Random Forest"],
                     [[lab, f"{int(r['test_flows']):,}", f"{r['decision_tree']:.2%}", f"{r['random_forest']:.2%}"]
                      for lab, r in per.sort_values("test_flows", ascending=False).iterrows()]),
          "", "For BENIGN the rate is the false-positive rate; for every other class it is recall.", "",
          "## Random Forest feature importance (top 15)", "",
          S.md_table(["feature", "importance"], [[f, f"{v:.4f}"] for f, v in imp.items()]), ""]
    if rob:
        md += ["## Robustness (Random Forest)", "",
               S.md_table(["check", "recall", "false-positive rate", "F1"], [
                   ["Random split (test set)", f"{res['random_forest']['test']['recall']:.4f}",
                    f"{res['random_forest']['test']['fpr']:.4%}", f"{res['random_forest']['test']['f1']:.4f}"],
                   ["5-fold cross-validation (mean ± sd)",
                    f"{rob['cv']['recall']['mean']:.4f} ± {rob['cv']['recall']['std']:.4f}",
                    f"{rob['cv']['fpr']['mean']:.4%} ± {rob['cv']['fpr']['std']:.4%}",
                    f"{rob['cv']['f1']['mean']:.4f} ± {rob['cv']['f1']['std']:.4f}"],
                   ["Temporal holdout (train early, test late)", f"{rob['temporal']['recall']:.4f}",
                    f"{rob['temporal']['fpr']:.4%}", f"{rob['temporal']['f1']:.4f}"]]), "",
               "Leave-one-attack-out (attack type absent from training):", "",
               S.md_table(["hidden attack", "flows", "detected"],
                          [[r["attack"], f"{r['flows']:,}", f"{r['detected']:.1%}"]
                           for r in sorted(rob["loao"], key=lambda r: r["detected"])]), ""]
    md += ["## Training data (after cleaning)", "",
           S.md_table(["class", "flows"], [[lab, f"{n:,}"] for lab, n in counts.items()]), ""]
    (out / "tables.md").write_text("\n".join(md))
    print(f"  {out / 'tables.md'}")


if __name__ == "__main__":
    main()
