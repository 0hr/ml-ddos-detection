"""Compare the collected (simulated) dataset with CIC-DDoS2019, and train on it.

    uv run python simulation/compare.py                       # newest collection (simulation/data/latest.json)
    uv run python simulation/compare.py --sim simulation/data/<collection>/dataset.parquet

Every model is the project's Random Forest (same settings as ml/train.py), with its
threshold tuned on its own training set's validation data (max TPR - FPR, FPR <= 1 %).

  train on        test on          question
  CIC-DDoS2019    CIC-DDoS2019     baseline (the saved model, the ml/train.py test split)
  CIC-DDoS2019    simulated        does the public-dataset model recognise our own traffic?
  simulated       simulated        can our own data train a detector?
  simulated       CIC-DDoS2019     does a model trained on our data catch the public attacks?
  both            each             does adding our data help or hurt on either?

A fourth model, trained on the simulated finished flows only (no in-progress snapshots, see
simulation/build_dataset.py), shows what the snapshots change.

Flow-level scores use finished flows, the unit CIC-DDoS2019 is made of. Detection time is
measured separately (simulation/detection_time.py): each held-out session's capture is
replayed through the live monitor with each model, and we record the time from the attack's
launch to the first block for each attacker, plus any block against a normal host.

The simulated data is split by session, not by flow: flows of one session are near-copies,
so a random split would put near-duplicates on both sides and report an accuracy no new
traffic would reach. With several repetitions the last one is the test set (also the most
intense); with one, each session is split in time (first 70 % trains, last 30 % tests).

We also measure how different the datasets are: a classifier is trained to tell which
dataset a flow came from. ROC-AUC 0.5 = can't tell them apart, 1.0 = trivially separable.

Writes figures, tables.md and results.json to simulation/results/<collection>/.
--no-replay skips the detection-time replay (it takes a few minutes).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "ml"))

import plotstyle as S
from ddos.features import BENIGN, FEATURES, LABEL_COL, binary_target
from ddos.model_io import load_bundle
from detection_time import as_bundle, measure
from report import scores, split
from train import make_models, tune_threshold

CIC, SIM, BOTH = "CIC-DDoS2019", "Simulated", "CIC + simulated"
SIM_FIN = "Simulated, finished flows only"
TRAIN_COLOR = {CIC: S.SERIES[0], SIM: S.SERIES[1], BOTH: S.SERIES[2], SIM_FIN: S.SERIES[3]}
MODEL_ORDER = [CIC, SIM_FIN, SIM, BOTH]
DIST_FEATURES = ["Flow Duration", "Total Fwd Packets", "Flow Packets/s", "Average Packet Size",
                 "Flow IAT Mean", "Init_Win_bytes_forward"]


# ---------------------------------------------------------------------------- data
def sim_split(sim: pd.DataFrame, test_rep: int | None, seed: int) -> tuple[np.ndarray, np.ndarray, np.ndarray, str]:
    """(train, val, test) row indices of the simulated data, keeping a session's
    near-duplicate flows all on the same side."""
    reps = sorted(sim["rep"].unique())
    rng = np.random.default_rng(seed)
    if len(reps) >= 2:
        test_rep = reps[-1] if test_rep is None else test_rep
        test = np.flatnonzero(sim["rep"].to_numpy() == test_rep)
        fit = np.flatnonzero(sim["rep"].to_numpy() != test_rep)
        how = f"by repetition: repetition {test_rep} held out as test ({len(reps)} repetitions)"
    else:
        # Ties (a flow and its in-progress snapshots share start_ts) stay on one side.
        order = sim.groupby("session")["start_ts"].rank(method="min", pct=True).to_numpy()
        test, fit = np.flatnonzero(order > 0.7), np.flatnonzero(order <= 0.7)
        how = "in time within each session: last 30 % of each session's flows held out as test (1 repetition)"
    # Validation (threshold only) = 20 % of the fit rows, stratified by label.
    val_mask = np.zeros(len(fit), bool)
    labels = sim[LABEL_COL].to_numpy()[fit]
    for lab in np.unique(labels):
        idx = np.flatnonzero(labels == lab)
        val_mask[rng.choice(idx, size=max(1, round(0.2 * len(idx))), replace=False)] = True
    return fit[~val_mask], fit[val_mask], test, how


def evaluate(name_train: str, name_test: str, y: np.ndarray, p: np.ndarray, t: float, labels: np.ndarray) -> dict:
    s = scores(y, p, t)
    both = len(np.unique(y)) == 2
    per = pd.Series(p >= t).groupby(labels).mean().round(4).to_dict()
    return {"train": name_train, "test": name_test, "threshold": t, "n": int(len(y)), "attacks": int(y.sum()),
            **{k: float(v) if isinstance(v, (float, np.floating)) else v for k, v in s.items()},
            "roc_auc": float(roc_auc_score(y, p)) if both else None,
            "pr_auc": float(average_precision_score(y, p)) if both else None,
            "per_label": per}


def fit_rf(X: pd.DataFrame, y: np.ndarray, X_val: pd.DataFrame, y_val: np.ndarray, seed: int):
    model = make_models(seed)["random_forest"]
    model.fit(X, y)
    t = tune_threshold(y_val, model.predict_proba(X_val)[:, 1], max_fpr=0.01)
    return model, t


def domain_gap(cic: pd.DataFrame, sim: pd.DataFrame, seed: int, n: int = 15000) -> dict:
    """How well a classifier can tell which dataset a flow came from (5-fold CV ROC-AUC)."""
    out = {}
    for name, a, b in (("all flows", cic, sim),
                       ("benign flows", cic[cic[LABEL_COL] == BENIGN], sim[sim[LABEL_COL] == BENIGN]),
                       ("attack flows", cic[cic[LABEL_COL] != BENIGN], sim[sim[LABEL_COL] != BENIGN])):
        if len(a) < 50 or len(b) < 50:
            continue
        a = a.sample(min(n, len(a)), random_state=seed)
        b = b.sample(min(n, len(b)), random_state=seed)
        X = pd.concat([a[FEATURES], b[FEATURES]]).astype("float64")
        y = np.r_[np.zeros(len(a)), np.ones(len(b))]
        clf = RandomForestClassifier(n_estimators=100, max_depth=12, n_jobs=-1, random_state=seed,
                                     class_weight="balanced")
        p = cross_val_predict(clf, X, y, cv=StratifiedKFold(5, shuffle=True, random_state=seed),
                              method="predict_proba")[:, 1]
        clf.fit(X, y)
        imp = pd.Series(clf.feature_importances_, index=FEATURES).sort_values(ascending=False).head(8)
        out[name] = {"auc": float(roc_auc_score(y, p)), "cic": len(a), "sim": len(b),
                     "top_features": imp.round(4).to_dict()}
    return out


# ---------------------------------------------------------------------------- figures
def fig_datasets(cic: pd.DataFrame, sim: pd.DataFrame, out: Path) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(12, 5.2), gridspec_kw={"width_ratios": [1.15, 1]})
    for ax, (name, df) in zip(axes, ((CIC, cic), (SIM, sim))):
        counts = df[LABEL_COL].value_counts().sort_values()
        ys = np.arange(len(counts))
        colors = [S.SERIES[1] if lab == BENIGN else S.SERIES[0] for lab in counts.index]
        ax.hlines(ys, 1, counts.values, color=S.GRID, linewidth=2, zorder=2)
        ax.scatter(counts.values, ys, s=50, color=colors, zorder=3, edgecolor=S.SURFACE, linewidth=1.2)
        for y, v in zip(ys, counts.values):
            ax.annotate(f"{v:,}", (v, y), xytext=(7, 0), textcoords="offset points", va="center", fontsize=8.5,
                        color=S.INK_2)
        ax.set_yticks(ys, counts.index)
        ax.set_xscale("log")
        ax.set_xlim(max(1, counts.min() / 4), counts.max() * 8)
        ax.grid(axis="y", visible=False)
        ax.set_xlabel("flows (log scale)")
        tcp = (df["Protocol"] == 6).mean()
        ax.set_title(f"{name}: {len(df):,} flows · {(df[LABEL_COL] == BENIGN).mean():.0%} benign · {tcp:.0%} TCP")
    axes[1].scatter([], [], color=S.SERIES[1], label="benign")
    axes[1].scatter([], [], color=S.SERIES[0], label="attack")
    axes[1].legend(loc="lower right")
    fig.tight_layout()
    S.save(fig, out / "01_datasets.png")


def fig_transfer(results: list[dict], out: Path) -> None:
    tests = [CIC, SIM]
    trains = [t for t in MODEL_ORDER if any(r["train"] == t for r in results)]
    grid = {(r["train"], r["test"]): r for r in results}
    fig, ax = plt.subplots(figsize=(8.8, 1.3 * len(trains) + 0.8))
    vals = np.array([[grid[(tr, te)]["f1"] if (tr, te) in grid else np.nan for te in tests] for tr in trains])
    ax.imshow(vals, cmap=S.BLUES, vmin=0, vmax=1, aspect="auto")
    for i, tr in enumerate(trains):
        for j, te in enumerate(tests):
            r = grid.get((tr, te))
            if r is None:
                continue
            dark = r["f1"] > 0.55
            ax.text(j, i - 0.13, f"F1 {r['f1']:.3f}", ha="center", va="center", fontsize=13, fontweight="bold",
                    color="white" if dark else S.INK)
            ax.text(j, i + 0.2, f"recall {r['recall']:.1%} · FPR {r['fpr']:.2%}", ha="center", va="center",
                    fontsize=9, color="white" if dark else S.INK_2)
    ax.set_xticks(range(len(tests)), [f"test: {t}" for t in tests])
    ax.set_yticks(range(len(trains)), [f"train: {t}" for t in trains])
    ax.grid(False)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title("Train on one dataset, test on another (Random Forest)")
    fig.tight_layout()
    S.note(fig, "Shading = F1. Diagonal = in-dataset; off-diagonal = transfer to the other dataset.")
    S.save(fig, out / "02_transfer_matrix.png")


def fig_transfer_metrics(results: list[dict], out: Path) -> None:
    keys = [("precision", "Precision"), ("recall", "Recall"), ("f1", "F1"), ("accuracy", "Accuracy")]
    fig, axes = plt.subplots(1, 2, figsize=(12.5, 5.2), sharey=False)
    for ax, test in zip(axes, (CIC, SIM)):
        rows = sorted((r for r in results if r["test"] == test), key=lambda r: MODEL_ORDER.index(r["train"]))
        ys = np.arange(len(keys))[::-1]
        offs = np.linspace(0.27, -0.27, len(rows)) if len(rows) > 1 else [0]
        for off, r in zip(offs, rows):
            vals = [r[k] for k, _ in keys]
            ax.scatter(vals, ys + off, s=55, color=TRAIN_COLOR[r["train"]], label=f"trained on {r['train']}",
                       zorder=3, edgecolor=S.SURFACE, linewidth=1.2)
            for v, y in zip(vals, ys + off):
                ax.annotate(f"{v:.3f}", (v, y), xytext=(7, 0), textcoords="offset points", va="center",
                            fontsize=8, color=S.INK_2)
        ax.set_yticks(ys, [lab for _, lab in keys])
        ax.set_xlim(0, 1.12)
        ax.grid(axis="y", visible=False)
        ax.set_title(f"Tested on {test}")
        ax.legend(loc="lower left", fontsize=8.5)
    fig.tight_layout()
    S.save(fig, out / "03_transfer_metrics.png")


def fig_distributions(cic: pd.DataFrame, sim: pd.DataFrame, out: Path) -> None:
    fig, axes = plt.subplots(2, 3, figsize=(13, 7.2))
    for ax, feat in zip(axes.flat, DIST_FEATURES):
        for (name, df), color in ((CIC, cic), S.SERIES[0]), ((SIM, sim), S.SERIES[1]):
            for cls, ls in ((BENIGN, (0, (4, 2))), ("attack", "-")):
                v = df.loc[(df[LABEL_COL] == BENIGN) if cls == BENIGN else (df[LABEL_COL] != BENIGN), feat]
                if len(v) == 0:
                    continue
                v = np.sort(v.to_numpy(dtype=float))
                ax.plot(v, np.arange(1, len(v) + 1) / len(v), color=color, linestyle=ls, linewidth=1.8,
                        label=f"{name} {'benign' if cls == BENIGN else 'attack'}")
        ax.set_xscale("symlog", linthresh=1)
        ax.set_ylim(0, 1.02)
        ax.set_title(feat, fontsize=10.5)
        ax.set_ylabel("share of flows at or below x")
    handles, labels = axes.flat[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper left", ncol=4, bbox_to_anchor=(0.01, 0.955))
    fig.suptitle("Feature distributions: CIC-DDoS2019 vs simulated (cumulative)", x=0.01, y=0.995, ha="left",
                 fontsize=12, fontweight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    S.note(fig, "Solid = attack flows, dashed = benign flows. x-axis: symmetric log (linear below 1).")
    S.save(fig, out / "04_feature_distributions.png")


def fig_importance(models: dict, out: Path) -> None:
    fig, axes = plt.subplots(1, len(models), figsize=(5.4 * len(models), 4.8))
    for ax, (name, model) in zip(np.atleast_1d(axes), models.items()):
        imp = pd.Series(model.feature_importances_, index=FEATURES).sort_values(ascending=False).head(10)[::-1]
        bars = ax.barh(imp.index, imp.values, color=TRAIN_COLOR[name], height=0.62, zorder=3)
        ax.bar_label(bars, labels=[f"{v:.3f}" for v in imp.values], padding=3, fontsize=8.5, color=S.INK_2)
        ax.grid(axis="y", visible=False)
        ax.margins(x=0.15)
        ax.set_title(f"{name}: top 10", fontsize=11)
        ax.set_xlabel("importance")
    fig.tight_layout()
    S.save(fig, out / "05_feature_importance.png")


def fig_sim_per_label(results: list[dict], out: Path) -> None:
    rows = sorted((r for r in results if r["test"] == SIM), key=lambda r: MODEL_ORDER.index(r["train"]))
    labels = sorted({lab for r in rows for lab in r["per_label"]}, key=lambda x: (x == BENIGN, x))
    fig, ax = plt.subplots(figsize=(10, 0.9 * len(labels) + 1.6))
    ys = np.arange(len(labels))[::-1]
    offs = np.linspace(0.27, -0.27, len(rows))
    for off, r in zip(offs, rows):
        vals = [r["per_label"].get(lab, np.nan) for lab in labels]
        ax.scatter(vals, ys + off, s=55, color=TRAIN_COLOR[r["train"]], label=f"trained on {r['train']}",
                   zorder=3, edgecolor=S.SURFACE, linewidth=1.2)
        for v, y in zip(vals, ys + off):
            if not np.isnan(v):
                ax.annotate(f"{v:.1%}", (v, y), xytext=(7, 0), textcoords="offset points", va="center",
                            fontsize=8, color=S.INK_2)
    ax.set_yticks(ys, [f"{lab}  (false-positive rate)" if lab == BENIGN else lab for lab in labels])
    ax.set_xlim(-0.02, 1.12)
    ax.grid(axis="y", visible=False)
    ax.set_xlabel("share of the class's test flows flagged as attack")
    ax.set_title("Simulated test set: detection per attack type")
    ax.legend(loc="lower right", fontsize=8.5)
    fig.tight_layout()
    S.save(fig, out / "06_sim_per_attack.png")


def fig_domain_gap(gap: dict, out: Path) -> None:
    if not gap:
        return
    fig, (ax, ax2) = plt.subplots(1, 2, figsize=(12, 3.9), gridspec_kw={"width_ratios": [1, 1.25]})
    names = list(gap)[::-1]
    bars = ax.barh(names, [gap[n]["auc"] for n in names], color=S.SERIES[0], height=0.55, zorder=3)
    ax.bar_label(bars, labels=[f"{gap[n]['auc']:.3f}" for n in names], padding=3, fontsize=9, color=S.INK_2)
    ax.axvline(0.5, color=S.MUTED, linewidth=1, linestyle=(0, (4, 3)), zorder=4)
    ax.set_xlim(0, 1.12)
    ax.grid(axis="y", visible=False)
    ax.set_xlabel("ROC-AUC of telling the datasets apart\n(dashed: 0.5 = indistinguishable)")
    ax.set_title("How different are the datasets?")
    top = pd.Series(gap[next(iter(gap))]["top_features"]).sort_values()
    bars = ax2.barh(top.index, top.values, color=S.SERIES[0], height=0.6, zorder=3)
    ax2.bar_label(bars, labels=[f"{v:.3f}" for v in top.values], padding=3, fontsize=8.5, color=S.INK_2)
    ax2.margins(x=0.15)
    ax2.grid(axis="y", visible=False)
    ax2.set_xlabel("importance for telling the datasets apart")
    ax2.set_title(f"What differs most ({next(iter(gap))})")
    fig.tight_layout()
    S.save(fig, out / "07_domain_gap.png")


def detection_summary(replays: list[dict]) -> pd.DataFrame:
    """One row per (model, attack type): attackers flagged, median and worst detection time;
    plus one row per model for blocks against normal hosts."""
    rows = []
    for (model, label), grp in pd.DataFrame(replays).groupby(["model", "label"]):
        times = [t for r in grp.itertuples() for t in r.detection_s.values()]
        caught = [t for t in times if t is not None]
        rows.append({"model": model, "label": label, "attackers": len(times), "flagged": len(caught),
                     "median_s": float(np.median(caught)) if caught else None,
                     "max_s": float(max(caught)) if caught else None,
                     "false_blocks": sum(len(r.false_blocks) for r in grp.itertuples()),
                     "sessions": len(grp)})
    return pd.DataFrame(rows)


def fig_detection(summary: pd.DataFrame, replays: list[dict], out: Path) -> None:
    attacks = summary[summary["label"] != BENIGN]
    labels = sorted(attacks["label"].unique())
    models = [m for m in MODEL_ORDER if m in set(summary["model"])]
    limit = max((r["attack_duration_s"] or 30) for r in replays)
    fig, (ax, ax2) = plt.subplots(1, 2, figsize=(13, 0.95 * len(labels) + 2.2), gridspec_kw={"width_ratios": [2.3, 1]})
    ys = np.arange(len(labels))[::-1]
    offs = np.linspace(0.27, -0.27, len(models))
    for off, m in zip(offs, models):
        for y, lb in zip(ys, labels):
            row = attacks[(attacks["model"] == m) & (attacks["label"] == lb)]
            if row.empty:
                continue
            r = row.iloc[0]
            if r["flagged"] == 0:
                ax.scatter([limit], [y + off], s=55, facecolor=S.SURFACE, edgecolor=TRAIN_COLOR[m], linewidth=1.6, zorder=3)
                ax.annotate("not flagged", (limit, y + off), xytext=(-8, 0), textcoords="offset points", ha="right",
                            va="center", fontsize=8, color=S.INK_2)
                continue
            ax.scatter([r["median_s"]], [y + off], s=55, color=TRAIN_COLOR[m], zorder=3, edgecolor=S.SURFACE, linewidth=1.2)
            extra = f" ({int(r['flagged'])}/{int(r['attackers'])})" if r["flagged"] < r["attackers"] else ""
            ax.annotate(f"{r['median_s']:.1f} s{extra}", (r["median_s"], y + off), xytext=(8, 0),
                        textcoords="offset points", va="center", fontsize=8, color=S.INK_2)
    for m in models:
        ax.scatter([], [], color=TRAIN_COLOR[m], label=m)
    ax.set_yticks(ys, labels)
    ax.set_xlim(-0.5, limit + 1)
    ax.grid(axis="y", visible=False)
    ax.set_xlabel("seconds from launching the attack to the first block decision (median over attackers)")
    ax.set_title("Detection time in the live monitor (held-out captures)")
    ax.legend(loc="upper left", bbox_to_anchor=(0, -0.22), ncol=2, fontsize=8.5)

    fb = summary.groupby("model")["false_blocks"].sum().reindex(models).fillna(0)
    bars = ax2.barh(range(len(models))[::-1], fb.values, color=[TRAIN_COLOR[m] for m in models], height=0.55, zorder=3)
    ax2.bar_label(bars, labels=[str(int(v)) for v in fb.values], padding=3, fontsize=9, color=S.INK_2)
    ax2.set_yticks(range(len(models))[::-1], models, fontsize=9)
    ax2.set_xlim(0, max(1, fb.max()) * 1.3)
    ax2.xaxis.set_major_locator(plt.MaxNLocator(integer=True))
    ax2.grid(axis="y", visible=False)
    ax2.set_xlabel("legitimate hosts flagged")
    ax2.set_title("False blocks")
    fig.tight_layout()
    S.note(fig, "Model rule only (flow-rate rule off). Hollow marker: no attacker flagged before the attack ended.")
    S.save(fig, out / "08_detection_time.png")


# ---------------------------------------------------------------------------- main
def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sim", help="simulated dataset.parquet (default: newest collection)")
    ap.add_argument("--cic", default=str(ROOT / "dataset/processed/clean.parquet"))
    ap.add_argument("--cic-model", default=str(ROOT / "models/random_forest.joblib"))
    ap.add_argument("--out", help="output directory (default simulation/results/<collection name>)")
    ap.add_argument("--test-rep", type=int, help="repetition held out as the simulated test set (default: last)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--no-replay", action="store_true", help="skip the detection-time replay")
    args = ap.parse_args()
    S.apply()

    sim_path = Path(args.sim) if args.sim else None
    if sim_path is None:
        latest = HERE / "data/latest.json"
        if not latest.exists():
            sys.exit("no --sim given and no collection yet: run simulation/collect.py first")
        sim_path = Path(json.loads(latest.read_text())["collection"]) / "dataset.parquet"
    out = Path(args.out) if args.out else HERE / "results" / sim_path.parent.name
    out.mkdir(parents=True, exist_ok=True)

    sim = pd.read_parquet(sim_path).reset_index(drop=True)
    if "snapshot_s" not in sim:
        sim["snapshot_s"] = 0.0
    finished = sim["snapshot_s"].to_numpy() == 0
    sim_fin = sim[finished]
    cic = pd.read_parquet(args.cic)
    if sim[LABEL_COL].nunique() < 2 or (sim[LABEL_COL] == BENIGN).all():
        sys.exit("the simulated dataset needs both benign and attack flows")
    print(f"CIC-DDoS2019 {len(cic):,} flows · simulated {int(finished.sum()):,} flows "
          f"+ {int((~finished).sum()):,} in-progress snapshots ({sim_path})")

    c_va, c_te = split(cic, args.seed)
    c_tr = np.setdiff1d(np.arange(len(cic)), np.r_[c_va, c_te])
    s_tr, s_va, s_te, how = sim_split(sim, args.test_rep, args.seed)
    s_te = s_te[finished[s_te]]  # scored on finished flows, like CIC-DDoS2019
    print(f"simulated split {how}: train {len(s_tr):,} · val {len(s_va):,} · test {len(s_te):,} finished flows")
    if not binary_target(sim[LABEL_COL].iloc[s_te]).any():
        sys.exit("the simulated test set has no attack flows; collect more repetitions or pick --test-rep")

    X = lambda df, idx: df[FEATURES].iloc[idx].astype("float64")
    y = lambda df, idx: binary_target(df[LABEL_COL].iloc[idx])
    lab = lambda df, idx: df[LABEL_COL].iloc[idx].to_numpy()
    tests = {CIC: (cic, c_te), SIM: (sim, s_te)}

    results, models = [], {}
    cic_model = load_bundle(args.cic_model)
    models[CIC] = cic_model.model
    print("evaluating the saved CIC-DDoS2019 model ...")
    for name, (df, idx) in tests.items():
        results.append(evaluate(CIC, name, y(df, idx), cic_model.predict_proba(df.iloc[idx]), cic_model.threshold,
                                lab(df, idx)))

    print("training on simulated data ...")
    m_sim, t_sim = fit_rf(X(sim, s_tr), y(sim, s_tr), X(sim, s_va), y(sim, s_va), args.seed)
    models[SIM] = m_sim
    for name, (df, idx) in tests.items():
        results.append(evaluate(SIM, name, y(df, idx), m_sim.predict_proba(X(df, idx))[:, 1], t_sim, lab(df, idx)))

    print("training on simulated finished flows only ...")
    f_tr, f_va = s_tr[finished[s_tr]], s_va[finished[s_va]]
    m_fin, t_fin = fit_rf(X(sim, f_tr), y(sim, f_tr), X(sim, f_va), y(sim, f_va), args.seed)
    models[SIM_FIN] = m_fin
    for name, (df, idx) in tests.items():
        results.append(evaluate(SIM_FIN, name, y(df, idx), m_fin.predict_proba(X(df, idx))[:, 1], t_fin,
                                lab(df, idx)))

    print("training on CIC-DDoS2019 + simulated ...")
    Xb = pd.concat([X(cic, c_tr), X(sim, s_tr)])
    yb = np.r_[y(cic, c_tr), y(sim, s_tr)]
    Xbv = pd.concat([X(cic, c_va), X(sim, s_va)])
    ybv = np.r_[y(cic, c_va), y(sim, s_va)]
    m_both, t_both = fit_rf(Xb, yb, Xbv, ybv, args.seed)
    models[BOTH] = m_both
    for name, (df, idx) in tests.items():
        results.append(evaluate(BOTH, name, y(df, idx), m_both.predict_proba(X(df, idx))[:, 1], t_both,
                                lab(df, idx)))

    print("measuring the gap between the datasets ...")
    gap = domain_gap(cic, sim_fin, args.seed)

    replays, det = [], pd.DataFrame()
    test_sessions = sorted(sim["session"].iloc[s_te].unique())
    session_dirs = [sim_path.parent / "sessions" / sid for sid in test_sessions]
    session_dirs = [d for d in session_dirs if (d / "capture.pcap").exists() and (d / "session.json").exists()]
    if args.no_replay:
        print("detection-time replay skipped (--no-replay)")
    elif not session_dirs:
        print("detection-time replay skipped: the held-out sessions have no captures")
    else:
        bundles = {CIC: cic_model, SIM_FIN: as_bundle(m_fin, t_fin, SIM_FIN), SIM: as_bundle(m_sim, t_sim, SIM),
                   BOTH: as_bundle(m_both, t_both, BOTH)}
        print(f"replaying {len(session_dirs)} held-out captures through the monitor with {len(bundles)} models ...",
              flush=True)
        replays = measure(bundles, session_dirs)
        det = detection_summary(replays)

    print("figures:")
    fig_datasets(cic, sim_fin, out)
    fig_transfer(results, out)
    fig_transfer_metrics(results, out)
    fig_distributions(cic, sim_fin, out)
    fig_importance(models, out)
    fig_sim_per_label(results, out)
    fig_domain_gap(gap, out)
    if len(det):
        fig_detection(det, replays, out)

    header = ["train on", "test on", "flows", "accuracy", "precision", "recall", "F1", "FPR", "ROC-AUC"]
    rows = [[r["train"], r["test"], f"{r['n']:,}", f"{r['accuracy']:.4f}", f"{r['precision']:.4f}",
             f"{r['recall']:.4f}", f"{r['f1']:.4f}", f"{r['fpr']:.2%}",
             "—" if r["roc_auc"] is None else f"{r['roc_auc']:.4f}"] for r in results]
    S.table_png(rows, header, out / "00_results_table.png", "Cross-dataset results (Random Forest)",
                col_widths=[2.3, 1.4, 0.9, 0.9, 0.9, 0.9, 0.8, 0.8, 0.9], text_cols=2)
    det_header = ["model", "attack", "attackers flagged", "median time", "slowest"]
    det_rows = [[r.model, r.label, f"{int(r.flagged)}/{int(r.attackers)}",
                 "—" if r.median_s is None or pd.isna(r.median_s) else f"{r.median_s:.1f} s",
                 "—" if r.max_s is None or pd.isna(r.max_s) else f"{r.max_s:.1f} s"]
                for r in det[det["label"] != BENIGN].sort_values(
                    ["label", "model"], key=lambda c: c.map(MODEL_ORDER.index) if c.name == "model" else c).itertuples()
                ] if len(det) else []
    fb_rows = ([[m, str(int(det.loc[det["model"] == m, "false_blocks"].sum())),
                 str(int(det.loc[det["model"] == m, "sessions"].sum()))]
                for m in MODEL_ORDER if m in set(det["model"])] if len(det) else [])
    if det_rows:
        S.table_png(det_rows, det_header, out / "09_detection_table.png", "Detection time in the live monitor",
                    col_widths=[2.3, 1.8, 1.2, 1.0, 0.9], text_cols=2)
    sim_labels = sorted(sim[LABEL_COL].unique(), key=lambda x: (x == BENIGN, x))
    md = ["# Simulated data vs CIC-DDoS2019", "",
          f"Simulated dataset: `{sim_path}` — {len(sim_fin):,} finished flows, {sim['session'].nunique()} sessions, "
          f"plus {len(sim) - len(sim_fin):,} in-progress snapshots used for training only.", "",
          f"Simulated split: {how}. Train {len(s_tr):,} · validation {len(s_va):,} rows (flows and snapshots) · "
          f"test {len(s_te):,} finished flows.",
          f"CIC-DDoS2019 split: the one of ml/train.py (test {len(c_te):,} flows).", "",
          "## Results", "", S.md_table(header, rows), "",
          "## Simulated test set, per class", "",
          S.md_table(["class", "test flows"] + list(MODEL_ORDER),
                     [[lb, f"{int((lab(sim, s_te) == lb).sum()):,}"]
                      + [f"{next(r for r in results if r['train'] == t and r['test'] == SIM)['per_label'].get(lb, float('nan')):.1%}"
                         for t in MODEL_ORDER] for lb in sim_labels]), "",
          "For BENIGN the rate is the false-positive rate; for every other class it is recall.", "",
          "## Detection time in the live monitor", "",
          *(["Each held-out capture replayed through traffic/monitor.py (same flow meter, scoring and "
             "per-source vote as live; flow-rate rule off so only the model decides). Time from launching the "
             "attack to the first block decision for each attacker.", "",
             S.md_table(det_header, det_rows), "",
             S.md_table(["model", "legitimate hosts flagged", "sessions replayed"], fb_rows), ""]
            if det_rows else ["Not measured (--no-replay, or the held-out sessions have no captures).", ""]),
          "## How different are the datasets", "",
          S.md_table(["flows compared", "CIC sample", "simulated sample", "ROC-AUC (0.5 = indistinguishable)"],
                     [[k, f"{v['cic']:,}", f"{v['sim']:,}", f"{v['auc']:.3f}"] for k, v in gap.items()]), "",
          "Features that separate them most (all flows): "
          + ", ".join(f"{k} ({v:.3f})" for k, v in (gap.get("all flows") or {}).get("top_features", {}).items()) + ".", "",
          "## Datasets", "",
          S.md_table(["", CIC, SIM], [
              ["flows", f"{len(cic):,}", f"{len(sim_fin):,}"],
              ["benign share", f"{(cic[LABEL_COL] == BENIGN).mean():.1%}", f"{(sim_fin[LABEL_COL] == BENIGN).mean():.1%}"],
              ["attack types", str(cic[LABEL_COL].nunique() - 1), str(sim_fin[LABEL_COL].nunique() - 1)],
              ["TCP share", f"{(cic['Protocol'] == 6).mean():.1%}", f"{(sim_fin['Protocol'] == 6).mean():.1%}"],
              ["UDP share of benign flows",
               f"{(cic.loc[cic[LABEL_COL] == BENIGN, 'Protocol'] == 17).mean():.1%}",
               f"{(sim_fin.loc[sim_fin[LABEL_COL] == BENIGN, 'Protocol'] == 17).mean():.1%}"],
          ]), ""]
    (out / "tables.md").write_text("\n".join(md))
    (out / "results.json").write_text(json.dumps({"sim": str(sim_path), "split": how, "results": results,
                                                  "domain_gap": gap, "detection_time": replays}, indent=2, default=float))
    print(f"  {out / 'tables.md'}\n")
    for r in results:
        print(f"  train {r['train']:31s} test {r['test']:13s} F1 {r['f1']:.4f}  recall {r['recall']:.4f}  FPR {r['fpr']:.4f}")
    if det_rows:
        print("\n" + S.md_table(det_header, det_rows) + "\n\n" + S.md_table(["model", "legitimate hosts flagged", "sessions"], fb_rows))


if __name__ == "__main__":
    main()
