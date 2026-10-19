"""Shared matplotlib style for the result figures (ml/report.py, simulation/compare.py).

Colours come from a palette checked for colour-vision separation and contrast on the
light surface. Series take the categorical slots in fixed order; magnitudes (confusion
matrices, heatmaps) use the single-hue blue ramp. Slots 3 and 4 are below 3:1 contrast
on the surface, so any chart using them labels those series directly.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap

SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]  # categorical slots 1-4, in order
SURFACE, INK, INK_2, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#8a897f", "#e6e5e0"
BLUES = LinearSegmentedColormap.from_list(
    "blues", ["#f2f7fd", "#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"])


def apply() -> None:
    mpl.rcParams.update({
        "figure.facecolor": SURFACE, "savefig.facecolor": SURFACE, "axes.facecolor": SURFACE,
        "font.family": "sans-serif", "font.sans-serif": ["Inter", "Noto Sans", "DejaVu Sans"],
        "font.size": 10.5, "axes.titlesize": 12, "axes.titleweight": "bold", "axes.titlelocation": "left",
        "axes.titlepad": 10, "axes.labelcolor": INK_2, "axes.labelsize": 10, "axes.edgecolor": GRID,
        "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True, "axes.axisbelow": True,
        "grid.color": GRID, "grid.linewidth": 0.8, "xtick.color": INK_2, "ytick.color": INK_2,
        "xtick.major.size": 0, "ytick.major.size": 0, "legend.frameon": False, "legend.fontsize": 9.5,
        "lines.linewidth": 2.0, "lines.solid_capstyle": "round", "text.color": INK,
    })


def save(fig, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=180, bbox_inches="tight", pad_inches=0.2)
    plt.close(fig)
    print(f"  {path}")


def note(fig, text: str) -> None:
    """A one-line caption under the figure, in secondary ink."""
    fig.text(0.01, -0.02, text, fontsize=9, color=INK_2, ha="left", va="top")


def table_png(rows: list[list[str]], header: list[str], path: Path, title: str = "",
              highlight_col: int | None = None, col_widths: list[float] | None = None,
              text_cols: int = 1) -> None:
    """A table rendered as an image, for slides. The first `text_cols` columns are text
    (left-aligned); the rest are numbers (right-aligned). Recessive rules."""
    n_rows, n_cols = len(rows) + 1, len(header)
    widths = col_widths or [1.0] * n_cols
    fig, ax = plt.subplots(figsize=(sum(widths) * 1.55, 0.3 * n_rows + (0.5 if title else 0.15)))
    ax.axis("off")
    tab = ax.table(cellText=rows, colLabels=header, bbox=[0, 0, 1, 1], cellLoc="right",
                   colWidths=[w / sum(widths) for w in widths])
    tab.auto_set_font_size(False)
    tab.set_fontsize(10)
    for (r, c), cell in tab.get_celld().items():
        cell.set_edgecolor(GRID)
        cell.visible_edges = "B"
        cell.set_facecolor(SURFACE)
        if c < text_cols:
            cell.set_text_props(ha="left")
            cell._loc = "left"
        if r == 0:
            cell.set_text_props(weight="bold", color=INK_2)
            cell.set_facecolor("#f0efec")
        elif highlight_col is not None and c == highlight_col:
            cell.set_text_props(weight="bold", color=INK)
    if title:
        ax.set_title(title, loc="left", fontsize=12, fontweight="bold", color=INK, pad=6)
    save(fig, path)


def md_table(header: list[str], rows: list[list[str]]) -> str:
    align = ["---"] + ["---:"] * (len(header) - 1)
    return "\n".join(["| " + " | ".join(header) + " |", "| " + " | ".join(align) + " |",
                      *["| " + " | ".join(r) + " |" for r in rows]])
