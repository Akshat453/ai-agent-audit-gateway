"""Shared publication style for the report charts (matplotlib).

Okabe-Ito palette (colour-blind safe), chosen entries with clearly different lightness so the
charts still read in greyscale; 6.0 x 3.2 in figures; 10-11 pt fonts; light y grid; no top/right
spines; no hatching. Saved as 300 dpi PNG plus SVG.
"""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[4]          # repository root
OUT = Path(__file__).resolve().parents[1]           # docs/report/figures

# Okabe-Ito, ordered dark -> light (greyscale lightness ~ 25 %, 45 %, 65 %, 80 %)
DARK_BLUE = "#0072B2"
VERMILION = "#D55E00"
SKY = "#56B4E9"
ORANGE = "#E69F00"
GREEN = "#009E73"
YELLOW = "#F0E442"
BLACK = "#000000"
SERIES3 = ["#003F6B", "#0072B2", "#8FCBEF"]          # one hue, three lightness steps

SIZE = (6.0, 3.0)


def apply():
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        "font.size": 10.5,
        "axes.titlesize": 11,
        "axes.labelsize": 10.5,
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "legend.fontsize": 10,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.edgecolor": "#333333",
        "axes.grid": True,
        "axes.grid.axis": "y",
        "grid.color": "#DDDDDD",
        "grid.linewidth": 0.6,
        "axes.axisbelow": True,
        "savefig.dpi": 300,
        "savefig.facecolor": "white",
    })


def save(fig, name: str):
    fig.savefig(OUT / f"{name}.png", dpi=300, bbox_inches="tight", pad_inches=0.04)
    fig.savefig(OUT / "charts" / f"{name}.svg", bbox_inches="tight", pad_inches=0.04)
    plt.close(fig)
