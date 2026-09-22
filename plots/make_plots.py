"""Generate every figure for the report from the results/*.csv files.

Run (after the experiments):  .venv/bin/python plots/make_plots.py
All PNGs are written to plots/. Nothing here is copied from the paper -- every
figure is produced from our own measurements.
"""
from __future__ import annotations
import csv, json, pathlib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = pathlib.Path(__file__).resolve().parents[1]
RES = ROOT / "results"
OUT = ROOT / "plots"

# Consistent, colour-blind-friendly palette.
DE_C, CC_C = "#2563eb", "#f59e0b"       # blue / amber
LEAK_C, SAFE_C = "#dc2626", "#16a34a"   # red / green
plt.rcParams.update({"figure.dpi": 130, "font.size": 11,
                     "axes.spines.top": False, "axes.spines.right": False})


def _bars(ax, x, series, colors, width=0.38, fmt="{:.0f}"):
    """Grouped bars with value labels. series = {name: [values]}."""
    import numpy as np
    idx = np.arange(len(x))
    n = len(series)
    for i, (name, vals) in enumerate(series.items()):
        off = (i - (n - 1) / 2) * width
        bars = ax.bar(idx + off, vals, width, label=name, color=colors[i])
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, b.get_height(),
                    fmt.format(v), ha="center", va="bottom", fontsize=9)
    ax.set_xticks(idx); ax.set_xticklabels(x)
    ax.legend(frameon=False)


def plot_replication(summary):
    de, cc = summary["DE"], summary["CC"]
    fig, ax = plt.subplots(figsize=(7, 4.3))
    _bars(ax, ["Sensitive WCD\nfound", "Harmless WCD\nflagged", "Sensitive WCD\nmissed"],
          {"DE (this paper)": [de["tp"], de["fp"], de["fn"]],
           "CC (prior work)": [cc["tp"], cc["fp"], cc["fn"]]},
          [DE_C, CC_C])
    ax.set_ylabel("number of endpoints")
    ax.set_title(f"DE vs CC over the sensitive-WCD target "
                 f"({summary['n_sensitive_target']} of {summary['n_endpoints']} endpoints)")
    fig.tight_layout(); fig.savefig(OUT / "fig1_replication.png"); plt.close(fig)


def plot_metrics(summary):
    de, cc = summary["DE"], summary["CC"]
    fig, ax = plt.subplots(figsize=(7, 4.3))
    _bars(ax, ["Precision", "Recall", "F1"],
          {"DE (this paper)": [de["precision"], de["recall"], de["f1"]],
           "CC (prior work)": [cc["precision"], cc["recall"], cc["f1"]]},
          [DE_C, CC_C], fmt="{:.2f}")
    ax.set_ylim(0, 1.15); ax.set_ylabel("score")
    ax.set_title("Detection quality vs the sensitive-WCD target (beyond the paper)")
    fig.tight_layout(); fig.savefig(OUT / "fig2_metrics.png"); plt.close(fig)


def plot_confusion(summary):
    import numpy as np
    fig, axes = plt.subplots(1, 2, figsize=(9, 4))
    for ax, name in zip(axes, ["DE", "CC"]):
        m = summary[name]
        mat = np.array([[m["tp"], m["fp"]], [m["fn"], m["tn"]]])
        im = ax.imshow(mat, cmap="Blues")
        ax.set_xticks([0, 1]); ax.set_xticklabels(["sensitive\nWCD", "other"])
        ax.set_yticks([0, 1]); ax.set_yticklabels(["flagged", "not flagged"])
        ax.set_xlabel("ground truth"); ax.set_title(f"{name}")
        for (r, c), v in np.ndenumerate(mat):
            ax.text(c, r, str(v), ha="center", va="center",
                    color="white" if v > mat.max() / 2 else "black", fontsize=13)
    fig.suptitle("Confusion matrices (our lab has ground truth; the paper does not)")
    fig.tight_layout(); fig.savefig(OUT / "fig3_confusion.png"); plt.close(fig)


def plot_config():
    rows = list(csv.DictReader((RES / "config.csv").open()))
    names = {"vulnerable.conf": "vulnerable\n(cache ignores\nno-store)",
             "honor.conf": "honour headers\n(the fix)",
             "nocache.conf": "no caching\n(baseline)"}
    x = [names.get(r["config"], r["config"]) for r in rows]
    fig, ax = plt.subplots(figsize=(7.5, 4.3))
    _bars(ax, x,
          {"DE detections": [int(r["de_detections"]) for r in rows],
           "real leaks (sensitive)": [int(r["real_leaks"]) for r in rows]},
          [DE_C, LEAK_C])
    ax.set_ylabel("count"); ax.set_title("Cache-configuration sensitivity (extension)")
    fig.tight_layout(); fig.savefig(OUT / "fig4_config.png"); plt.close(fig)


def plot_extension():
    rows = list(csv.DictReader((RES / "extension.csv").open()))
    exts = ["." + r["extension"] for r in rows]
    ok = [r["attack_success"] == "True" for r in rows]
    fig, ax = plt.subplots(figsize=(8, 4))
    bars = ax.bar(exts, [1 if v else 0 for v in ok],
                  color=[LEAK_C if v else SAFE_C for v in ok])
    ax.set_yticks([0, 1]); ax.set_yticklabels(["safe", "LEAK"])
    ax.set_title("Which extensions spring the trap? (attack on /profile)")
    for b, v in zip(bars, ok):
        ax.text(b.get_x() + b.get_width() / 2, 0.5, "LEAK" if v else "safe",
                ha="center", va="center", rotation=90, color="white", fontsize=8)
    plt.xticks(rotation=45, ha="right")
    fig.tight_layout(); fig.savefig(OUT / "fig5_extension.png"); plt.close(fig)


def main():
    summary = json.loads((RES / "summary.json").read_text())
    plot_replication(summary)
    plot_metrics(summary)
    plot_confusion(summary)
    plot_config()
    plot_extension()
    print("Wrote:", ", ".join(sorted(p.name for p in OUT.glob("*.png"))))


if __name__ == "__main__":
    main()
