"""Central experiment: run DE and CC over every endpoint and compare to ground
truth. Reproduces the paper's DE-vs-CC comparison (Table 2) in a lab where we
KNOW the correct answer.

Outputs:
  results/detection.csv   one row per endpoint (ground truth + both verdicts)
  results/summary.json    confusion-matrix metrics for DE and CC

Run:  .venv/bin/python experiments/run_experiment.py
"""
from __future__ import annotations
import csv, json, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from origin.pages import REGISTRY
from detector import de, cc
from experiments.metrics import confusion

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
ROOT = pathlib.Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"; RESULTS.mkdir(exist_ok=True)


def main() -> None:
    rows = []
    de_pairs, cc_pairs = [], []
    pages = sorted(REGISTRY.values(), key=lambda p: p.path)
    print(f"Testing {len(pages)} endpoints against {BASE} ...")
    for pg in pages:
        url = BASE + pg.path
        de_res = de.detect(url)
        cc_res = cc.detect(url)
        rows.append({
            "path": pg.path, "label": pg.label,
            "ground_truth_is_wcd": pg.is_wcd,
            "ground_truth_sensitive_target": pg.vulnerable,
            "de_detected": de_res.detected, "de_stop": de_res.stopped_at,
            "cc_detected": cc_res.detected,
        })
        de_pairs.append((de_res.detected, pg.vulnerable))
        cc_pairs.append((cc_res.detected, pg.vulnerable))

    with (RESULTS / "detection.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)

    de_m = confusion(de_pairs); cc_m = confusion(cc_pairs)
    summary = {
        "base": BASE,
        "note": "Run against the VULNERABLE nginx config. Target = sensitive "
                "(high-impact) WCD. Harmless WCD (non-sensitive) is real but "
                "out of target; see origin/pages.py.",
        "n_endpoints": len(pages),
        "n_wcd_any": sum(p.is_wcd for p in pages),
        "n_sensitive_target": sum(p.vulnerable for p in pages),
        "n_harmless_wcd": sum(p.is_wcd and not p.vulnerable for p in pages),
        "DE": de_m.as_dict(), "CC": cc_m.as_dict()}
    (RESULTS / "summary.json").write_text(json.dumps(summary, indent=2))

    # Pretty print
    def line(name, m):
        print(f"  {name:3s}  TP={m.tp:2d} FP={m.fp:2d} TN={m.tn:2d} FN={m.fn:2d}"
              f"   precision={m.precision:.2f} recall={m.recall:.2f} f1={m.f1:.2f}")
    print(f"\n=== RESULTS (target = sensitive WCD: {summary['n_sensitive_target']}"
          f" of {len(pages)} endpoints; {summary['n_harmless_wcd']} harmless WCD) ===")
    line("DE", de_m); line("CC", cc_m)
    de_harmless = sum(1 for r in rows
                      if r["de_detected"] and r["ground_truth_is_wcd"]
                      and not r["ground_truth_sensitive_target"])
    print(f"  DE also surfaces {de_harmless} harmless WCD (real, low impact).")
    print("\nWrote results/detection.csv and results/summary.json")


if __name__ == "__main__":
    main()
