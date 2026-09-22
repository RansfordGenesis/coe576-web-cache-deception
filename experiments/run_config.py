"""Extension B: cache-configuration sensitivity.

Re-run the lab under three nginx configurations and measure two things per config:
  * DE detections   -- how many endpoints DE flags as vulnerable
  * real leaks      -- how many SENSITIVE pages actually leak to an attacker
                       (victim primes the cache, unauthenticated attacker reads
                        back an identical sensitive body from a cache HIT)

Configs:
  vulnerable.conf  cache static exts + ignore Cache-Control   (the bug)
  honor.conf       cache static exts but obey Cache-Control    (the fix)
  nocache.conf     caching disabled                            (baseline)

This script switches the nginx config via Docker (fresh cache each time), so it
needs Docker running. Output: results/config.csv

Run:  .venv/bin/python experiments/run_config.py
"""
from __future__ import annotations
import csv, subprocess, sys, time, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import requests
from origin.pages import REGISTRY
from detector import de
from detector.http import fetch, cache_status
from detector.attack_urls import generate_attack_url

BASE = "http://localhost:8080"
ROOT = pathlib.Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"; RESULTS.mkdir(exist_ok=True)
CONFIGS = ["vulnerable.conf", "honor.conf", "nocache.conf"]


def switch_config(conf: str) -> None:
    """Recreate the nginx container with the chosen config (empties its cache)."""
    subprocess.run(
        ["docker", "compose", "up", "-d", "--force-recreate", "nginx"],
        cwd=ROOT, env={**_env(), "NGINX_CONF": conf},
        check=True, capture_output=True)
    for _ in range(60):
        try:
            if requests.get(BASE + "/about", timeout=2).status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"stack did not come up for {conf}")


def _env():
    import os
    return dict(os.environ)


def real_leak(url: str) -> bool:
    """True if an unauthenticated attacker reads back the victim's exact
    sensitive response from the cache (a genuine leak)."""
    a = generate_attack_url(url)
    victim = fetch(a, cookies={"user": "VICTIM_SECRET"})
    attacker = fetch(a)
    return (attacker.status_code == 200
            and attacker.text == victim.text
            and cache_status(attacker) == "HIT")


def main() -> None:
    pages = sorted(REGISTRY.values(), key=lambda p: p.path)
    vulnerable_pages = [p for p in pages if p.vulnerable]
    rows = []
    for conf in CONFIGS:
        print(f"\n### switching to {conf} ...")
        switch_config(conf)
        de_hits = sum(de.detect(BASE + p.path).detected for p in pages)
        leaks = sum(real_leak(BASE + p.path) for p in vulnerable_pages)
        print(f"  DE detections: {de_hits:2d}    real leaks: {leaks:2d}"
              f" / {len(vulnerable_pages)} sensitive pages")
        rows.append({"config": conf, "de_detections": de_hits,
                     "real_leaks": leaks,
                     "n_sensitive": len(vulnerable_pages),
                     "n_endpoints": len(pages)})

    with (RESULTS / "config.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    print("\nWrote results/config.csv")
    # leave the lab in the vulnerable config for the other demos
    switch_config("vulnerable.conf")
    print("restored vulnerable.conf")


if __name__ == "__main__":
    main()
