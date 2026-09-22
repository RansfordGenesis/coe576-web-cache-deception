"""Run the DE detector on a few representative endpoints and print the trace.

Run it yourself:   .venv/bin/python experiments/demo_de.py
Requires the stack up:  docker compose up -d --build
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # repo root
from detector.de import detect

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"

CASES = [
    ("/profile",  "vulnerable, reflects a marker  -> CC and DE find it"),
    ("/login",    "vulnerable, NO marker (CSRF)   -> only DE finds it"),
    ("/api/time", "dynamic but not confusable     -> SAFE (true negative)"),
    ("/about",    "static page                    -> SAFE (true negative)"),
]

print(f"Running DE against {BASE}\n" + "=" * 65)
for path, note in CASES:
    print(f"\n### {path}   ({note})")
    res = detect(BASE + path, verbose=True)
    verdict = "WCD DETECTED" if res.detected else "not detected"
    print(f"  => {verdict}  [stopped at {res.stopped_at}: {res.reason}]")
