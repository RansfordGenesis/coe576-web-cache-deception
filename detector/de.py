"""DE: the WCD detector from "Web Cache Deception Escalates!" (Algorithm 1).

This is the paper's central contribution and our central replication. It decides
"vulnerable / not" for a URL using three marker-free checks:

    Step 1  is the URL dynamic?              (two GETs differ)
    Step 2  does an attack URL still return  (two attack URLs differ AND the
            dynamic content, first a MISS?    first one is a cache MISS)
    Step 3  is it cached?                     (re-request -> HIT, identical body)

Run a single URL with a full trace:
    python -m detector.de http://localhost:8080/profile
"""
from __future__ import annotations
import sys
from dataclasses import dataclass, field

from detector.http import fetch, cache_status
from detector.attack_urls import generate_attack_url


@dataclass
class DEResult:
    url: str
    detected: bool
    stopped_at: str            # "step1" | "step2" | "step3"
    reason: str
    trace: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        verdict = "WCD DETECTED" if self.detected else "not detected"
        lines = [f"[{verdict}] {self.url}  ({self.reason})"]
        lines += [f"    {t}" for t in self.trace]
        return "\n".join(lines)


def detect(base_url: str, verbose: bool = False) -> DEResult:
    trace: list[str] = []

    def log(msg: str) -> None:
        trace.append(msg)
        if verbose:
            print("    " + msg)

    # --- Step 1: is the base URL dynamic? (Algorithm 1 lines 1-3) -----------
    r1, r2 = fetch(base_url), fetch(base_url)
    log(f"Step1 GET {base_url} x2 -> bodies {'differ' if r1.text != r2.text else 'identical'}")
    if r1.text == r2.text:
        return DEResult(base_url, False, "step1", "not dynamic", trace)

    # --- Step 2: attack URLs still dynamic, first one a MISS? (lines 4-8) ---
    a1, a2 = generate_attack_url(base_url), generate_attack_url(base_url)
    ra1, ra2 = fetch(a1), fetch(a2)
    log(f"Step2 GET {a1} -> {cache_status(ra1)}")
    log(f"Step2 GET {a2} -> {cache_status(ra2)}")
    log(f"Step2 attack bodies {'differ' if ra1.text != ra2.text else 'identical'}")
    if ra1.text == ra2.text:
        return DEResult(base_url, False, "step2",
                        "attack URL not dynamic (reroute failed / static)", trace)
    if cache_status(ra1) != "MISS":
        return DEResult(base_url, False, "step2",
                        f"first attack request was not a MISS ({cache_status(ra1)})", trace)

    # --- Step 3: re-request attack URL1 -> HIT, identical body? (lines 9-11) -
    ra1b = fetch(a1)
    log(f"Step3 re-GET {a1} -> {cache_status(ra1b)}, "
        f"body {'matches' if ra1b.text == ra1.text else 'changed'}")
    if ra1b.text == ra1.text and cache_status(ra1b) == "HIT":
        return DEResult(base_url, True, "step3", "MISS->HIT, identical body", trace)
    return DEResult(base_url, False, "step3",
                    f"re-request not a matching HIT ({cache_status(ra1b)})", trace)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python -m detector.de <url>")
        raise SystemExit(2)
    print(detect(sys.argv[1], verbose=True))
