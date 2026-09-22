"""CC: the "Cached and Confused" (2020) marker-injection detector.

This is the PRIOR method that Paper 7 improves on. We implement it so we can
reproduce the paper's headline comparison (Table 2): DE finds vulnerabilities
CC cannot.

How CC works (paper section 2.3), in our lab:
  1. "Create an account" = plant a unique MARKER in the `user` cookie.
  2. Authenticated victim requests the WCD attack URL (/path/<rand>.css) WITH
     the marker cookie -> if the page reflects it, the marked response is cached.
  3. Unauthenticated attacker requests the SAME URL WITHOUT the cookie. If the
     marker appears in the attacker's response, a private page leaked -> WCD.

CC's built-in blind spot: if a page does not ECHO the marker (e.g. a login page
that only shows a CSRF token), the marker never appears in any response, so CC
can never detect the leak -- no matter how vulnerable the page really is.
"""
from __future__ import annotations
import secrets
from dataclasses import dataclass, field

from detector.http import fetch
from detector.attack_urls import generate_attack_url


@dataclass
class CCResult:
    url: str
    detected: bool
    reason: str
    trace: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        verdict = "WCD DETECTED" if self.detected else "not detected"
        return f"[{verdict}] {self.url}  ({self.reason})"


def detect(base_url: str, verbose: bool = False) -> CCResult:
    trace: list[str] = []

    def log(msg: str) -> None:
        trace.append(msg)
        if verbose:
            print("    " + msg)

    marker = "CCMARKER_" + secrets.token_hex(8)
    attack = generate_attack_url(base_url)

    # Step 2: authenticated victim primes the cache with the marked response.
    fetch(attack, cookies={"user": marker})
    log(f"victim GET {attack} with marker={marker}")

    # Step 3: unauthenticated attacker reads the same URL back.
    r = fetch(attack)
    leaked = marker in r.text
    log(f"attacker GET {attack} -> marker {'PRESENT' if leaked else 'absent'}")

    if leaked:
        return CCResult(base_url, True, "marker leaked to attacker", trace)
    return CCResult(base_url, False, "marker never appeared (no reflection / not cached)", trace)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("usage: python -m detector.cc <url>"); raise SystemExit(2)
    print(detect(sys.argv[1], verbose=True))
