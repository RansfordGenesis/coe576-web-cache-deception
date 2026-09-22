"""
The origin's endpoint registry -- the GROUND TRUTH for our experiments.

Each page has five properties. Three map onto DE's Algorithm-1 checks; the other
two decide what the OLD method (CC) and the true security label are:

    dynamic          -> DE Step 1  (does the body change between two requests?)
    confusable       -> DE Step 2  (does /path/x.css reroute back to this page?)
    (cache stores it)-> DE Step 3  (decided by nginx, not here)

    sensitive        -> is the leaked dynamic data actually secret (session /
                        CSRF)? By the paper's definition ANY dynamic content that
                        is erroneously cached is a WCD vulnerability; whether the
                        content is sensitive only decides its IMPACT. Non-sensitive
                        WCD is a real finding whose leak is HARMLESS (the paper's
                        "harmless" category, Table 3). We make the evaluation
                        TARGET the sensitive (high-impact) WCD that a security team
                        cares about, so a detector flagging a harmless WCD counts
                        against target-precision -- not because the detector erred,
                        but because the finding is out of the sensitive target.
    reflects_marker  -> does the page echo a user-controlled value? CC can only
                        detect a leak on such pages. Pages with no marker are
                        the COVERAGE GAP (P1) that DE sees but CC cannot.

Any WCD                    <=>  dynamic AND confusable  (erroneous caching).
Detection TARGET (sensitive) <=>  dynamic AND confusable AND sensitive.
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class Page:
    path: str
    dynamic: bool
    sensitive: bool
    reflects_marker: bool
    confusable: bool
    label: str

    @property
    def is_wcd(self) -> bool:
        """Any WCD by the paper's definition: dynamic content erroneously
        cached under a path-confusion URL (regardless of impact)."""
        return self.dynamic and self.confusable

    @property
    def vulnerable(self) -> bool:
        """Our evaluation TARGET: a SENSITIVE (high-impact) WCD. Harmless WCD
        (non-sensitive) is real but out of target; see the module docstring."""
        return self.dynamic and self.confusable and self.sensitive


N_PER_CATEGORY = 10  # synthetic pages per category (plus one named 'hero' each)


def build_registry() -> dict[str, Page]:
    pages: list[Page] = []

    def add(path, dynamic, sensitive, marker, confusable, label):
        pages.append(Page(path, dynamic, sensitive, marker, confusable, label))

    # ---- Hero pages (used in the walkthrough & slides) ----------------------
    # VULNERABLE + reflects a marker            -> CC and DE both detect
    add("/profile", True,  True,  True,  True,  "sensitive+marker")
    # VULNERABLE + no marker (CSRF/login page)  -> DE only (coverage gap)
    add("/login",   True,  True,  False, True,  "sensitive+no-marker")
    # NOT vulnerable: public dynamic, cacheable -> DE FALSE POSITIVE
    add("/news",    True,  False, False, True,  "WCD (harmless)")
    # NOT vulnerable: dynamic but not confusable-> true negative
    add("/api/time",True,  True,  False, False, "safe: not-confusable")
    # NOT vulnerable: static                    -> true negative
    add("/about",   False, False, False, False, "safe: static")

    # ---- Synthetic pages for statistical weight -----------------------------
    for i in range(1, N_PER_CATEGORY + 1):
        add(f"/dash{i}", True,  True,  True,  True,  "sensitive+marker")     # DE+CC
        add(f"/csrf{i}", True,  True,  False, True,  "sensitive+no-marker")  # DE only
        add(f"/feed{i}", True,  False, False, True,  "WCD (harmless)")       # DE false pos
        add(f"/api{i}",  True,  True,  False, False, "safe: not-confusable") # TN
        add(f"/doc{i}",  False, False, False, False, "safe: static")         # TN

    return {p.path: p for p in pages}


REGISTRY = build_registry()
