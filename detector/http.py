"""HTTP helpers + the cache-status heuristic (paper section 3.2, Table 1).

DE cannot assume every cache uses the same header. The paper compiled a list of
cache-status headers per vendor (Akamai `X-Cache`, Cloudflare `cf-cache-status`,
Fastly `X-Cache`, nginx `X-Proxy-Cache`, ...) and, instead of exact matching,
NORMALISES the value and keyword-searches for "hit" / "miss". We do the same, so
our detector is not hard-wired to our own lab's header.
"""
from __future__ import annotations
import requests

# Header names that popular caches use to report the lookup result (Table 1),
# plus our lab's nginx `X-Cache-Status`.
CACHE_HEADERS = [
    "x-cache-status", "x-cache", "x-cache-remote", "cf-cache-status",
    "cdn_cache_status", "x-proxy-cache", "x-rack-cache", "x-cache-info",
    "server-timing",
]


def fetch(url: str, cookies: dict | None = None, timeout: float = 10.0) -> requests.Response:
    """A single GET with a fresh client state (no cookie unless given)."""
    return requests.get(url, cookies=cookies or {}, timeout=timeout,
                        allow_redirects=False)


def cache_status(resp: requests.Response) -> str:
    """Return 'HIT', 'MISS', or 'UNKNOWN' by keyword-searching cache headers."""
    for name in CACHE_HEADERS:
        val = resp.headers.get(name)
        if not val:
            continue
        v = val.lower()
        # keyword search over the value (paper section 3.2). Order matters:
        # check the more specific 'caching'/'miss' before 'cached'/'hit'.
        if "miss" in v or "caching" in v:
            return "MISS"
        if "hit" in v or "cached" in v:
            return "HIT"
    return "UNKNOWN"
