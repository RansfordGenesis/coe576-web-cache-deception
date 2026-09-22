"""Generate WCD attack URLs (paper section 3.1).

Core technique: append a path segment that looks like a static file, e.g.
    /profile        ->  /profile/<random>.css
The filename is randomised so two calls produce two different attack URLs
(Algorithm 1 needs two) and so real users never hit a poisoned cache entry.

We modify only the PATH component, preserving scheme/host/query, so URLs that
carry a query string or fragment are handled correctly.
"""
from __future__ import annotations
import secrets
from urllib.parse import urlsplit, urlunsplit


def generate_attack_url(base_url: str, ext: str = "css") -> str:
    parts = urlsplit(base_url)
    new_path = parts.path.rstrip("/") + "/" + f"{secrets.token_hex(6)}.{ext}"
    # drop any fragment; keep query so it still reaches the same endpoint
    return urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, ""))
