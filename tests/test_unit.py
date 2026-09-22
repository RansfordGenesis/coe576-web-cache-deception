"""Unit tests that DO NOT need the Docker stack (fast, deterministic).

They cover the detector's building blocks and its decision logic using a fake
HTTP layer, so the whole DE algorithm is exercised without a running server.
"""
import pytest
from requests.structures import CaseInsensitiveDict

from detector import de
from detector.attack_urls import generate_attack_url
from detector.http import cache_status
from origin.pages import REGISTRY


# --- cache-status heuristic (paper Table 1) ---------------------------------
class FakeResp:
    def __init__(self, headers=None, text=""):
        self.headers = CaseInsensitiveDict(headers or {})
        self.text = text
        self.status_code = 200


@pytest.mark.parametrize("headers,expected", [
    ({"X-Cache-Status": "HIT"}, "HIT"),
    ({"X-Cache-Status": "MISS"}, "MISS"),
    ({"cf-cache-status": "hit"}, "HIT"),          # Cloudflare, lowercase
    ({"X-Cache": "Hit from cloudfront"}, "HIT"),  # keyword search, not exact
    ({"X-Cache": "Miss from cloudfront"}, "MISS"),
    ({"whatever": "nonsense"}, "UNKNOWN"),
    ({}, "UNKNOWN"),
])
def test_cache_status_heuristic(headers, expected):
    assert cache_status(FakeResp(headers)) == expected


def test_generate_attack_url_shape():
    u = generate_attack_url("http://x/profile")
    assert u.startswith("http://x/profile/") and u.endswith(".css")
    # two calls -> two different URLs (DE needs distinct attack URLs)
    assert generate_attack_url("http://x/p") != generate_attack_url("http://x/p")


# --- DE decision logic with a scripted fake network -------------------------
def make_fake_fetch(script):
    """script: callable(url) -> (text, cache_status_str)."""
    def fake_fetch(url, cookies=None, timeout=10.0):
        text, cs = script(url)
        return FakeResp(headers={"X-Cache-Status": cs}, text=text)
    return fake_fetch


def test_de_detects_vulnerable(monkeypatch):
    """Dynamic base, dynamic attack URLs, MISS then HIT -> detected."""
    state = {"n": 0}
    def script(url):
        state["n"] += 1
        if url.endswith((".css",)):
            # first two distinct attack URLs are MISS w/ unique bodies;
            # a repeat of the first returns HIT with its stored body.
            return (f"secret-{url}", "HIT" if url in seen else "MISS")
        return (f"dyn-{state['n']}", "UNKNOWN")   # base URL: changes each call
    seen = set()
    orig = make_fake_fetch(script)
    def tracking_fetch(url, cookies=None, timeout=10.0):
        r = orig(url, cookies, timeout); seen.add(url); return r
    monkeypatch.setattr(de, "fetch", tracking_fetch)
    res = de.detect("http://x/profile")
    assert res.detected and res.stopped_at == "step3"


def test_de_rejects_static(monkeypatch):
    """Identical base bodies -> not dynamic -> stop at step 1."""
    monkeypatch.setattr(de, "fetch",
                        make_fake_fetch(lambda u: ("same", "UNKNOWN")))
    res = de.detect("http://x/about")
    assert not res.detected and res.stopped_at == "step1"


def test_ground_truth_counts():
    """The dataset is balanced the way the experiment assumes."""
    vuln = sum(p.vulnerable for p in REGISTRY.values())
    assert len(REGISTRY) == 55 and vuln == 22
