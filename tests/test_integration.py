"""Integration tests that require the Docker stack on http://localhost:8080.

Skipped automatically if the stack is not reachable, so `pytest` stays green
without Docker. Start the stack first:  docker compose up -d --build
"""
import pytest, requests
from detector import de, cc

BASE = "http://localhost:8080"


def _up():
    try:
        return requests.get(BASE + "/about", timeout=2).status_code == 200
    except requests.RequestException:
        return False


pytestmark = pytest.mark.skipif(not _up(),
                                reason="stack not running on :8080")


def test_de_flags_login_but_cc_does_not():
    """The paper's headline: DE finds the no-marker page CC is blind to."""
    assert de.detect(BASE + "/login").detected is True
    assert cc.detect(BASE + "/login").detected is False


def test_both_flag_profile():
    assert de.detect(BASE + "/profile").detected is True
    assert cc.detect(BASE + "/profile").detected is True


def test_safe_pages_not_flagged():
    assert de.detect(BASE + "/about").detected is False       # static
    assert de.detect(BASE + "/api/time").detected is False    # not confusable
