"""
Origin web application for the WCD lab (Paper 7 replication).

Plays the ORIGIN SERVER of Figure 1. It deliberately contains the request-
processing discrepancy WCD exploits: /profile/nonexistent.css is REROUTED to the
dynamic /profile page for 'confusable' endpoints, so a cache in front sees the
".css" suffix and stores a sensitive response.

Run standalone:  uvicorn origin.app:app --port 8000
(In the lab it runs in Docker behind nginx; see docker-compose.yml.)
"""
from __future__ import annotations
import secrets
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse

from origin.pages import REGISTRY, Page

app = FastAPI(title="WCD Lab Origin")

# Extensions a naive cache is likely to treat as static/cacheable. The origin
# uses the same list to recognise a path-confusion attack URL.
STATIC_EXTS = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
               ".woff", ".woff2", ".pdf", ".txt")


def render(page: Page, request: Request) -> Response:
    """Build the response for a known page.

    - static           : identical bytes, Cache-Control: public (safe to cache)
    - sensitive+marker : per-request secrets + echoes the `user` cookie, no-store
    - sensitive+plain  : per-request secrets (CSRF/nonce), no marker, no-store
    - public dynamic   : per-request but NON-sensitive, Cache-Control: public
                         (intentionally cacheable -> a DE false positive)
    """
    if not page.dynamic:
        body = (f"<!doctype html><title>{page.path}</title>"
                f"<h1>Static document {page.path}</h1>"
                f"<p>This content never changes. Nothing sensitive here.</p>")
        return HTMLResponse(body, headers={"Cache-Control": "public, max-age=3600"})

    if not page.sensitive:
        # Public but dynamic (e.g. a news feed): changes per request, safe to
        # cache, and holds NO secret. Caching it is not a real vulnerability.
        headline = secrets.token_hex(4)
        body = (f"<!doctype html><title>{page.path}</title>"
                f"<h1>Public feed</h1><p>Trending id: {headline}</p>"
                f"<p>This page is public and intentionally cacheable.</p>")
        return HTMLResponse(body, headers={"Cache-Control": "public, max-age=60"})

    # Sensitive dynamic content: fabricate per-request secrets.
    csrf = secrets.token_hex(16)
    session = secrets.token_hex(8)
    if page.reflects_marker:
        user = request.cookies.get("user", "guest")
        body = (f"<!doctype html><title>{page.path}</title>"
                f"<h1>Welcome {user}</h1><p>Session: {session}</p>"
                f"<input type=hidden name=csrf value={csrf}>")
    else:
        body = (f"<!doctype html><title>{page.path}</title>"
                f"<h1>Sign in</h1>"
                f"<input type=hidden name=csrf value={csrf}>"
                f"<meta name=csp-nonce content={session}>")
    # Honest origin: never store this. (The vulnerable cache ignores it.)
    return HTMLResponse(body, headers={"Cache-Control": "no-store"})


def resolve(path: str) -> Page | None:
    """Map a raw path to a Page, applying path-confusion rerouting.

    1. exact match -> that page.
    2. /<base>/<file>.<ext> where <base> is confusable -> reroute to <base>
       (THE BUG: origin ignores the bogus static-looking suffix).
    """
    if path in REGISTRY:
        return REGISTRY[path]
    if "/" in path.rstrip("/") and path.lower().endswith(STATIC_EXTS):
        base = path.rsplit("/", 1)[0]
        page = REGISTRY.get(base)
        if page is not None and page.confusable:
            return page
    return None


@app.get("/{full_path:path}")
def catch_all(full_path: str, request: Request) -> Response:
    path = "/" + full_path.lstrip("/")
    page = resolve(path)
    if page is None:
        # Non-confusable pages 404 on the .css variant -> WCD attack fails here.
        return PlainTextResponse("404 Not Found\n", status_code=404)
    return render(page, request)
