"""Opt-in web search for the AI chat — OFF by default.

This is the one and only component in Oyster that can leave the machine, and it
only runs when the user explicitly flips the "Online" toggle in the AI chat and
the sidecar passes online=True. The scanner never imports this module.

Even when enabled, egress is pinned by netguard.assert_search_host to a single
search engine (DuckDuckGo's no-JS HTML endpoint) — so an online answer can pull
in a few public result snippets for the model to ground itself on, but the app
can never be steered into fetching an arbitrary URL. We send only the query the
user/AI composed; never the file's bytes.
"""
from __future__ import annotations

import html
import re
import urllib.parse
import urllib.request

from . import netguard

SEARCH_URL = "https://html.duckduckgo.com/html/"
_UA = "Mozilla/5.0 (compatible; Oyster-AV/1.0; local antivirus assistant)"

_RESULT = re.compile(
    r'<a[^>]+class="result__a"[^>]+href="(?P<href>[^"]+)"[^>]*>(?P<title>.*?)</a>',
    re.S)
_SNIPPET = re.compile(
    r'<a[^>]+class="result__snippet"[^>]*>(?P<snip>.*?)</a>', re.S)
_TAG = re.compile(r"<[^>]+>")


def _clean(s: str) -> str:
    return html.unescape(_TAG.sub("", s)).strip()


def _real_url(href: str) -> str:
    """DuckDuckGo wraps hits in a /l/?uddg=<encoded> redirect — unwrap it."""
    if "uddg=" in href:
        q = urllib.parse.urlparse(href).query
        u = urllib.parse.parse_qs(q).get("uddg")
        if u:
            return u[0]
    return href if href.startswith("http") else "https:" + href


def search(query: str, max_results: int = 5, timeout: int = 8) -> list[dict]:
    """Return up to max_results {title, url, snippet} dicts. Raises EgressBlocked
    if anything tries to redirect off the sanctioned search host."""
    query = (query or "").strip()
    if not query:
        return []
    netguard.assert_search_host(SEARCH_URL)
    data = urllib.parse.urlencode({"q": query, "kl": "us-en"}).encode()
    req = urllib.request.Request(
        SEARCH_URL, data=data,
        headers={"User-Agent": _UA,
                 "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        netguard.assert_search_host(r.geturl())   # block redirect-off attempts
        body = r.read().decode("utf-8", "replace")

    titles = list(_RESULT.finditer(body))
    snips = list(_SNIPPET.finditer(body))
    out: list[dict] = []
    for i, m in enumerate(titles[:max_results]):
        snip = _clean(snips[i].group("snip")) if i < len(snips) else ""
        out.append({"title": _clean(m.group("title")),
                    "url": _real_url(m.group("href")),
                    "snippet": snip})
    return out


def context_block(query: str, max_results: int = 5) -> tuple[str, list[dict]]:
    """A compact, model-ready text block of web results plus the raw list (for
    citing sources in the UI). Returns ("", []) on any failure so the chat always
    degrades gracefully back to an offline answer."""
    try:
        results = search(query, max_results=max_results)
    except Exception:
        return "", []
    if not results:
        return "", []
    lines = []
    for i, r in enumerate(results, 1):
        lines.append(f"[{i}] {r['title']}\n{r['snippet']}\n({r['url']})")
    return "\n\n".join(lines), results
