"""No-egress enforcement.

The agent may talk ONLY to the local Ollama server on loopback. Any attempt to
reach a non-loopback host raises. This is defense-in-depth on top of "the core
imports no network libraries at all": even the one component that uses a socket
is pinned to localhost, so nothing — including your IP/location — can leak.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

OLLAMA_HOST = "127.0.0.1"
OLLAMA_PORT = 11434
OLLAMA_URL = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}"

# The ONLY non-loopback hosts the app may ever contact, and only on the explicit,
# off-by-default "Online" path of the AI chat (see agent/websearch.py). Even with
# online mode on, egress is pinned to this one search engine — never an arbitrary
# URL the model might produce. The scanner never imports this module at all.
SEARCH_HOSTS = frozenset({
    "html.duckduckgo.com", "duckduckgo.com", "lite.duckduckgo.com",
})


class EgressBlocked(RuntimeError):
    pass


def assert_loopback(url: str) -> str:
    """Raise unless `url` points at the loopback interface. Returns the url."""
    host = urlparse(url).hostname or ""
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_loopback:
            raise EgressBlocked(f"blocked non-loopback host: {host}")
    except ValueError:
        if host != "localhost":
            raise EgressBlocked(f"blocked non-loopback host: {host}")
    return url


def assert_search_host(url: str) -> str:
    """Raise unless `url` is the sanctioned web-search host. Used ONLY by the
    opt-in online AI chat path, so even then nothing else can be reached."""
    host = (urlparse(url).hostname or "").lower()
    if host not in SEARCH_HOSTS:
        raise EgressBlocked(f"web search blocked non-search host: {host}")
    if urlparse(url).scheme != "https":
        raise EgressBlocked("web search must use https")
    return url
