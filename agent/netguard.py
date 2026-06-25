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
