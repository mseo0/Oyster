"""Minimal Ollama client — loopback only, stdlib only.

Uses urllib but every request is forced through netguard.assert_loopback, so it
can only ever reach 127.0.0.1. If Ollama isn't running we degrade gracefully and
the caller falls back to a deterministic, non-AI summary.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from . import netguard


class Ollama:
    def __init__(self, model: str, base_url: str = netguard.OLLAMA_URL):
        self.model = model
        self.base_url = netguard.assert_loopback(base_url)

    def available(self) -> bool:
        try:
            req = urllib.request.Request(
                netguard.assert_loopback(f"{self.base_url}/api/tags")
            )
            with urllib.request.urlopen(req, timeout=2) as r:
                return r.status == 200
        except Exception:
            return False

    def generate(self, prompt: str, system: str = "",
                 fmt_json: bool = False) -> str:
        body = {
            "model": self.model,
            "prompt": prompt,
            "system": system,
            "stream": False,
        }
        if fmt_json:
            body["format"] = "json"
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            netguard.assert_loopback(f"{self.base_url}/api/generate"),
            data=data, headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read())["response"]
