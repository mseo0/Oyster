"""Minimal version comparison for OSV range evaluation.

Uses `packaging.version` when available (best for PyPI semver-ish versions) and
falls back to a tolerant tuple comparison otherwise. Deliberately dependency-
free so the core stays installable on a bare Python.
"""
from __future__ import annotations

import re

try:
    from packaging.version import Version, InvalidVersion  # type: ignore

    def _parse(v: str):
        try:
            return ("pep440", Version(v))
        except InvalidVersion:
            return ("loose", _loose(v))
except Exception:  # packaging not installed
    def _parse(v: str):
        return ("loose", _loose(v))


def _loose(v: str) -> tuple:
    parts = re.split(r"[.\-_+]", v.strip())
    out: list[tuple[int, object]] = []
    for p in parts:
        if p.isdigit():
            out.append((0, int(p)))      # numeric sorts before/with numeric
        elif p:
            out.append((1, p))           # strings after numbers at same slot
    return tuple(out)


def compare(a: str, b: str) -> int:
    """Return -1/0/1 for a<b / a==b / a>b. Never raises."""
    ka, va = _parse(a)
    kb, vb = _parse(b)
    if ka == kb == "pep440":
        return (va > vb) - (va < vb)
    # mixed or loose: compare loose tuples
    la = va if ka == "loose" else _loose(a)
    lb = vb if kb == "loose" else _loose(b)
    return (la > lb) - (la < lb)


def in_range(version: str, introduced: str | None, fixed: str | None) -> bool:
    """True if introduced <= version < fixed (OSV semantics)."""
    if introduced and introduced != "0" and compare(version, introduced) < 0:
        return False
    if fixed and compare(version, fixed) >= 0:
        return False
    return True
