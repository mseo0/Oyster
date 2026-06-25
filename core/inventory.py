"""Installed-software inventory — cross-platform, fully local.

Enumerates packages so the vulnerability auditor can match them against the
local OSV snapshot. Shells out to package managers (no network). Each item is
(ecosystem, name, version) where ecosystem matches OSV's naming ("PyPI", "npm").
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class Package:
    ecosystem: str
    name: str
    version: str


def collect() -> list[Package]:
    pkgs: list[Package] = []
    pkgs += _python_packages()
    pkgs += _npm_global()
    pkgs += _homebrew()
    # de-dup
    return sorted(set(pkgs), key=lambda p: (p.ecosystem, p.name))


def _python_packages() -> list[Package]:
    out: list[Package] = []
    try:
        from importlib import metadata
        for dist in metadata.distributions():
            name = (dist.metadata["Name"] or "").strip()
            ver = (dist.version or "").strip()
            if name and ver:
                out.append(Package("PyPI", name.lower(), ver))
    except Exception:
        pass
    return out


def _npm_global() -> list[Package]:
    npm = shutil.which("npm")
    if not npm:
        return []
    try:
        proc = subprocess.run(
            [npm, "ls", "-g", "--depth=0", "--json"],
            capture_output=True, text=True, timeout=60,
        )
        data = json.loads(proc.stdout or "{}")
        deps = data.get("dependencies", {}) or {}
        return [Package("npm", n.lower(), (v or {}).get("version", ""))
                for n, v in deps.items() if (v or {}).get("version")]
    except Exception:
        return []


def _homebrew() -> list[Package]:
    """Inventoried for visibility; OSV has no 'Homebrew' ecosystem, so these are
    reported but not version-matched against OSV."""
    brew = shutil.which("brew")
    if not brew:
        return []
    try:
        proc = subprocess.run(
            [brew, "list", "--versions", "--formula"],
            capture_output=True, text=True, timeout=60,
        )
        out: list[Package] = []
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                out.append(Package("Homebrew", parts[0].lower(), parts[1]))
        return out
    except Exception:
        return []
