"""Process inspector — the "Activity Monitor / Task Manager" threat module.

Enumerates running processes via psutil, scores each with cheap heuristics, and
(optionally) feeds the backing executable to the ClamAV engine. Killing is never
done here automatically: this module only *reports*. The approval gate +
PROTECTED_PROCESS_NAMES decide whether a kill is even offered.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import config, signing

try:
    import psutil
except ImportError:  # keep import-safe so the rest of the app loads
    psutil = None


# Directories from which a running binary is inherently suspicious.
_WRITABLE_HOTSPOTS = ("/tmp", "/private/tmp", "/var/tmp")


@dataclass
class ProcThreat:
    pid: int
    name: str
    exe: str
    username: str
    score: int
    reasons: list[str] = field(default_factory=list)
    connections: int = 0
    protected: bool = False


def _is_in_writable_hotspot(exe: str) -> bool:
    low = exe.lower()
    if any(h in low for h in _WRITABLE_HOTSPOTS):
        return True
    home = str(Path.home()).lower()
    return (f"{home}/downloads" in low) or ("\\temp\\" in low) or \
           ("\\downloads\\" in low) or ("appdata\\local\\temp" in low)


def _masquerades(name: str, exe: str) -> bool:
    """A trusted system name running from a non-system path."""
    sysish = {"svchost.exe", "explorer.exe", "lsass.exe", "chrome", "Finder"}
    if name in sysish and exe:
        low = exe.lower()
        if sys.platform.startswith("win") and "windows" not in low \
                and "program files" not in low:
            return True
        if sys.platform == "darwin" and not low.startswith(
                ("/system", "/applications", "/usr")):
            return True
    return False


def inspect(check_signatures: bool = True) -> list[ProcThreat]:
    if psutil is None:
        return []
    threats: list[ProcThreat] = []
    for proc in psutil.process_iter(["pid", "name", "exe", "username"]):
        try:
            info = proc.info
            name = info.get("name") or ""
            exe = info.get("exe") or ""
            score = 0
            reasons: list[str] = []

            if exe and _is_in_writable_hotspot(exe):
                score += 40
                reasons.append("runs from a writable/temp/downloads dir")

            if _masquerades(name, exe):
                score += 45
                reasons.append("name masquerades as a system process")

            conns = 0
            try:
                conns = len(proc.net_connections(kind="inet"))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            if conns and exe and _is_in_writable_hotspot(exe):
                score += 20
                reasons.append(f"{conns} network connection(s) from temp binary")

            if check_signatures and exe and score >= 20:
                si = signing.verify(Path(exe))
                if si.checked and not si.valid:
                    score += 25
                    reasons.append("executable is unsigned / signature invalid")

            if score <= 0:
                continue

            threats.append(ProcThreat(
                pid=info.get("pid", -1),
                name=name,
                exe=exe,
                username=info.get("username") or "",
                score=min(score, 100),
                reasons=reasons,
                connections=conns,
                protected=name in config.PROTECTED_PROCESS_NAMES,
            ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return sorted(threats, key=lambda t: t.score, reverse=True)


def suspend(pid: int) -> None:
    """Suspend (freeze) rather than kill — reversible, gentler default."""
    if psutil is None:
        raise RuntimeError("psutil not installed")
    psutil.Process(pid).suspend()


def terminate(pid: int, name: str) -> None:
    """Hard kill. Callers MUST have an approval + protected-name check first."""
    if psutil is None:
        raise RuntimeError("psutil not installed")
    if name in config.PROTECTED_PROCESS_NAMES:
        raise PermissionError(f"refusing to kill protected process {name}")
    psutil.Process(pid).terminate()
