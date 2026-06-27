"""Locate external CLI tools (clamscan, freshclam, …) robustly.

A macOS app launched from Finder/Dock inherits only a minimal PATH
(/usr/bin:/bin:/usr/sbin:/sbin) — it does NOT see Homebrew's /opt/homebrew/bin.
So shutil.which("clamscan") returns None inside the bundled .app even though
ClamAV is installed. We fall back to the well-known install directories per OS.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


def _extra_dirs() -> list[str]:
    if sys.platform == "darwin":
        return ["/opt/homebrew/bin", "/opt/homebrew/sbin",   # Apple-silicon brew
                "/usr/local/bin", "/usr/local/sbin",          # Intel brew
                "/opt/local/bin", "/opt/local/sbin",          # MacPorts
                "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    if sys.platform.startswith("win"):
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        return [rf"{pf}\ClamAV", rf"{pf}\ClamAV\bin",
                rf"{pf86}\ClamAV", rf"{pf86}\ClamAV\bin"]
    return ["/usr/bin", "/usr/local/bin", "/bin", "/usr/sbin", "/sbin"]


def ensure_path() -> None:
    """Prepend known tool dirs to PATH so a Finder-launched app (minimal PATH)
    and any subprocess it spawns can find Homebrew/MacPorts/ClamAV binaries.

    Call once at startup. Idempotent; only adds dirs that exist and are missing.
    """
    current = os.environ.get("PATH", "")
    parts = current.split(os.pathsep) if current else []
    have = set(parts)
    add = [d for d in _extra_dirs() if d not in have and os.path.isdir(d)]
    if add:
        os.environ["PATH"] = os.pathsep.join(add + parts)


def bundled_clamav() -> Path | None:
    """If the app ships its own ClamAV (Windows builds do), return its clamscan.
    Layout: <resources>/clamav/clamscan(.exe), engine at <resources>/engine/...
    so it's two levels up from the frozen engine binary."""
    if not getattr(sys, "frozen", False):
        return None
    exe = "clamscan.exe" if sys.platform.startswith("win") else "clamscan"
    try:
        cand = Path(sys.executable).resolve().parents[2] / "clamav" / exe
        return cand if cand.is_file() else None
    except (IndexError, OSError):
        return None


def find_tool(name: str) -> str | None:
    """Absolute path to `name` from PATH or a known location, else None."""
    found = shutil.which(name)
    if found:
        return found
    exe = name + (".exe" if sys.platform.startswith("win") else "")
    for d in _extra_dirs():
        cand = Path(d) / exe
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return None


def find_clamav_db() -> str | None:
    """Return a path to a ClamAV database directory that contains .cvd/.cld files,
    or None if only the system default should be used (clamscan finds it itself)."""
    candidates: list[Path] = []
    if sys.platform.startswith("win"):
        local = Path(os.environ.get("LOCALAPPDATA", "")) / "ClamAV" / "db"
        pf = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "ClamAV" / "database"
        candidates = [local, pf]
    elif sys.platform == "darwin":
        candidates = [Path("/usr/local/var/lib/clamav"),
                      Path("/opt/homebrew/var/lib/clamav"),
                      Path.home() / ".clamav"]
    else:
        candidates = [Path("/var/lib/clamav"), Path("/var/lib/clamav/db")]
    for d in candidates:
        if d.is_dir() and any(d.glob("*.cvd")) or (d.is_dir() and any(d.glob("*.cld"))):
            return str(d)
    return None
