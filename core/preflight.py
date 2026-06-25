"""Startup permission & capability checks.

Pure logic (no UI, no network beyond the loopback Ollama probe) so both the GUI
gate and the CLI can use it. Each check returns a Check with a status the caller
renders. macOS Full Disk Access is the one true *permission* gate — there is no
API to request it, so we detect it (by reading a TCC-protected file) and point
the user at System Settings.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from .toolpaths import find_tool


@dataclass
class Check:
    key: str
    name: str
    ok: bool
    required: bool
    detail: str
    fix: str = ""        # human hint on how to satisfy it


def full_disk_access() -> Check:
    """macOS: can we read a TCC-protected file? That implies Full Disk Access."""
    name = "Full Disk Access"
    if sys.platform != "darwin":
        return Check("fda", name, True, required=False,
                     detail="not applicable on this OS")
    # TCC.db is readable only with Full Disk Access — the canonical probe.
    probe = Path.home() / "Library/Application Support/com.apple.TCC/TCC.db"
    try:
        with open(probe, "rb") as fh:
            fh.read(1)
        return Check("fda", name, True, required=True, detail="granted")
    except PermissionError:
        return Check("fda", name, False, required=True,
                     detail="not granted — private & system folders will be "
                            "skipped during a scan",
                     fix="System Settings → Privacy & Security → Full Disk "
                         "Access → add Oyster, then re-check")
    except FileNotFoundError:
        # Unusual, but fall back to another protected location.
        alt = Path.home() / "Library/Mail"
        try:
            if alt.exists():
                list(alt.iterdir())
            return Check("fda", name, True, required=True, detail="granted")
        except PermissionError:
            return Check("fda", name, False, required=True,
                         detail="not granted",
                         fix="System Settings → Privacy & Security → Full Disk "
                             "Access → add Oyster, then re-check")
    except OSError:
        return Check("fda", name, True, required=True,
                     detail="could not determine (assuming ok)")


def storage(cfg_dir: Path) -> Check:
    """We must be able to create ~/.oyster for the DB and quarantine vault."""
    name = "Local storage"
    try:
        cfg_dir.mkdir(parents=True, exist_ok=True)
        probe = cfg_dir / ".write_test"
        probe.write_text("ok")
        probe.unlink()
        return Check("storage", name, True, required=True, detail=str(cfg_dir))
    except OSError as e:
        return Check("storage", name, False, required=True,
                     detail=f"cannot write {cfg_dir}: {e}",
                     fix="ensure your home folder is writable")


def clamav() -> Check:
    """ClamAV is the detection engine. Recommended, not a hard gate."""
    name = "ClamAV engine"
    path = find_tool("clamscan") or find_tool("clamdscan")
    if path:
        return Check("clamav", name, True, required=False, detail=path)
    install = ("brew install clamav && freshclam" if sys.platform == "darwin"
               else "winget install ClamAV.ClamAV  (then freshclam)"
               if sys.platform.startswith("win")
               else "install clamav via your package manager, then freshclam")
    return Check("clamav", name, False, required=False,
                 detail="not found — scans run without signature/YARA matching",
                 fix=install)


def ollama(model: str) -> Check:
    """Local LLM for plain-English reports. Optional — heuristic fallback works."""
    name = "Ollama (AI reports)"
    try:
        from agent.ollama_client import Ollama
        if Ollama(model).available():
            return Check("ollama", name, True, required=False,
                         detail="reachable on 127.0.0.1:11434")
    except Exception:
        pass
    return Check("ollama", name, False, required=False,
                 detail="not running — reports use the offline heuristic",
                 fix=f"ollama serve  &&  ollama pull {model}")


def run_all(cfg_dir: Path, model: str) -> list[Check]:
    return [full_disk_access(), storage(cfg_dir), clamav(), ollama(model)]


def blocking(checks: list[Check]) -> list[Check]:
    """Required checks that are not satisfied — these block launch."""
    return [c for c in checks if c.required and not c.ok]
