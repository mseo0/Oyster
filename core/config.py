"""Configuration, resource tiering, and protected-path rules.

Everything here is tuned for an 8GB everyday machine: aggressive skip rules so
the disk walk stays cheap, and an LLM tier that only loads a small model.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

# --- LLM tiering (the model is loaded ON DEMAND during triage, never during ---
# --- the scan, so it never competes with the disk walk for RAM). ------------
def recommended_model() -> str:
    """Pick an Ollama model by RAM. Oyster's AI jobs (summarize, classify, parse)
    are easy, so we default to small/fast models — a ~2 GB 3B model is plenty and
    keeps the first-run download light. Big machines may use a larger one."""
    gb = _total_ram_gb()
    if gb >= 32:
        return "qwen3:8b"      # ~5 GB — only where there's RAM to spare
    if gb >= 12:
        return "llama3.2:3b"   # ~2 GB — the efficient default for most machines
    return "qwen3:1.7b"        # ~1.4 GB — smallest, for tight RAM


def _total_ram_gb() -> float:
    try:
        import psutil  # local-only; no network
        return psutil.virtual_memory().total / (1024 ** 3)
    except Exception:
        return 8.0


# --- Filesystem walk tuning -------------------------------------------------
# Directories we never descend into: noise, huge, or system-owned churn.
SKIP_DIR_NAMES: set[str] = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".cache", "Caches", "DerivedData", ".gradle", ".m2", ".npm",
    "$RECYCLE.BIN", "System Volume Information",
}

# On these OS-owned trees we trust the OS and skip by default (opt-in deep scan
# can override). Keeps an 8GB machine from grinding on millions of system files.
SKIP_DIR_PREFIXES: tuple[str, ...] = (
    "/System", "/private/var/db", "/usr/share",          # macOS
    "C:\\Windows\\WinSxS", "C:\\Windows\\servicing",      # Windows
)

# Only these are worth scanning content-of by default. Everything else is
# hashed + checked against the known-bad DB but skips the heavier engine pass.
INTERESTING_EXTENSIONS: set[str] = {
    # executables / libraries
    ".exe", ".dll", ".sys", ".scr", ".com", ".msi",
    ".app", ".dylib", ".so", ".bin", ".o", ".out",
    # scripts
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".vbs", ".js",
    ".py", ".pl", ".rb", ".php", ".jar",
    # docs that carry macros / payloads
    ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".pdf", ".rtf",
    # archives (ClamAV unpacks these)
    ".zip", ".rar", ".7z", ".gz", ".tar", ".cab", ".iso", ".dmg",
}

# Files above this size skip content scanning (still hashed). 8GB-friendly.
MAX_CONTENT_SCAN_BYTES: int = 200 * 1024 * 1024  # 200 MB


def full_system_roots() -> list[Path]:
    """Every mounted volume — the starting point for a whole-computer scan.

    macOS/Linux: the filesystem root '/'. Windows: every existing drive letter.
    Reading some of these (other users' homes, TCC-protected app data on macOS)
    requires elevated/Full-Disk-Access permission; unreadable trees are simply
    skipped, never fatal.
    """
    if sys.platform.startswith("win"):
        import string
        drives = [Path(f"{d}:\\") for d in string.ascii_uppercase
                  if Path(f"{d}:\\").exists()]
        return drives or [Path("C:\\")]
    return [Path("/")]


# --- Protected paths: NEVER auto-actioned; always require user confirmation --
def _home() -> Path:
    return Path.home()


def protected_path_roots() -> list[Path]:
    h = _home()
    roots = [
        h / "Documents", h / "Desktop", h / "Pictures", h / "Movies",
        h / "Music", h / "Videos",
    ]
    if sys.platform == "darwin":
        roots += [Path("/System"), Path("/Library"), Path("/usr")]
    elif sys.platform.startswith("win"):
        roots += [Path("C:\\Windows"), Path("C:\\Program Files"),
                  Path("C:\\Program Files (x86)")]
    else:
        roots += [Path("/usr"), Path("/etc"), Path("/boot")]
    return [r for r in roots if r.exists()]


# --- Protected processes: NEVER auto-killed. Kill always needs confirmation. -
PROTECTED_PROCESS_NAMES: set[str] = {
    # macOS
    "kernel_task", "launchd", "WindowServer", "loginwindow", "Finder",
    "coreaudiod", "mds", "mds_stores", "syslogd", "UserEventAgent",
    # Windows
    "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "winlogon.exe", "explorer.exe",
    "svchost.exe", "dwm.exe",
}


@dataclass
class ScanConfig:
    roots: list[Path] = field(default_factory=lambda: [Path.home()])
    deep: bool = False          # if True, descend into system trees too
    include_noise: bool = False  # if True, don't even skip caches/build/hidden
    follow_symlinks: bool = False
    db_path: Path = field(
        default_factory=lambda: Path(
            os.environ.get("OYSTER_DB", str(Path.home() / ".oyster" / "scan.db"))
        )
    )
    quarantine_dir: Path = field(
        default_factory=lambda: Path.home() / ".oyster" / "quarantine"
    )
    osv_db_path: Path = field(
        default_factory=lambda: Path.home() / ".oyster" / "osv.db"
    )
    definitions_dir: Path = field(
        default_factory=lambda: Path.home() / ".oyster" / "definitions"
    )
