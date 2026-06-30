"""Application cleanup — list installed apps with the files they scatter across
the system, so the user can uninstall an app *and* the leftovers it leaves
behind (caches, preferences, support files, sandbox containers, …).

Analysis here is read-only. Removal reuses organize.execute('delete'), which
moves the .app bundle and the selected leftovers to ~/.oyster/cleanup rather
than hard-deleting them — so an uninstall is just as reversible as everything
else Oyster does.

macOS-focused: enumerates the Applications folders, reads each bundle id from
Info.plist, and matches that id / the app name against the standard ~/Library
locations apps write to. On other platforms it returns an empty list with a
note rather than guessing.
"""
from __future__ import annotations

import os
import plistlib
import subprocess
import sys
import time
from pathlib import Path

from core.organize import _human

_APP_DIRS = ["/Applications", "/Applications/Utilities",
             str(Path.home() / "Applications")]

# Per-user ~/Library locations apps drop data into, each with a friendly label
# shown next to the file in the review list.
_LIBRARY = {
    "Application Support": "support files",
    "Caches": "cache",
    "Preferences": "preferences",
    "Preferences/ByHost": "per-host preferences",
    "Logs": "logs",
    "Containers": "sandbox container",
    "Group Containers": "group container",
    "Application Scripts": "sandbox scripts",
    "Saved Application State": "saved state",
    "HTTPStorages": "web storage",
    "WebKit": "web data",
    "Cookies": "cookies",
    "LaunchAgents": "launch agent",
    "Crash Reports": "crash reports",
}
_CAP = 300   # max leftover entries returned per app


def _du(path: Path) -> int:
    """Bytes used by a file or directory tree. Uses `du` for speed on posix."""
    try:
        if path.is_symlink() or path.is_file():
            return path.lstat().st_size
    except OSError:
        return 0
    if sys.platform != "win32":
        try:
            out = subprocess.run(["du", "-sk", str(path)], capture_output=True,
                                 text=True, timeout=30)
            if out.returncode == 0 and out.stdout.split():
                return int(out.stdout.split()[0]) * 1024
        except Exception:
            pass
    total = 0
    for dp, _dn, fns in os.walk(path):
        for fn in fns:
            try:
                total += (Path(dp) / fn).lstat().st_size
            except OSError:
                pass
    return total


def _bundle_info(app: Path) -> tuple[str, str]:
    """(bundle id, version) from the app's Info.plist — ('','') if unreadable."""
    try:
        with open(app / "Contents" / "Info.plist", "rb") as fh:
            d = plistlib.load(fh)
        return (str(d.get("CFBundleIdentifier", "") or ""),
                str(d.get("CFBundleShortVersionString",
                          d.get("CFBundleVersion", "")) or ""))
    except Exception:
        return "", ""


def _date(ts: float) -> str:
    try:
        return time.strftime("%b %-d, %Y", time.localtime(ts))
    except Exception:
        return ""


def _leftovers(bundle_id: str, name: str) -> list[dict]:
    """Files an app left around ~/Library, matched by bundle id or app name.

    Matching is deliberately conservative — an exact bundle-id prefix
    (com.foo.Bar / com.foo.Bar.plist) or an exact app-name match — so we don't
    sweep in unrelated files that merely share a word.
    """
    home = Path.home()
    nlow = name.lower()
    bid = bundle_id.lower()
    out: list[dict] = []
    for sub, label in _LIBRARY.items():
        base = home / "Library" / sub
        if not base.is_dir():
            continue
        try:
            entries = list(base.iterdir())
        except OSError:
            continue
        for e in entries:
            enl = e.name.lower()
            stem = enl[:-6] if enl.endswith(".plist") else enl
            hit = (
                (bid and (stem == bid or enl.startswith(bid + ".") or
                          stem.startswith(bid + "."))) or
                (enl == nlow or stem == nlow)
            )
            if not hit:
                continue
            sz = _du(e)
            out.append({"path": str(e), "name": e.name, "size": sz,
                        "human": _human(sz), "note": label,
                        "risk": "", "important": "", "accessed": ""})
    out.sort(key=lambda i: -i["size"])
    return out[:_CAP]


def list_apps(progress=lambda s: None) -> dict:
    """Installed apps/programs with what they leave behind, by platform.

    macOS returns .app bundles + their ~/Library leftovers (uninstall = move
    everything to the reversible vault). Windows returns registered programs +
    their own uninstaller (uninstall = run that uninstaller) plus any leftover
    AppData folders we can match and tidy afterwards.
    """
    if sys.platform == "darwin":
        return _mac_apps(progress)
    if sys.platform.startswith("win"):
        return _windows_programs(progress)
    return {"apps": [], "platform": sys.platform,
            "note": "Application cleanup is supported on macOS and Windows."}


def _mac_apps(progress) -> dict:
    seen: set[Path] = set()
    apps: list[dict] = []
    for d in _APP_DIRS:
        base = Path(d)
        if not base.is_dir():
            continue
        try:
            entries = sorted(base.glob("*.app"))
        except OSError:
            continue
        for app in entries:
            if app in seen:
                continue
            seen.add(app)
            name = app.stem
            progress(f"Inspecting {name}…")
            bid, ver = _bundle_info(app)
            bundle_sz = _du(app)
            try:
                used = app.stat().st_atime
            except OSError:
                used = 0
            leftovers = _leftovers(bid, name)
            extra = sum(i["size"] for i in leftovers)
            apps.append({
                "name": name, "path": str(app), "bundleId": bid, "version": ver,
                "bundleBytes": bundle_sz, "bundleHuman": _human(bundle_sz),
                "bytes": bundle_sz + extra, "human": _human(bundle_sz + extra),
                "leftoverCount": len(leftovers), "leftoverBytes": extra,
                "leftoverHuman": _human(extra),
                "used": _date(used) if used else "", "atime": used,
                "leftovers": leftovers,
            })
    apps.sort(key=lambda a: -a["bytes"])
    return {"apps": apps, "platform": sys.platform}


# --- Windows ----------------------------------------------------------------
# Programs register themselves under these "Uninstall" keys. We read the display
# name, size and the command Windows itself uses to uninstall them, then offer
# to run that uninstaller (the correct, registry-aware way to remove a program).
_WIN_UNINSTALL = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
]


def _win_leftovers(name: str, publisher: str) -> list[dict]:
    """Leftover folders a program keeps in AppData / ProgramData, by exact name."""
    bases = [os.environ.get("LOCALAPPDATA"), os.environ.get("APPDATA"),
             os.environ.get("PROGRAMDATA")]
    nlow = name.lower()
    out: list[dict] = []
    for b in bases:
        if not b:
            continue
        base = Path(b)
        if not base.is_dir():
            continue
        # <base>\<Name> and <base>\<Publisher>\<Name>
        cands = [base / name]
        if publisher:
            cands.append(base / publisher / name)
        for c in cands:
            try:
                if c.is_dir() and c.name.lower() == nlow:
                    sz = _du(c)
                    out.append({"path": str(c), "name": str(c), "size": sz,
                                "human": _human(sz), "note": "app data",
                                "risk": "", "important": "", "accessed": ""})
            except OSError:
                pass
    return out


def _windows_programs(progress) -> dict:
    import winreg  # Windows-only stdlib

    hives = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
    seen: set[str] = set()
    apps: list[dict] = []
    for hive_name, path in _WIN_UNINSTALL:
        try:
            root = winreg.OpenKey(hives[hive_name], path)
        except OSError:
            continue
        for i in range(winreg.QueryInfoKey(root)[0]):
            try:
                sub = winreg.EnumKey(root, i)
                k = winreg.OpenKey(root, sub)
            except OSError:
                continue

            def val(n, default=""):
                try:
                    return winreg.QueryValueEx(k, n)[0]
                except OSError:
                    return default

            name = str(val("DisplayName")).strip()
            uninstall = str(val("UninstallString") or val("QuietUninstallString"))
            # skip updates / system components / entries with no real uninstaller
            if (not name or not uninstall or val("SystemComponent") == 1 or
                    name.lower() in seen):
                continue
            seen.add(name.lower())
            publisher = str(val("Publisher")).strip()
            kb = val("EstimatedSize", 0)
            sz = int(kb) * 1024 if isinstance(kb, int) else 0
            progress(f"Inspecting {name}…")
            leftovers = _win_leftovers(name, publisher)
            extra = sum(it["size"] for it in leftovers)
            apps.append({
                "name": name, "path": str(val("InstallLocation")),
                "bundleId": publisher, "version": str(val("DisplayVersion")),
                "bundleBytes": sz, "bundleHuman": _human(sz) if sz else "",
                "bytes": sz + extra, "human": _human(sz + extra) if sz + extra else "",
                "leftoverCount": len(leftovers), "leftoverBytes": extra,
                "leftoverHuman": _human(extra),
                "used": "", "atime": 0, "leftovers": leftovers,
                "win": True, "uninstall": uninstall,
            })
    apps.sort(key=lambda a: -a["bytes"])
    return {"apps": apps, "platform": sys.platform}
