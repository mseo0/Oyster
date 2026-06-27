"""File provenance — did a file come from a download, or was it user-created?

macOS tags anything from a browser / download / AirDrop with the
`com.apple.quarantine` extended attribute. We use that to distinguish files the
user *received* (worth flagging) from files they *made* themselves (almost never
malware, and noisy to flag). Checked only on the handful of findings, never on
every walked file, so the cost is trivial.
"""
from __future__ import annotations

import os
import subprocess
import sys

_QUARANTINE = "com.apple.quarantine"
_DOWNLOAD_DIRS = ("/Downloads/", "/Desktop/")


def is_downloaded(path: str) -> bool:
    """True if the file carries download provenance (or, off macOS, unknown ->
    treat as downloaded so we never silently hide a real detection)."""
    if sys.platform != "darwin":
        return True
    getx = getattr(os, "getxattr", None)
    if getx is not None:
        try:
            getx(path, _QUARANTINE)
            return True
        except OSError:
            return False
        except Exception:
            pass
    try:
        return subprocess.run(
            ["xattr", "-p", _QUARANTINE, path],
            capture_output=True, timeout=2).returncode == 0
    except Exception:
        return True


def source_label(path: str) -> str:
    """'downloaded' if it has download provenance or lives in Downloads/Desktop,
    else 'user-created'."""
    if is_downloaded(path) or any(d in path for d in _DOWNLOAD_DIRS):
        return "downloaded"
    return "user-created"
