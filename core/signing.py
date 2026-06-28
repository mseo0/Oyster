"""Local code-signature verification (no network).

macOS: `codesign` + `spctl` (Gatekeeper assessment).
Windows: PowerShell `Get-AuthenticodeSignature`.
Used as a strong heuristic: an unsigned binary running from a writable dir is a
classic "potential hacker" signal.
"""
from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SignInfo:
    checked: bool
    signed: bool
    valid: bool
    authority: str = ""
    detail: str = ""


def verify_safe(path: str | Path) -> SignInfo:
    """`verify` for a string path that never raises and never blocks forever —
    returns a 'not checked' result on any error so a risk assessment can fall
    back gracefully."""
    try:
        return verify(Path(path))
    except Exception as e:
        return SignInfo(checked=False, signed=False, valid=False, detail=str(e))


def verify(path: Path) -> SignInfo:
    try:
        if sys.platform == "darwin":
            return _verify_macos(path)
        if sys.platform.startswith("win"):
            return _verify_windows(path)
    except Exception as e:  # never let a signing check crash a scan
        return SignInfo(checked=True, signed=False, valid=False, detail=str(e))
    return SignInfo(checked=False, signed=False, valid=False,
                    detail="unsupported platform")


def _verify_macos(path: Path) -> SignInfo:
    proc = subprocess.run(
        ["codesign", "--verify", "--deep", "--strict", str(path)],
        capture_output=True, text=True, timeout=30,
    )
    valid = proc.returncode == 0
    authority = ""
    info = subprocess.run(
        ["codesign", "-dv", "--verbose=2", str(path)],
        capture_output=True, text=True, timeout=30,
    )
    for line in info.stderr.splitlines():
        if line.startswith("Authority="):
            authority = line.split("=", 1)[1]
            break
    signed = "code object is not signed" not in info.stderr.lower()
    return SignInfo(True, signed, valid, authority, proc.stderr.strip())


def _verify_windows(path: Path) -> SignInfo:
    ps = (
        f"$s = Get-AuthenticodeSignature -LiteralPath '{path}'; "
        "Write-Output $s.Status; "
        "Write-Output $s.SignerCertificate.Subject"
    )
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps],
        capture_output=True, text=True, timeout=30,
    )
    lines = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
    status = lines[0] if lines else "Unknown"
    authority = lines[1] if len(lines) > 1 else ""
    signed = status != "NotSigned"
    valid = status == "Valid"
    return SignInfo(True, signed, valid, authority, status)
