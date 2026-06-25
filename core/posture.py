"""OS security-posture checks — local config auditing (no network).

Looks at firewall, system integrity protections, and disk encryption: the cheap,
high-value "are the basics on?" checks. Each returns a PostureCheck so the vuln
auditor can surface misconfigurations alongside CVEs.
"""
from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass


@dataclass
class PostureCheck:
    name: str
    ok: bool
    detail: str


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=15).stdout.strip()
    except Exception as e:
        return f"__error__:{e}"


def audit() -> list[PostureCheck]:
    if sys.platform == "darwin":
        return _macos()
    if sys.platform.startswith("win"):
        return _windows()
    return _linux()


def _macos() -> list[PostureCheck]:
    checks: list[PostureCheck] = []

    fw = _run(["/usr/libexec/ApplicationFirewall/socketfilterfw",
               "--getglobalstate"])
    checks.append(PostureCheck("Application Firewall",
                               "enabled" in fw.lower(), fw or "unknown"))

    sip = _run(["csrutil", "status"])
    checks.append(PostureCheck("System Integrity Protection",
                               "enabled" in sip.lower(), sip or "unknown"))

    fv = _run(["fdesetup", "status"])
    checks.append(PostureCheck("FileVault disk encryption",
                               "on" in fv.lower(), fv or "unknown"))

    gk = _run(["spctl", "--status"])
    checks.append(PostureCheck("Gatekeeper",
                               "enabled" in gk.lower(), gk or "unknown"))
    return checks


def _windows() -> list[PostureCheck]:
    checks: list[PostureCheck] = []

    fw = _run(["powershell", "-NoProfile", "-Command",
               "(Get-NetFirewallProfile | Where-Object Enabled -eq 'True')"
               ".Count"])
    checks.append(PostureCheck("Windows Firewall profiles enabled",
                               fw.strip() not in ("", "0", "__error__"),
                               f"{fw} profile(s) on"))

    av = _run(["powershell", "-NoProfile", "-Command",
               "(Get-MpComputerStatus).RealTimeProtectionEnabled"])
    checks.append(PostureCheck("Defender real-time protection",
                               av.strip().lower() == "true", av))

    bl = _run(["powershell", "-NoProfile", "-Command",
               "(Get-BitLockerVolume -MountPoint C:).ProtectionStatus"])
    checks.append(PostureCheck("BitLocker (C:)",
                               "on" in bl.lower() or bl.strip() == "1", bl))
    return checks


def _linux() -> list[PostureCheck]:
    ufw = _run(["ufw", "status"])
    return [PostureCheck("ufw firewall", "active" in ufw.lower(),
                         ufw or "unknown")]
