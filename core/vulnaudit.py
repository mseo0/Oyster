"""Vulnerability auditor — Phase 5.

Combines the installed-software inventory with the local OSV snapshot and OS
posture checks, emitting VULNERABILITY findings. Fully offline: if no OSV
snapshot has been downloaded yet, it still runs posture checks and tells you to
update definitions.
"""
from __future__ import annotations

from pathlib import Path

from . import inventory, portscan, posture
from .findings import Finding, FindingKind, Severity
from .osvdb import OsvDB


def _sev_from_osv(score: str) -> Severity:
    s = (score or "").upper()
    if "CRITICAL" in s or s.startswith("CVSS:3") and "/9" in s:
        return Severity.CRITICAL
    if "HIGH" in s:
        return Severity.HIGH
    if "MEDIUM" in s or "MODERATE" in s:
        return Severity.MEDIUM
    return Severity.LOW


def audit(osv_db_path: Path) -> list[Finding]:
    findings: list[Finding] = []

    # --- 1) known-CVE matching against the local OSV snapshot -------------
    db = OsvDB(osv_db_path)
    if db.count == 0:
        findings.append(Finding(
            FindingKind.VULNERABILITY, Severity.INFO,
            "osv-database", "no-snapshot",
            "No local OSV snapshot yet — run the updater "
            "(python -m updater.update --osv) to enable CVE matching.",
        ))
    else:
        for pkg in inventory.collect():
            if pkg.ecosystem not in ("PyPI", "npm"):
                continue  # only ecosystems OSV indexes by name+version
            for adv in db.query(pkg.ecosystem, pkg.name, pkg.version):
                findings.append(Finding(
                    FindingKind.VULNERABILITY,
                    _sev_from_osv(adv.severity),
                    f"{pkg.ecosystem}:{pkg.name}@{pkg.version}",
                    adv.osv_id,
                    adv.summary or "known vulnerability",
                    {"fixed_in": adv.fixed or "unknown",
                     "ecosystem": pkg.ecosystem, "package": pkg.name,
                     "installed": pkg.version},
                ))

    # --- 2) network exposure: listening / open ports ---------------------
    findings.extend(portscan.audit())

    # --- 3) OS security posture ------------------------------------------
    for chk in posture.audit():
        if not chk.ok:
            findings.append(Finding(
                FindingKind.VULNERABILITY, Severity.MEDIUM,
                f"posture:{chk.name}", "misconfiguration",
                f"{chk.name} is not enabled/secure: {chk.detail}",
                {"check": chk.name},
            ))

    return findings


def inventory_summary() -> dict[str, int]:
    counts: dict[str, int] = {}
    for p in inventory.collect():
        counts[p.ecosystem] = counts.get(p.ecosystem, 0) + 1
    return counts
