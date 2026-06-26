"""Scan orchestration — wires the funnel together.

walk -> skip filter -> hash + known-bad lookup -> ClamAV (interesting/unknown
only) -> Findings. Plus a process sweep. Emits progress via a callback so the
CLI and UI can both render it. Only findings (tens) ever reach the AI layer.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import config, processes, vulnaudit
from .engine import ClamEngine
from .findings import Finding, FindingKind, Severity, Store
from .hashcache import HashCache
from .walker import walk

ProgressFn = Callable[[str], None]


def _short(p: Path, maxlen: int = 70) -> str:
    """Path trimmed from the left so the live status line never overflows."""
    s = str(p)
    return s if len(s) <= maxlen else "…" + s[-(maxlen - 1):]


@dataclass
class ScanReport:
    files_seen: int = 0
    files_hashed: int = 0
    files_scanned: int = 0
    files_unreadable: int = 0   # couldn't be read (perms) -> coverage gap
    findings: list[Finding] = field(default_factory=list)
    engine_available: bool = False
    process_threats: int = 0
    vulnerabilities: int = 0


class Scanner:
    def __init__(self, cfg: config.ScanConfig, rules_dir: Path | None = None):
        self.cfg = cfg
        self.cache = HashCache(cfg.db_path)
        self.store = Store(cfg.db_path)
        self.engine = ClamEngine(extra_yara_dir=rules_dir)

    def scan(self, progress: ProgressFn = lambda s: None,
             vuln: bool = True) -> ScanReport:
        report = ScanReport(engine_available=self.engine.available)
        progress(self.engine.status())
        roots = ", ".join(str(r) for r in self.cfg.roots)
        progress(f"Walking {roots} …")

        last = 0.0
        for cand in walk(self.cfg):
            report.files_seen += 1
            # throttle the live "current file" line to ~10/sec so it stays
            # readable and never floods the UI event loop.
            now = time.monotonic()
            if now - last >= 0.1:
                last = now
                progress(
                    f"Scanning · {report.files_seen:,} seen · "
                    f"{report.files_hashed:,} hashed · "
                    f"{report.files_scanned:,} deep · {_short(cand.path)}")

            digest, _changed = self.cache.hash_for(
                cand.path, cand.size, cand.mtime)
            if not digest:
                # regular file we couldn't read — a real coverage gap, surfaced
                # below so the user can grant Full Disk Access / run with sudo.
                report.files_unreadable += 1
                continue
            report.files_hashed += 1

            # 1) cheapest, strongest signal: local known-bad hash
            label = self.cache.known_bad_label(digest)
            if label:
                self._record(report, Finding(
                    FindingKind.FILE_MALWARE, Severity.CRITICAL,
                    str(cand.path), f"known-bad-hash:{label}",
                    "matched local known-bad hash set",
                    {"sha256": digest},
                ))
                continue

            # 2) heavier engine pass, only for interesting + sane-sized files
            if (cand.interesting and self.engine.available
                    and cand.size <= config.MAX_CONTENT_SCAN_BYTES):
                report.files_scanned += 1
                # this call blocks (clamscan), so name the file we're on
                progress(f"Inspecting with ClamAV · {_short(cand.path)}")
                last = time.monotonic()
                res = self.engine.scan_file(cand.path)
                if res.infected:
                    self._record(report, Finding(
                        FindingKind.FILE_MALWARE, Severity.HIGH,
                        str(cand.path), res.signature or "clamav",
                        "ClamAV signature/YARA match",
                        {"sha256": digest, "signature": res.signature},
                    ))

        self.cache.flush()  # persist the batched hash writes

        progress(f"Walked {report.files_seen:,} files · inspecting running "
                 "processes…")
        self._scan_processes(report)

        if vuln:
            progress("Auditing installed software + OS posture…")
            self._scan_vulnerabilities(report)

        tail = (f" · {report.files_unreadable:,} unreadable (grant Full Disk "
                "Access to cover them)") if report.files_unreadable else ""
        progress(f"Done · {len(report.findings)} finding(s){tail}.")
        return report

    def _scan_vulnerabilities(self, report: ScanReport) -> None:
        for f in vulnaudit.audit(self.cfg.osv_db_path):
            if f.severity.value != "info":
                report.vulnerabilities += 1
            self._record(report, f)

    def _scan_processes(self, report: ScanReport) -> None:
        for t in processes.inspect():
            report.process_threats += 1
            sev = (Severity.HIGH if t.score >= 60 else
                   Severity.MEDIUM if t.score >= 35 else Severity.LOW)
            self._record(report, Finding(
                FindingKind.PROCESS_SUSPICIOUS, sev,
                f"pid:{t.pid}:{t.name}", "process-heuristics",
                "; ".join(t.reasons),
                {"pid": t.pid, "exe": t.exe, "score": t.score,
                 "protected": t.protected, "connections": t.connections},
            ))

    def _record(self, report: ScanReport, f: Finding) -> None:
        report.findings.append(f)
        self.store.add_finding(f)
