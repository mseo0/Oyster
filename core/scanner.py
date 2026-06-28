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

from . import config, processes, risk, vulnaudit
from .engine import ClamEngine
from .findings import Finding, FindingKind, Severity, Store
from .hashcache import HashCache
from .walker import walk

ProgressFn = Callable[[str], None]

# How many files to hand ClamAV per invocation. ClamAV reloads its whole
# signature DB on every launch, so we batch: one DB load covers a few hundred
# files instead of one DB load per file (which made full scans appear to hang).
CLAM_BATCH = 150


def _short(p: Path, maxlen: int = 70) -> str:
    """Path trimmed from the left so the live status line never overflows."""
    s = str(p)
    return s if len(s) <= maxlen else "…" + s[-(maxlen - 1):]


def count_candidates(cfg: config.ScanConfig, cap: int = 400_000) -> int:
    """Fast pre-count of files to be scanned (walk only, no hashing) so the UI
    can estimate time remaining. Capped so a whole-disk count can't run away."""
    n = 0
    for _ in walk(cfg):
        n += 1
        if n >= cap:
            break
    return n


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
    risks_suppressed: int = 0   # heuristic hits on trusted-signed files (likely FPs)
    canceled: bool = False


class Scanner:
    def __init__(self, cfg: config.ScanConfig, rules_dir: Path | None = None):
        self.cfg = cfg
        self.cache = HashCache(cfg.db_path)
        self.store = Store(cfg.db_path)
        self.engine = ClamEngine(extra_yara_dir=rules_dir)

    def scan(self, progress: ProgressFn = lambda s: None,
             vuln: bool = True, cancel=lambda: False) -> ScanReport:
        report = ScanReport(engine_available=self.engine.available)
        progress(self.engine.status())
        roots = ", ".join(str(r) for r in self.cfg.roots)
        progress(f"Walking {roots} …")

        last = 0.0
        # interesting files are buffered and inspected by ClamAV in batches
        # (one DB load per batch) instead of one slow process per file.
        pending: list[tuple[Path, str]] = []
        for cand in walk(self.cfg):
            if cancel():
                self._flush_batch(report, pending, progress)
                self.cache.flush()
                report.canceled = True
                progress(f"Canceled · {report.files_seen:,} files scanned.")
                return report
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

            # 2) heavier engine pass, only for interesting + sane-sized files.
            #    Buffer it; ClamAV runs on the whole batch at once below.
            if (cand.interesting and self.engine.available
                    and cand.size <= config.MAX_CONTENT_SCAN_BYTES):
                pending.append((cand.path, digest))
                if len(pending) >= CLAM_BATCH:
                    progress(f"Inspecting {len(pending)} files with ClamAV…")
                    self._flush_batch(report, pending, progress)
                    last = time.monotonic()

        self._flush_batch(report, pending, progress)  # inspect the final partial batch
        self.cache.flush()  # persist the batched hash writes

        progress(f"Walked {report.files_seen:,} files · inspecting running "
                 "processes…")
        self._scan_processes(report)

        if vuln:
            progress("Auditing installed software + OS posture…")
            self._scan_vulnerabilities(report)

        tail = (f" · {report.files_unreadable:,} unreadable (grant Full Disk "
                "Access to cover them)") if report.files_unreadable else ""
        if report.risks_suppressed:
            tail += (f" · {report.risks_suppressed:,} low-confidence heuristic "
                     "hit(s) on signed files filtered out")
        progress(f"Done · {len(report.findings)} finding(s){tail}.")
        return report

    def _flush_batch(self, report: ScanReport,
                     pending: list[tuple[Path, str]],
                     progress: ProgressFn) -> None:
        """Inspect one buffered batch of files with a single ClamAV run, then
        score each hit into a reliably-ranked risk (named family vs. heuristic,
        cross-checked against code-signing) so legitimate signed program files
        aren't reported as malware."""
        if not pending:
            return
        report.files_scanned += len(pending)
        paths = [p for p, _ in pending]
        digests = {str(p): d for p, d in pending}
        hits = self.engine.scan_files(paths)
        pending.clear()
        for path, signature in hits.items():
            a = risk.assess(path, signature)
            if a.suppress:
                # almost certainly a false positive on a file a program needs —
                # count it for transparency, but don't alarm the user with it.
                report.risks_suppressed += 1
                continue
            self._record(report, Finding(
                a.kind, a.severity, path, signature or "clamav",
                f"ClamAV/YARA match — {a.reason}",
                {"sha256": digests.get(path, ""), "signature": signature,
                 "confidence": a.confidence},
            ))

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
