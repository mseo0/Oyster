"""Command-line entry point.

    python -m cli.scan ~/Downloads            # scan a path
    python -m cli.scan --processes-only       # just the process sweep
    python -m cli.scan --apply ~/Downloads    # interactively act on findings

Approval is interactive: nothing destructive happens without a y/N prompt, and
protected paths/processes are never offered for automatic action.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agent import triage
from core import config, processes
from core.findings import FindingKind, Store
from core.quarantine import Quarantine
from core.scanner import Scanner


def _confirm(prompt: str) -> bool:
    try:
        return input(f"{prompt} [y/N] ").strip().lower() == "y"
    except (EOFError, KeyboardInterrupt):
        return False


def main(argv: list[str] | None = None) -> int:
    from core import toolpaths
    toolpaths.ensure_path()  # locate Homebrew/ClamAV tools under a minimal PATH
    ap = argparse.ArgumentParser(description="Oyster — local agentic antivirus")
    ap.add_argument("paths", nargs="*", default=[], help="paths to scan")
    ap.add_argument("--deep", action="store_true",
                    help="descend into system trees too (slow)")
    ap.add_argument("--everything", action="store_true",
                    help="deep-scan the ENTIRE computer: all volumes, system "
                         "trees, hidden + cache/build dirs. Very slow; needs "
                         "Full Disk Access (macOS) or admin to read it all.")
    ap.add_argument("--processes-only", action="store_true")
    ap.add_argument("--vuln-only", action="store_true",
                    help="only audit installed software + OS posture")
    ap.add_argument("--no-vuln", action="store_true",
                    help="skip the vulnerability audit during a file scan")
    ap.add_argument("--apply", action="store_true",
                    help="interactively act on findings (approval-gated)")
    ap.add_argument("--model", default=config.recommended_model())
    args = ap.parse_args(argv)

    if args.everything:
        cfg = config.ScanConfig(
            roots=config.full_system_roots(), deep=True, include_noise=True)
        from core import preflight
        fda = preflight.full_disk_access()
        if not fda.ok:
            print(f"  !! {fda.name}: {fda.detail}")
            print(f"     fix: {fda.fix}")
    else:
        cfg = config.ScanConfig(
            roots=[Path(p) for p in args.paths] or [Path.home()],
            deep=args.deep,
        )
    rules_dir = Path(__file__).resolve().parent.parent / "rules"
    scanner = Scanner(cfg, rules_dir=rules_dir)
    store = Store(cfg.db_path)
    quar = Quarantine(cfg.quarantine_dir)

    print(f"== Oyster ==  local agentic antivirus  ·  model tier: {args.model}")

    if args.vuln_only:
        from core import vulnaudit
        print("Software inventory:", vulnaudit.inventory_summary())
        findings = vulnaudit.audit(cfg.osv_db_path)
        for f in findings:
            store.add_finding(f)
            print(f"[{f.severity.value:8s}] {f.target}  —  {f.rule}: {f.detail}")
        print("\n-- scan report --")
        print(triage.summarize_session(store.session_summary_data(), args.model))
        return 0

    if args.processes_only:
        threats = processes.inspect()
        for t in threats:
            flag = " [PROTECTED]" if t.protected else ""
            print(f"[{t.score:3d}] pid {t.pid} {t.name}{flag}: "
                  f"{'; '.join(t.reasons)}")
        if args.apply:
            _apply_processes(threats, store)
        return 0

    report = scanner.scan(progress=lambda s: print("  ..", s),
                          vuln=not args.no_vuln)
    print(f"\nSeen {report.files_seen}, hashed {report.files_hashed}, "
          f"engine-scanned {report.files_scanned}, "
          f"processes-flagged {report.process_threats}, "
          f"vulns {report.vulnerabilities}, "
          f"findings {len(report.findings)}")

    if report.findings:
        print("\n-- AI triage --")
        print(triage.triage_findings(report.findings, args.model))

    if args.apply and report.findings:
        _apply_findings(report.findings, store, quar)

    print("\n-- scan report --")
    print(triage.summarize_session(store.session_summary_data(), args.model))
    return 0


def _apply_findings(findings, store, quar) -> None:
    protected_roots = config.protected_path_roots()
    for f in findings:
        if f.kind == FindingKind.PROCESS_SUSPICIOUS:
            continue
        path = Path(f.target)
        is_protected = any(str(path).startswith(str(r)) for r in protected_roots)
        tag = " [PROTECTED — confirm carefully]" if is_protected else ""
        if _confirm(f"Quarantine {path}? ({f.rule}){tag}"):
            try:
                qid = quar.quarantine(path, reason=f.rule)
                store.log_action("quarantine", str(path), True,
                                 detail=f"qid={qid}", reversible=True)
                print(f"   quarantined -> {qid} (restore with the UI/CLI)")
            except OSError as e:
                print(f"   failed: {e}")
        else:
            store.log_action("quarantine", str(path), False, reversible=True)


def _apply_processes(threats, store) -> None:
    for t in threats:
        if t.protected:
            print(f"   refusing to offer kill for protected {t.name}")
            continue
        if _confirm(f"Suspend pid {t.pid} {t.name}? ({'; '.join(t.reasons)})"):
            try:
                processes.suspend(t.pid)
                store.log_action("suspend", f"pid:{t.pid}:{t.name}", True,
                                 reversible=True)
                print("   suspended (reversible).")
            except Exception as e:
                print(f"   failed: {e}")


if __name__ == "__main__":
    sys.exit(main())
