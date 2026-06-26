"""Oyster engine sidecar — line-delimited JSON-RPC over stdio.

The Electron app spawns this process and talks to it over stdin/stdout only —
no sockets are opened, so the no-egress guarantee is preserved. Each line in is
a request {"id", "method", "params"}; each line out is either a response
{"id","ok","result"|"error"} or an unsolicited event {"event","data"} used to
stream scan progress.
"""
from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

# repo root on path (works frozen via PyInstaller pathex, and from source)
if not getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import config, preflight, processes, toolpaths, vulnaudit  # noqa: E402
from core.findings import FindingKind, Store  # noqa: E402
from core.quarantine import Quarantine  # noqa: E402
from core.scanner import Scanner  # noqa: E402
from agent import triage  # noqa: E402

FILE_KINDS = (FindingKind.FILE_MALWARE, FindingKind.FILE_SUSPICIOUS)

_OUT_LOCK = threading.Lock()


def _rules_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "rules"
    return Path(__file__).resolve().parent.parent / "rules"


def _write(obj: dict) -> None:
    with _OUT_LOCK:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()


def _finding_dict(f) -> dict:
    p = Path(f.target)
    return {
        "severity": f.severity.value,
        "kind": f.kind.value,
        "target": f.target,
        "name": p.name or f.target,
        "dir": str(p.parent),
        "rule": f.rule,
        "detail": f.detail,
        "evidence": {str(k): str(v) for k, v in (f.evidence or {}).items()},
    }


def _proc_dict(t) -> dict:
    return {
        "pid": t.pid, "name": t.name, "exe": t.exe or "",
        "score": t.score, "protected": bool(t.protected),
        "reasons": list(t.reasons or []),
        "connections": getattr(t, "connections", None),
    }


class Engine:
    def __init__(self):
        toolpaths.ensure_path()
        self.cfg = config.ScanConfig()
        self.model = config.recommended_model()
        self.store = Store(self.cfg.db_path)
        self.quar = Quarantine(self.cfg.quarantine_dir)

    # --- meta ---------------------------------------------------------
    def hello(self, _):
        return {
            "model": self.model,
            "defaultTarget": str(Path.home() / "Downloads"),
            "platform": sys.platform,
        }

    def preflight(self, _):
        checks = preflight.run_all(self.cfg.db_path.parent, self.model)
        return [{"key": c.key, "name": c.name, "ok": c.ok,
                 "required": c.required, "detail": c.detail, "fix": c.fix}
                for c in checks]

    def open_settings(self, params):
        import subprocess
        if params.get("key") == "fda" and sys.platform == "darwin":
            subprocess.run(["open", "x-apple.systempreferences:com.apple."
                            "preference.security?Privacy_AllFiles"], check=False)
        return {"ok": True}

    # --- scans --------------------------------------------------------
    def scan(self, params):
        path = params.get("path") or str(Path.home() / "Downloads")
        return self._scan(config.ScanConfig(roots=[Path(path)]))

    def deep_scan(self, _):
        return self._scan(config.ScanConfig(
            roots=config.full_system_roots(), deep=True, include_noise=True))

    def _scan(self, cfg):
        scanner = Scanner(cfg, rules_dir=_rules_dir())
        t0 = time.time()
        report = scanner.scan(
            progress=lambda s: _write({"event": "progress", "data": s}))
        findings = [_finding_dict(f) for f in report.findings
                    if f.kind in FILE_KINDS]
        findings.sort(key=lambda d: _sev_rank(d["severity"]))
        return {
            "findings": findings,
            "filesSeen": report.files_seen,
            "filesUnreadable": report.files_unreadable,
            "secs": round(time.time() - t0, 1),
        }

    def sweep_processes(self, _):
        threats = processes.inspect()
        out = [_proc_dict(t) for t in threats]
        out.sort(key=lambda d: -d["score"])
        return {"processes": out}

    def audit_vulns(self, _):
        findings = vulnaudit.audit(self.cfg.osv_db_path)
        for f in findings:
            self.store.add_finding(f)
        out = [_finding_dict(f) for f in findings]
        out.sort(key=lambda d: _sev_rank(d["severity"]))
        return {"vulns": out}

    # --- actions ------------------------------------------------------
    def quarantine(self, params):
        path = Path(params["target"])
        qid = self.quar.quarantine(path, reason=params.get("rule", ""))
        self.store.log_action("quarantine", str(path), True,
                              detail=f"qid={qid}", reversible=True)
        return {"qid": qid}

    def mark_safe(self, params):
        self.store.log_action("mark_safe", params["target"], True,
                              reversible=False)
        return {"ok": True}

    def suspend(self, params):
        processes.suspend(int(params["pid"]))
        self.store.log_action("suspend", f"pid:{params['pid']}", True,
                              reversible=True)
        return {"ok": True}

    def kill(self, params):
        processes.terminate(int(params["pid"]), params.get("name", ""))
        self.store.log_action("kill", f"pid:{params['pid']}", True,
                              reversible=False)
        return {"ok": True}

    def summary(self, _):
        return {"text": triage.summarize_session(
            self.store.session_summary_data(), self.model)}


def _sev_rank(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3,
            "info": 4}.get(sev, 5)


def main():
    engine = Engine()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        rid, method = req.get("id"), req.get("method")
        fn = getattr(engine, method, None)
        if fn is None:
            _write({"id": rid, "ok": False, "error": f"unknown method {method}"})
            continue
        try:
            result = fn(req.get("params") or {})
            _write({"id": rid, "ok": True, "result": result})
        except Exception as e:  # surface, never crash the sidecar
            _write({"id": rid, "ok": False,
                    "error": f"{type(e).__name__}: {e}"})


if __name__ == "__main__":
    main()
