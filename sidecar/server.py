"""Oyster engine sidecar — line-delimited JSON-RPC over stdio.

The Electron app spawns this process and talks to it over stdin/stdout only —
no sockets are opened, so the no-egress guarantee is preserved. Each line in is
a request {"id","method","params"}; each line out is a response
{"id","ok","result"|"error"} or an unsolicited event {"event","data"} (progress,
or a "total" file count for ETA). Requests are handled on worker threads so a
`cancel` can arrive and take effect while a scan is running.
"""
from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

if not getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import (config, organize, posture, preflight, processes,  # noqa: E402
                  provenance, toolpaths, vulnaudit)
from core.findings import FindingKind, Store  # noqa: E402
from core.quarantine import Quarantine  # noqa: E402
from core.scanner import Scanner, count_candidates  # noqa: E402
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


def _emit(event: str, data) -> None:
    _write({"event": event, "data": data})


# --- richer, plain-English descriptions -------------------------------------
_FAMILIES = {
    "emotet": "Emotet, a banking trojan / malware loader",
    "trojan": "a trojan (malware disguised as a legitimate file)",
    "ransom": "ransomware (encrypts your files for ransom)",
    "agent": "a generic malware agent",
    "adware": "adware (unwanted ad-injecting software)",
    "worm": "a worm (self-spreading malware)",
    "miner": "a cryptocurrency miner running without consent",
    "phish": "a phishing payload",
    "macro": "a malicious document macro",
}


def _family(rule: str) -> str:
    rl = rule.lower()
    for key, desc in _FAMILIES.items():
        if key in rl:
            return desc
    return ""


def describe(f, source: str) -> tuple[str, str]:
    """Return (plain-English explanation, recommended action) for a finding."""
    sev = f.severity.value
    rule = f.rule or ""
    rl = rule.lower()
    kind = f.kind.value

    if "eicar" in rl:
        return ("This is the EICAR test file — a harmless 68-byte string the "
                "antivirus industry uses to confirm a scanner is working. It is "
                "NOT real malware and cannot harm your Mac; you can safely ignore "
                "or delete it.", "IGNORE")

    if kind == "vulnerability":
        return (f.detail or "A known weakness in installed software or an OS "
                "setting that an attacker could exploit.", "REVIEW")

    fam = _family(rule)
    if "known-bad-hash" in rl:
        label = rule.split(":")[-1]
        ai = (f"This file's SHA-256 fingerprint is an exact, byte-for-byte match "
              f"for a known-malware entry ({label}). Hash matches are definitive — "
              f"this isn't a guess, it is that malicious file.")
    elif kind.startswith("file"):
        ai = (f"ClamAV's detection engine matched the signature/YARA rule "
              f"“{rule}”"
              + (f", which is associated with {fam}. " if fam else ". ")
              + "The pattern of bytes in this file lines up with known-malicious "
              "code.")
    else:
        ai = f.detail or "Flagged by Oyster's heuristics."

    if source == "user-created":
        ai += (" Heads-up: this file carries no download provenance — it looks "
               "like something created locally on this Mac rather than downloaded, "
               "which makes a false positive more likely. Review it before acting.")
        return ai, "ASK_USER"
    if sev in ("critical", "high"):
        ai += " Recommended: quarantine it (reversible — it moves to a vault, " \
              "it isn't deleted)."
        return ai, "QUARANTINE"
    return ai, "ASK_USER"


def _finding_dict(f) -> dict:
    p = Path(f.target)
    is_file = f.kind in FILE_KINDS
    source = provenance.source_label(f.target) if is_file else "—"
    ai, action = describe(f, source)
    ev = {str(k): str(v) for k, v in (f.evidence or {}).items()}
    if is_file:
        ev["source"] = source
    return {
        "severity": f.severity.value, "kind": f.kind.value, "target": f.target,
        "name": p.name or f.target, "dir": str(p.parent), "rule": f.rule,
        "detail": f.detail, "evidence": ev, "source": source,
        "ai": ai, "action": action,
    }


def _proc_dict(t) -> dict:
    ai, action = (("This process scores high for masquerading / suspicious "
                   "behaviour. Suspending freezes it (reversible) so you can "
                   "investigate without killing it outright.", "SUSPEND")
                  if t.score >= 50 else
                  ("Unusual but low-risk behaviour. Worth a look, but no urgent "
                   "action needed.", "REVIEW"))
    return {"pid": t.pid, "name": t.name, "exe": t.exe or "", "score": t.score,
            "protected": bool(t.protected), "reasons": list(t.reasons or []),
            "connections": getattr(t, "connections", None),
            "ai": ai, "action": action}


def _sev_rank(s: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s, 5)


class Engine:
    def __init__(self):
        toolpaths.ensure_path()
        self.cfg = config.ScanConfig()
        self.model = config.recommended_model()
        self.store = Store(self.cfg.db_path)
        self.quar = Quarantine(self.cfg.quarantine_dir)
        self._cancel = threading.Event()
        self.scanned_once = False

    # --- meta ---------------------------------------------------------
    def hello(self, _):
        return {"model": self.model,
                "defaultTarget": str(Path.home() / "Downloads"),
                "platform": sys.platform}

    def preflight(self, _):
        checks = preflight.run_all(self.cfg.db_path.parent, self.model)
        return [{"key": c.key, "name": c.name, "ok": c.ok,
                 "required": c.required, "detail": c.detail, "fix": c.fix}
                for c in checks]

    def cancel(self, _):
        self._cancel.set()
        return {"ok": True}

    # --- scans --------------------------------------------------------
    def scan(self, params):
        return self._scan(config.ScanConfig(roots=[Path(params.get("path") or
                          str(Path.home() / "Downloads"))]),
                          downloaded_only=bool(params.get("downloadedOnly")),
                          precount=True)

    def deep_scan(self, params):
        return self._scan(config.ScanConfig(
            roots=config.full_system_roots(), deep=True, include_noise=True),
            downloaded_only=bool(params.get("downloadedOnly")), precount=False)

    def _scan(self, cfg, downloaded_only, precount):
        self._cancel.clear()
        if precount:
            _emit("progress", "Counting files…")
            _emit("total", count_candidates(cfg))
        else:
            _emit("total", 0)
        scanner = Scanner(cfg, rules_dir=_rules_dir())
        t0 = time.time()
        report = scanner.scan(
            progress=lambda s: _emit("progress", s),
            cancel=self._cancel.is_set, vuln=False)
        findings = []
        for f in report.findings:
            if f.kind not in FILE_KINDS:
                continue
            d = _finding_dict(f)
            if downloaded_only and d["source"] == "user-created":
                continue
            findings.append(d)
        findings.sort(key=lambda d: _sev_rank(d["severity"]))
        self.scanned_once = True
        return {"findings": findings, "filesSeen": report.files_seen,
                "filesUnreadable": report.files_unreadable,
                "secs": round(time.time() - t0, 1),
                "canceled": report.canceled}

    def sweep_processes(self, _):
        total = processes.total_count()
        out = [_proc_dict(t) for t in processes.inspect()]
        out.sort(key=lambda d: -d["score"])
        self.scanned_once = True
        return {"processes": out, "total": total}

    def audit_vulns(self, _):
        findings = [_finding_dict(f) for f in vulnaudit.audit(self.cfg.osv_db_path)]
        # surface passing OS posture checks too, so the tab is informative
        for chk in posture.audit():
            if chk.ok:
                findings.append({
                    "severity": "info", "kind": "vulnerability",
                    "target": f"posture:{chk.name}", "name": chk.name,
                    "dir": "OS posture", "rule": "ok", "detail": chk.detail,
                    "evidence": {"status": "secure"}, "source": "—",
                    "ai": f"{chk.name} is configured securely: {chk.detail}",
                    "action": "OK"})
        findings.sort(key=lambda d: _sev_rank(d["severity"]))
        self.scanned_once = True
        return {"vulns": findings}

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
        self.store.log_action("suspend", f"pid:{params['pid']}", True, reversible=True)
        return {"ok": True}

    def kill(self, params):
        processes.terminate(int(params["pid"]), params.get("name", ""))
        self.store.log_action("kill", f"pid:{params['pid']}", True, reversible=False)
        return {"ok": True}

    def summary(self, _):
        return {"text": triage.summarize_session(
            self.store.session_summary_data(), self.model),
            "ready": self.scanned_once}

    # --- organize / cleanup ------------------------------------------
    def organize_scan(self, params):
        path = params.get("path") or str(Path.home() / "Downloads")
        return organize.analyze(path, progress=lambda s: _emit("progress", s))

    def organize_apply(self, params):
        return organize.apply(params["action"], params.get("paths") or [],
                              params["folder"], params.get("categories"))


def _handle(engine: Engine, req: dict) -> None:
    rid, method = req.get("id"), req.get("method")
    fn = getattr(engine, method, None)
    if fn is None:
        _write({"id": rid, "ok": False, "error": f"unknown method {method}"})
        return
    try:
        _write({"id": rid, "ok": True, "result": fn(req.get("params") or {})})
    except Exception as e:
        _write({"id": rid, "ok": False, "error": f"{type(e).__name__}: {e}"})


def main():
    engine = Engine()
    threads = []
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        # each request on its own thread so `cancel` can land during a scan
        t = threading.Thread(target=_handle, args=(engine, req), daemon=True)
        t.start()
        threads.append(t)
        threads = [x for x in threads if x.is_alive()]
    for t in threads:   # stdin closed (app quit / piped EOF): finish pending work
        t.join()


if __name__ == "__main__":
    main()
