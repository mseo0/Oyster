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

import contextlib  # noqa: E402
import re  # noqa: E402

from core import (config, organize, posture, preflight, processes,  # noqa: E402
                  provenance, toolpaths, vulnaudit)
from core.findings import FindingKind, Store  # noqa: E402
from core.quarantine import Quarantine  # noqa: E402
from core.scanner import Scanner, count_candidates  # noqa: E402
from agent import triage, websearch  # noqa: E402
from agent.ollama_client import Ollama  # noqa: E402

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
    """Return (plain, friendly explanation, recommended action) for a finding.

    Written for people who aren't computer experts: short sentences, everyday
    words instead of jargon, and a clear "what should I do" at the end.
    """
    sev = f.severity.value
    rule = f.rule or ""
    rl = rule.lower()
    kind = f.kind.value

    if "eicar" in rl:
        return ("This is a harmless test file that antivirus companies use to "
                "check that a scanner is working. It is NOT a real virus and "
                "can't harm your computer. You can safely delete it or ignore it.",
                "IGNORE")

    if kind == "vulnerability":
        return (f.detail or "A program on your computer is out of date and has a "
                "known weak spot that someone could take advantage of. Updating "
                "the program usually fixes this.", "REVIEW")

    fam = _family(rule)
    if "known-bad-hash" in rl:
        ai = ("This exact file is already on a list of known viruses. This isn't "
              "a guess — it's a file that has caused harm on other people's "
              "computers.")
    elif kind.startswith("file"):
        ai = ("This file matches the pattern of known harmful software"
              + (f", specifically {fam}. " if fam else ". ")
              + "In plain terms: parts of this file look the same as software "
              "that's known to cause problems.")
    else:
        ai = f.detail or "Oyster flagged this as worth a closer look."

    if source == "user-created":
        ai += (" One thing to keep in mind: this file doesn't look like it was "
               "downloaded from the internet — it seems to have been made on this "
               "computer, so this might be a false alarm. Take a look before you "
               "remove it.")
        return ai, "ASK_USER"
    if sev in ("critical", "high"):
        ai += (" We'd suggest quarantining it. That just means moving it somewhere "
               "safe where it can't run — it isn't deleted, and you can put it "
               "back later if you need to.")
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
        # how much the risk engine trusts this hit ("high"/"medium"/"low") — the
        # UI offers a local-AI second opinion on the low/medium ones.
        "confidence": str((f.evidence or {}).get("confidence", "")),
        "ai": ai, "action": action,
    }


def _file_facts(f: dict) -> str:
    """The metadata block both the file Q&A and the second-opinion consult feed
    to the local model. Deliberately metadata-only — never the file's bytes — so
    these stay fully offline, no-egress features."""
    ev = f.get("evidence") or {}
    return (
        f"File name: {f.get('name', '?')}\n"
        f"Location: {f.get('dir') or f.get('path') or '?'}\n"
        f"What the scanner matched: {f.get('rule', '?')}\n"
        f"Severity: {f.get('severity', '?')}\n"
        f"Kind of finding: {f.get('kind', '?')}\n"
        f"Where it came from: {f.get('source', '?')}\n"
        f"Extra details: {f.get('detail') or '(none)'}\n"
        + (f"Evidence: {', '.join(f'{k}={v}' for k, v in ev.items())}\n"
           if ev else "")
    )


def _allow_key(d: dict) -> str:
    """A stable identity for a finding so a Mark-safe/Ignore decision can hide it
    on FUTURE scans. Files key on content hash (survives rename/move); open ports
    key on the program + port (a new program on that port still shows); other
    vulns key on their target (CVE id / posture check)."""
    ev = d.get("evidence") or {}
    rule = d.get("rule") or ""
    if d.get("kind") in ("file_malware", "file_suspicious") or _is_file_kind(d):
        sha = ev.get("sha256") or ""
        return f"file:sha256:{sha}" if sha else f"file:path:{d.get('target', '')}"
    if rule.startswith("open-port") or ev.get("port"):
        exe = ev.get("exe") or ev.get("process") or ""
        port = ev.get("port") or ""
        return f"vuln:port:{exe}|{port}" if exe else f"vuln:openport:{port}"
    return f"vuln:target:{d.get('target', '')}"


def _is_file_kind(d: dict) -> bool:
    return str(d.get("kind", "")).startswith("file")


def _allow_label(d: dict) -> str:
    """Short human description shown in the manage-allowlist view."""
    ev = d.get("evidence") or {}
    if _is_file_kind(d):
        return d.get("name") or d.get("target") or "file"
    if (d.get("rule") or "").startswith("open-port") or ev.get("port"):
        who = ev.get("process") or ev.get("exe") or "program"
        return f"Port {ev.get('port', '?')} · {who}"
    return d.get("rule") or d.get("target") or "finding"


def _proc_dict(t) -> dict:
    ai, action = (("This program is behaving like software that tries to hide "
                   "what it really is. You can pause it to stop it safely without "
                   "fully closing it, then decide what to do.", "SUSPEND")
                  if t.score >= 50 else
                  ("This program is doing something a little unusual. It's "
                   "probably fine, but it's worth a quick look.", "REVIEW"))
    return {"pid": t.pid, "name": t.name, "exe": t.exe or "", "score": t.score,
            "protected": bool(t.protected), "reasons": list(t.reasons or []),
            "connections": getattr(t, "connections", None),
            "ai": ai, "action": action}


def _sev_rank(s: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s, 5)


def _fallback_parse(prompt: str) -> dict:
    """Parse a cleanup command without the LLM (keyword heuristics)."""
    low = prompt.lower()
    action = "archive" if ("archive" in low or "move" in low) else "delete"
    contains = re.findall(r'["“”\']([^"“”\']+)["“”\']', prompt)
    contains += [t for t in re.findall(r"\b[A-Z]{2,}[A-Z0-9]*\b", prompt)
                 if t.lower() not in ("pdf", "jpg", "png", "mb", "gb", "os", "ai")]
    contains += [w for w in re.findall(
        r"\b(?:of|with|named|containing|called|about|for)\s+([A-Za-z0-9_\-]{2,})", low)
        if w not in ("class", "files", "file", "all", "the", "this", "that")]
    contains = list(dict.fromkeys(contains))
    ext = ["." + e for e in re.findall(r"\.([a-z0-9]{1,5})\b", low)]
    for word, e in (("pdf", ".pdf"), ("zip", ".zip"), ("screenshot", ".png")):
        if word in low and e not in ext:
            ext.append(e)
    older = None
    m = re.search(r"(?:older than|not opened in|untouched for|over)\s+(\d+)\s*"
                  r"(day|week|month|year)", low)
    if m:
        older = int(m.group(1)) * {"day": 1, "week": 7, "month": 30, "year": 365}[m.group(2)]
    larger = None
    m = re.search(r"(?:larger than|bigger than|over)\s+(\d+)\s*(mb|gb)", low)
    if m:
        larger = int(m.group(1)) * (1024 if m.group(2) == "gb" else 1)
    label = ", ".join(contains) or ", ".join(ext) or prompt
    return {"summary": f"Files matching: {label}", "contains": contains,
            "ext": ext, "olderDays": older, "largerMb": larger, "action": action}


class Engine:
    def __init__(self):
        toolpaths.ensure_path()
        self.cfg = config.ScanConfig()
        self.model = self._pick_model()
        self.store = Store(self.cfg.db_path)
        self.quar = Quarantine(self.cfg.quarantine_dir)
        self._cancel = threading.Event()
        self.scanned_once = False
        self._uninstallers: dict[str, str] = {}   # uid -> Windows uninstall cmd

    def _pick_model(self) -> str:
        """Use an already-installed model if there is one (so we don't ask for a
        model the user hasn't pulled), else the RAM-recommended one."""
        rec = config.recommended_model()
        try:
            installed = Ollama(rec).installed()
        except Exception:
            installed = []
        if rec in installed:
            return rec
        for m in ("llama3.2:3b", "qwen3:1.7b", "qwen3:4b", "qwen3:8b"):
            if m in installed:
                return m
        return installed[0] if installed else rec

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
        allowed = self.store.allowed_keys()
        findings = []
        suppressed = 0
        for f in report.findings:
            if f.kind not in FILE_KINDS:
                continue
            d = _finding_dict(f)
            if downloaded_only and d["source"] == "user-created":
                continue
            if _allow_key(d) in allowed:   # user marked this content safe before
                suppressed += 1
                continue
            findings.append(d)
        findings.sort(key=lambda d: _sev_rank(d["severity"]))
        self.scanned_once = True
        return {"findings": findings, "filesSeen": report.files_seen,
                "filesUnreadable": report.files_unreadable,
                "filesScanned": report.files_scanned,
                "filesCached": report.files_cached,
                "risksSuppressed": report.risks_suppressed,
                "allowlisted": suppressed,
                "secs": round(time.time() - t0, 1),
                "canceled": report.canceled}

    def sweep_processes(self, _):
        total = processes.total_count()
        out = [_proc_dict(t) for t in processes.inspect()]
        out.sort(key=lambda d: -d["score"])
        self.scanned_once = True
        return {"processes": out, "total": total}

    def audit_vulns(self, _):
        allowed = self.store.allowed_keys()
        findings = []
        suppressed = 0
        for f in vulnaudit.audit(self.cfg.osv_db_path):
            d = _finding_dict(f)
            if _allow_key(d) in allowed:   # user ignored this finding before
                suppressed += 1
                continue
            findings.append(d)
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
        return {"vulns": findings, "allowlisted": suppressed}

    # --- actions ------------------------------------------------------
    def quarantine(self, params):
        path = Path(params["target"])
        qid = self.quar.quarantine(path, reason=params.get("rule", ""))
        self.store.log_action("quarantine", str(path), True,
                              detail=f"qid={qid}", reversible=True)
        return {"qid": qid}

    def quarantine_info(self, _):
        """List the reversible vault's contents + its folder path, so the UI can
        show what's held and offer to open the folder or empty it."""
        items = []
        total = 0
        for qid, e in self.quar.list().items():
            sz = int(e.get("size") or 0)
            total += sz
            items.append({"qid": qid, "original": e.get("original", ""),
                          "name": Path(e.get("original", "")).name or qid,
                          "reason": e.get("reason", ""), "ts": e.get("ts", 0),
                          "size": sz})
        items.sort(key=lambda i: i.get("ts", 0), reverse=True)
        return {"dir": str(self.quar.vault), "count": len(items),
                "bytes": total, "items": items}

    def quarantine_empty(self, _):
        """Permanently erase everything in the vault (empties the 'trash')."""
        res = self.quar.empty()
        self.store.log_action(
            "quarantine_empty", str(self.quar.vault), True,
            detail=f"removed {res['removed']} item(s), freed {res['bytes']} bytes",
            reversible=False)
        return res

    def quarantine_restore(self, params):
        """Put one quarantined file back where it came from."""
        original = self.quar.restore(params["qid"])
        self.store.log_action("restore", str(original), True, reversible=False)
        return {"ok": True, "original": str(original)}

    def mark_safe(self, params):
        # Persist the decision so this exact file/finding stays hidden on future
        # scans (keyed on a stable identity, not the row). mode is just a label:
        # "safe" for files, "ignored" for vulnerabilities.
        d = params.get("finding") or params
        mode = params.get("mode") or "safe"
        key = _allow_key(d)
        self.store.allow(key, str(d.get("kind", "")), _allow_label(d), mode)
        self.store.log_action("mark_safe", d.get("target", ""), True,
                              detail=f"key={key}", reversible=True)
        return {"ok": True, "key": key}

    def allowlist_info(self, _):
        return {"items": self.store.list_allowed()}

    def allowlist_remove(self, params):
        """Un-ignore: the finding can surface again on the next scan."""
        self.store.unallow(params["key"])
        return {"ok": True}

    def allowlist_clear(self, _):
        return {"removed": self.store.clear_allowed()}

    def suspend(self, params):
        processes.suspend(int(params["pid"]))
        self.store.log_action("suspend", f"pid:{params['pid']}", True, reversible=True)
        return {"ok": True}

    def kill(self, params):
        processes.terminate(int(params["pid"]), params.get("name", ""))
        self.store.log_action("kill", f"pid:{params['pid']}", True, reversible=False)
        return {"ok": True}

    def close_port(self, params):
        """Close an open/listening port by stopping the process that holds it.
        Reuses the protected-process guard, so core OS services are refused."""
        pid = int(params["pid"])
        name = params.get("name", "")
        processes.terminate(pid, name)
        self.store.log_action(
            "close_port", f"pid:{pid}:{name}", True,
            detail="stopped the process listening on a port", reversible=False)
        return {"ok": True}

    def summary(self, _):
        return {"text": triage.summarize_session(
            self.store.session_summary_data(), self.model),
            "ready": self.scanned_once}

    def ask_file(self, params):
        """Answer a free-form question about ONE flagged file, using only its
        metadata (never its bytes) so it stays a fully-local, no-egress chat."""
        q = (params.get("question") or "").strip()
        if not q:
            return {"text": "Ask a question about this file above."}
        f = params.get("file") or {}
        online = bool(params.get("online"))
        context = _file_facts(f)
        offline_rule = (
            " Be honest when something is uncertain. If they ask whether to "
            "delete it, remember Oyster never erases files — it moves them to a "
            "safe place you can undo.")
        system = (
            "You are a friendly helper inside a local, offline antivirus, talking "
            "to someone who is NOT good with computers. Answer their question "
            "about this one file using ONLY the facts given — you cannot see the "
            "file's actual contents. Use short, plain, everyday language and avoid "
            "technical jargon." + offline_rule
        )
        client = Ollama(self.model)
        if not client.available():
            return {"text": "The local AI helper isn't running right now, so I "
                    "can't answer extra questions. The explanation above still "
                    "applies, and you can turn the AI on from first-run setup."}
        # Opt-in online mode: pull a few public search snippets for the model to
        # ground its answer on. Only the query leaves the machine (never bytes),
        # and only to the sanctioned search host (see agent/websearch.py).
        web_ctx, sources = "", []
        if online:
            query = self._web_query(q, f)
            web_ctx, sources = websearch.context_block(query)
            if web_ctx:
                system = (
                    "You are a friendly helper inside a local antivirus, talking "
                    "to someone who is NOT good with computers. Answer their "
                    "question about this one file in short, plain language. You "
                    "have two things: facts the scanner gathered, and a few WEB "
                    "SEARCH RESULTS about this kind of file/name. Use the web "
                    "results to add context (e.g. what a name is known for, "
                    "whether it's a known good app or a known threat), but say "
                    "plainly when something is uncertain and don't overclaim."
                    + offline_rule)
        prompt = f"Facts about the file:\n{context}\n"
        if web_ctx:
            prompt += f"\nWeb search results:\n{web_ctx}\n"
        prompt += f"\nQuestion: {q}"
        try:
            return {"text": client.generate(prompt=prompt, system=system),
                    "online": bool(web_ctx), "sources": sources}
        except Exception as e:
            return {"text": f"(couldn't reach the local AI model: {e})"}

    @staticmethod
    def _web_query(question: str, f: dict) -> str:
        """Build a focused search query from the file's identity + the question,
        so the snippets are about THIS file/name rather than generic noise."""
        ev = f.get("evidence") or {}
        bits = [f.get("name") or "", ev.get("signature") or f.get("rule") or ""]
        # a file hash is the single best disambiguator when we have one
        sha = ev.get("sha256") or ""
        if sha:
            bits.append(sha[:16])
        bits.append(question)
        return " ".join(b for b in bits if b).strip()

    def second_opinion(self, params):
        """A local-AI second opinion on a LOW-confidence finding — the generic /
        heuristic hits where the deterministic engine is unsure. Weighs the
        metadata (signature class, code-signing, downloaded-vs-made-here) the same
        way a human analyst would and returns a calm, structured verdict.

        Uses only metadata, never the file's bytes, so it stays fully offline and
        keeps Oyster's no-egress promise."""
        f = params.get("file") or {}
        system = (
            "You are a careful malware-analysis assistant inside a LOCAL, offline "
            "antivirus, giving a second opinion on a file the scanner matched with "
            "LOW confidence — i.e. a generic/heuristic pattern, NOT a named virus. "
            "Decide how worried a non-technical person should be. Weigh these the "
            "way an analyst would: a file VALIDLY signed by a trusted vendor "
            "(Apple, Microsoft, a Developer ID) is strong evidence it is "
            "legitimate; a generic match on a file made on this computer is usually "
            "a false positive; an unsigned file that was downloaded deserves more "
            "caution. You CANNOT see the file's contents — judge only from the "
            "facts. Reply with ONLY a JSON object: {\"verdict\": one of \"likely "
            "safe\", \"worth a closer look\", \"likely harmful\"; \"why\": one or "
            "two plain-English sentences a normal person understands; "
            "\"suggestion\": a short recommended next step}."
        )
        obj = self._llm_json(system, f"File facts:\n{_file_facts(f)}")
        if not obj:
            return {"available": False,
                    "text": "The local AI helper isn't running, so a second "
                    "opinion isn't available right now. The explanation above "
                    "still applies."}
        verdict = str(obj.get("verdict", "")).strip().lower()
        # normalise whatever the model returns onto our three buckets
        if "harm" in verdict or "malic" in verdict or "danger" in verdict:
            verdict = "likely harmful"
        elif "closer" in verdict or "review" in verdict or "caution" in verdict:
            verdict = "worth a closer look"
        else:
            verdict = "likely safe"
        return {"available": True, "verdict": verdict,
                "why": str(obj.get("why", "")).strip(),
                "suggestion": str(obj.get("suggestion", "")).strip()}

    # --- local LLM helpers -------------------------------------------
    def _llm_json(self, system: str, prompt: str) -> dict | None:
        """Ask the local model for a JSON object; None if unavailable/failed."""
        try:
            client = Ollama(self.model)
            if not client.available():
                return None
            txt = client.generate(prompt=prompt, system=system, fmt_json=True)
            m = re.search(r"\{.*\}", txt, re.S)
            return json.loads(m.group(0)) if m else None
        except Exception:
            return None

    def _classify_important(self, names: list[str]) -> set:
        if not names:
            return set()
        obj = self._llm_json(
            "You output only JSON {\"important\": [filenames]}.",
            "From these filenames, list ONLY the ones that look like personally "
            "important documents a person would never want deleted (taxes, "
            "legal, identity, financial, medical, credentials, irreplaceable). "
            "Filenames:\n" + "\n".join(names))
        return set(obj.get("important", [])) if obj else set()

    # --- organize / cleanup ------------------------------------------
    def organize_scan(self, params):
        path = params.get("path") or str(Path.home() / "Downloads")
        return organize.analyze(path, progress=lambda s: _emit("progress", s),
                                classify_important=self._classify_important)

    def organize_execute(self, params):
        return organize.execute(params["action"], params.get("paths") or [],
                                params.get("folder", ""),
                                params.get("categories"))

    # --- application / program cleanup -------------------------------
    def apps_scan(self, _):
        from core import appcleanup
        res = appcleanup.list_apps(progress=lambda s: _emit("progress", s))
        # keep Windows uninstall commands engine-side, hand the UI only an id —
        # the renderer never gets to invoke an arbitrary command line.
        self._uninstallers = {}
        for i, a in enumerate(res.get("apps", [])):
            cmd = a.pop("uninstall", None)
            if cmd:
                uid = f"u{i}"
                self._uninstallers[uid] = cmd
                a["uid"] = uid
        return res

    def app_run_uninstaller(self, params):
        """Windows: launch a program's own (registry-registered) uninstaller."""
        import subprocess
        cmd = self._uninstallers.get(params.get("uid", ""))
        if not cmd:
            raise ValueError("no uninstaller for this program")
        subprocess.Popen(cmd, shell=True)   # the program's GUI uninstaller
        self.store.log_action("uninstall", params.get("name", ""), True,
                              detail="ran native uninstaller", reversible=False)
        return {"ok": True}

    # --- natural-language assistant (chat box) -----------------------
    def assistant(self, params):
        prompt = (params.get("prompt") or "").strip()
        folder = params.get("folder") or str(Path.home() / "Downloads")
        cmd = self._parse_command(prompt)
        files = organize.find_matching(
            folder, cmd.get("contains"), cmd.get("ext"),
            cmd.get("olderDays"), cmd.get("largerMb"))
        return {"summary": cmd.get("summary") or f"Files matching “{prompt}”",
                "action": cmd.get("action", "delete"), "files": files,
                "count": len(files), "folder": folder,
                "human": organize._human(sum(f["size"] for f in files))}

    def _parse_command(self, prompt: str) -> dict:
        obj = self._llm_json(
            "Convert a file-cleanup request into JSON with keys: summary "
            "(short plain-English description of what will be selected), "
            "contains (array of case-insensitive substrings to match in the "
            "filename), ext (array of file extensions like \".pdf\"), olderDays "
            "(integer or null), largerMb (integer or null), action (one of "
            "\"delete\",\"archive\"). Output ONLY the JSON object.",
            f"Request: {prompt}")
        if obj and isinstance(obj.get("contains", []), list):
            return obj
        return _fallback_parse(prompt)   # heuristic when Ollama is off

    # --- definitions updater (the one sanctioned online step) --------
    def update_defs(self, _):
        from updater import update as upd
        _emit("progress", "Downloading OSV CVE snapshot (PyPI, npm)…")
        # the updater prints to stdout; redirect so it can't corrupt JSON-RPC
        with contextlib.redirect_stdout(sys.stderr):
            upd.update_osv(["PyPI", "npm"], self.cfg)
        from core.osvdb import OsvDB
        return {"ok": True, "rows": OsvDB(self.cfg.osv_db_path).count}

    # --- first-run setup: fetch the data the app needs --------------
    def setup_status(self, _):
        from core.osvdb import OsvDB
        client = Ollama(self.model)
        ok = client.available()
        return {"clamav": bool(toolpaths.find_tool("clamscan")),
                "cve": OsvDB(self.cfg.osv_db_path).count,
                "ollama": ok, "model": self.model,
                "modelReady": (self.model in client.installed()) if ok else False}

    def setup_run(self, _):
        from core.osvdb import OsvDB
        res = {}
        # 1) ClamAV virus database — update via the bundled or installed freshclam.
        res["clamav"] = self._setup_clamav()
        # 2) OSV CVE snapshot (only if not present)
        try:
            if OsvDB(self.cfg.osv_db_path).count == 0:
                from updater import update as upd
                _emit("progress", "Downloading OSV CVE snapshot…")
                with contextlib.redirect_stdout(sys.stderr):
                    upd.update_osv(["PyPI", "npm"], self.cfg)
            res["cve"] = OsvDB(self.cfg.osv_db_path).count
        except Exception as e:
            res["cve"] = f"error: {e}"
        # 3) local AI model — install Ollama if needed (Windows), then pull.
        res["model"] = self._setup_model()
        return res

    def _setup_clamav(self) -> str:
        """Refresh ClamAV signatures. With a bundled ClamAV (Windows builds) the
        ship-time database already works, so an update is a nice-to-have; we never
        report a hard failure that would block setup."""
        import os
        import subprocess
        fc = toolpaths.find_tool("freshclam")
        if not (toolpaths.find_tool("clamscan") and fc):
            return "clamav not installed"
        _emit("progress", "Updating ClamAV virus database…")
        cmd = [fc]
        bdir = toolpaths.bundled_clamav_dir()
        try:
            if bdir is not None:
                # The build-time freshclam.conf points at a path that doesn't
                # exist on the user's machine, so write a runtime one aimed at the
                # bundled db dir. If that dir is read-only (a locked-down install),
                # keep the signatures we shipped.
                db = bdir / "db"
                if not (db.is_dir() and os.access(db, os.W_OK)):
                    return "using bundled signatures"
                self.cfg.db_path.parent.mkdir(parents=True, exist_ok=True)
                conf = self.cfg.db_path.parent / "freshclam.conf"
                conf.write_text(
                    f"DatabaseDirectory {db}\nDatabaseMirror database.clamav.net\n")
                cmd = [fc, f"--config-file={conf}"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
            return "ok" if r.returncode == 0 else "using bundled signatures"
        except Exception:
            return "using bundled signatures"

    def _setup_model(self) -> str:
        """Make a local AI model available. On Windows, install Ollama (winget)
        if it's missing, start it, then pull the recommended model."""
        rec = config.recommended_model()
        if not Ollama(rec).available():
            if sys.platform.startswith("win"):
                if not self._install_ollama_windows():
                    return "ollama not installed — get it at ollama.com, then re-run setup"
            else:
                return "ollama not running — start Ollama, then re-run setup"
        if not Ollama(rec).available():
            return "ollama not running"
        client = Ollama(rec)
        if rec not in client.installed():
            _emit("progress", f"Downloading local AI model {rec} "
                  "(one-time; a few minutes)…")
            client.pull(rec)
        self.model = self._pick_model()
        return self.model

    def _install_ollama_windows(self) -> bool:
        """Install Ollama via winget and bring its local server up. Best-effort;
        returns True only once the loopback API answers."""
        import os
        import shutil
        import subprocess
        _emit("progress", "Installing Ollama (one-time)…")
        try:
            subprocess.run(
                ["winget", "install", "--id", "Ollama.Ollama", "-e", "--silent",
                 "--accept-package-agreements", "--accept-source-agreements"],
                capture_output=True, text=True, timeout=1200)
        except Exception:
            return False
        exe = shutil.which("ollama")
        if not exe:
            cand = (Path(os.environ.get("LOCALAPPDATA", "")) / "Programs"
                    / "Ollama" / "ollama.exe")
            exe = str(cand) if cand.is_file() else None
        if not exe:
            return False
        _emit("progress", "Starting Ollama…")
        try:
            subprocess.Popen(
                [exe, "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except Exception:
            pass
        for _ in range(40):                 # wait up to ~40s for the API to answer
            if Ollama(self.model).available():
                return True
            time.sleep(1)
        return Ollama(self.model).available()


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
