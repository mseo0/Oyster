"""Findings + an append-only action audit log.

The audit log is what powers the end-of-scan AI summary: every detection and
every action (quarantine / restore / kill / mark-safe) is recorded as a fact,
so the LLM summarizes *recorded history* rather than inventing it.
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingKind(str, Enum):
    FILE_MALWARE = "file_malware"
    FILE_SUSPICIOUS = "file_suspicious"
    PROCESS_SUSPICIOUS = "process_suspicious"
    VULNERABILITY = "vulnerability"


@dataclass
class Finding:
    kind: FindingKind
    severity: Severity
    target: str                       # file path or "pid:name"
    rule: str                         # what matched (signature/heuristic/CVE)
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def to_row(self) -> tuple:
        return (
            self.ts, self.kind.value, self.severity.value, self.target,
            self.rule, self.detail, json.dumps(self.evidence),
        )


class Store:
    """SQLite-backed findings + action audit log. Pure stdlib, no network."""

    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: the UI builds this on the main thread but the
        # scan runs on a worker thread. WAL + short serialized writes make the
        # shared connection safe here.
        self.db = sqlite3.connect(str(db_path), check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self._migrate()

    def _migrate(self) -> None:
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY,
                ts REAL, kind TEXT, severity TEXT, target TEXT,
                rule TEXT, detail TEXT, evidence TEXT
            );
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY,
                ts REAL, action TEXT, target TEXT,
                approved INTEGER, detail TEXT, reversible INTEGER
            );
            -- User's "I trust this" decisions (Mark safe / Ignore). Keyed on a
            -- stable identity (a file's content hash, a port's program, a CVE's
            -- target) so the same finding stays hidden on FUTURE scans until the
            -- user removes it here. Survives restarts; this is the only thing
            -- that suppresses a finding across runs.
            CREATE TABLE IF NOT EXISTS allowlist (
                key TEXT PRIMARY KEY, kind TEXT, label TEXT, mode TEXT, ts REAL
            );
            """
        )
        self.db.commit()

    def add_finding(self, f: Finding) -> int:
        cur = self.db.execute(
            "INSERT INTO findings (ts,kind,severity,target,rule,detail,evidence)"
            " VALUES (?,?,?,?,?,?,?)",
            f.to_row(),
        )
        self.db.commit()
        return cur.lastrowid

    # --- allowlist (persisted "trust this" decisions) ---------------------
    def allow(self, key: str, kind: str, label: str, mode: str) -> None:
        """Remember a Mark-safe / Ignore decision so the finding stays hidden on
        later scans. INSERT OR REPLACE keeps one row per identity."""
        self.db.execute(
            "INSERT OR REPLACE INTO allowlist (key,kind,label,mode,ts)"
            " VALUES (?,?,?,?,?)", (key, kind, label, mode, time.time()))
        self.db.commit()

    def allowed_keys(self) -> set[str]:
        return {r[0] for r in self.db.execute("SELECT key FROM allowlist")}

    def list_allowed(self) -> list[dict[str, Any]]:
        rows = self.db.execute(
            "SELECT key,kind,label,mode,ts FROM allowlist ORDER BY ts DESC")
        return [{"key": k, "kind": kd, "label": lb, "mode": m, "ts": ts}
                for (k, kd, lb, m, ts) in rows]

    def unallow(self, key: str) -> None:
        self.db.execute("DELETE FROM allowlist WHERE key=?", (key,))
        self.db.commit()

    def clear_allowed(self) -> int:
        n = self.db.execute("SELECT COUNT(*) FROM allowlist").fetchone()[0]
        self.db.execute("DELETE FROM allowlist")
        self.db.commit()
        return n

    def log_action(self, action: str, target: str, approved: bool,
                   detail: str = "", reversible: bool = True) -> None:
        self.db.execute(
            "INSERT INTO actions (ts,action,target,approved,detail,reversible)"
            " VALUES (?,?,?,?,?,?)",
            (time.time(), action, target, int(approved), detail,
             int(reversible)),
        )
        self.db.commit()

    def session_summary_data(self, since: float = 0.0) -> dict[str, Any]:
        """Structured facts for the AI to summarize. No prose here on purpose."""
        f = self.db.execute(
            "SELECT kind,severity,target,rule,detail FROM findings WHERE ts>=?",
            (since,),
        ).fetchall()
        a = self.db.execute(
            "SELECT action,target,approved,detail,reversible FROM actions"
            " WHERE ts>=?",
            (since,),
        ).fetchall()
        return {
            "findings": [
                {"kind": k, "severity": s, "target": t, "rule": r, "detail": d}
                for (k, s, t, r, d) in f
            ],
            "actions": [
                {"action": ac, "target": t, "approved": bool(ap),
                 "detail": d, "reversible": bool(rev)}
                for (ac, t, ap, d, rev) in a
            ],
        }
