"""Local OSV advisory database — built from a downloaded snapshot, queried offline.

The updater (the lone online component) downloads OSV's per-ecosystem exports and
calls `build_from_dir`. Everything here is offline: parse advisory JSON into a
flat SQLite table and answer "is (ecosystem, name, version) vulnerable?" with no
network access.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from .version_cmp import in_range


@dataclass
class Advisory:
    osv_id: str
    summary: str
    introduced: str | None
    fixed: str | None
    severity: str


class OsvDB:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(db_path))
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS advisories (
                osv_id TEXT, ecosystem TEXT, package TEXT,
                introduced TEXT, fixed TEXT, severity TEXT, summary TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_adv_pkg
                ON advisories (ecosystem, package);
            """
        )
        self.db.commit()

    @property
    def count(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM advisories").fetchone()[0]

    def query(self, ecosystem: str, package: str, version: str) -> list[Advisory]:
        rows = self.db.execute(
            "SELECT osv_id,introduced,fixed,severity,summary FROM advisories"
            " WHERE ecosystem=? AND package=?",
            (ecosystem, package.lower()),
        ).fetchall()
        hits: list[Advisory] = []
        for osv_id, introduced, fixed, severity, summary in rows:
            if in_range(version, introduced, fixed):
                hits.append(Advisory(osv_id, summary, introduced, fixed,
                                     severity))
        return hits

    # --- snapshot ingestion (called by the updater) -----------------------
    def build_from_dir(self, json_dir: Path) -> int:
        """Parse every OSV advisory JSON under json_dir into the table."""
        self.db.execute("DELETE FROM advisories")
        n = 0
        for jf in json_dir.rglob("*.json"):
            try:
                adv = json.loads(jf.read_text())
            except Exception:
                continue
            n += self._ingest_one(adv)
        self.db.commit()
        return n

    def _ingest_one(self, adv: dict) -> int:
        osv_id = adv.get("id", "")
        summary = adv.get("summary") or adv.get("details", "")[:200]
        severity = ""
        for s in adv.get("severity", []) or []:
            severity = s.get("score", "") or severity
        added = 0
        for affected in adv.get("affected", []) or []:
            pkg = affected.get("package", {}) or {}
            eco = pkg.get("ecosystem", "")
            name = (pkg.get("name", "") or "").lower()
            if not eco or not name:
                continue
            ranges = affected.get("ranges", []) or []
            for rng in ranges:
                introduced = fixed = None
                for ev in rng.get("events", []) or []:
                    if "introduced" in ev:
                        introduced = ev["introduced"]
                    if "fixed" in ev:
                        fixed = ev["fixed"]
                self.db.execute(
                    "INSERT INTO advisories VALUES (?,?,?,?,?,?,?)",
                    (osv_id, eco, name, introduced, fixed, severity, summary),
                )
                added += 1
            # advisories that only list explicit versions (no ranges)
            if not ranges:
                for v in affected.get("versions", []) or []:
                    self.db.execute(
                        "INSERT INTO advisories VALUES (?,?,?,?,?,?,?)",
                        (osv_id, eco, name, v, _next_after(v), severity, summary),
                    )
                    added += 1
        return added


def _next_after(v: str) -> str:
    """Synthesize a 'fixed' bound so an exact-version advisory matches only v."""
    return v + ".0.post0"
