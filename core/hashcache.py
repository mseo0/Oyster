"""Incremental hash cache — the single biggest speedup on a slow machine.

We remember (path -> size, mtime, sha256). On re-scan, unchanged files skip
both hashing and the engine pass. Also holds the local known-bad hash set so
hash verdicts need no network lookup.
"""
from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

_CHUNK = 1024 * 1024  # 1 MB — gentle on 8GB RAM


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(_CHUNK):
            h.update(chunk)
    return h.hexdigest()


class HashCache:
    _COMMIT_EVERY = 512  # batch writes so we don't fsync once per file

    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: built on the UI thread, used on the scan
        # worker thread (see findings.Store for the same rationale).
        self.db = sqlite3.connect(str(db_path), check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS filehashes (
                path TEXT PRIMARY KEY, size INTEGER, mtime REAL, sha256 TEXT
            );
            CREATE TABLE IF NOT EXISTS known_bad (
                sha256 TEXT PRIMARY KEY, label TEXT
            );
            -- Remembers content (by sha256) that the engine already scanned and
            -- found clean, tagged with the engine fingerprint that produced the
            -- verdict (clamscan + virus-DB version + rules + scan logic). On
            -- re-scan, an unchanged file whose verdict is still valid for the
            -- current fingerprint skips the costly clamscan pass entirely. A DB
            -- or rules update changes the fingerprint, so stale verdicts are
            -- ignored and the file is re-inspected — no false sense of safety.
            CREATE TABLE IF NOT EXISTS clean_scans (
                sha256 TEXT PRIMARY KEY, engine_ver TEXT
            );
            """
        )
        self.db.commit()
        # Rows are buffered in memory and flushed in batches. We deliberately do
        # NOT keep a write transaction open across the scan loop: that would
        # hold SQLite's write lock and block the separate findings.Store
        # connection ("database is locked") when a detection is recorded.
        self._buffer: list[tuple] = []

    def hash_for(self, path: Path, size: int | None = None,
                 mtime: float | None = None) -> tuple[str, bool]:
        """Return (sha256, changed). Uses size+mtime to avoid re-hashing.

        size/mtime can be supplied by the walker (which already stat()'d the
        file) to skip a redundant stat syscall per candidate.
        """
        if size is None or mtime is None:
            try:
                st = path.stat()
            except OSError:
                return "", False
            size, mtime = st.st_size, st.st_mtime
        row = self.db.execute(
            "SELECT size,mtime,sha256 FROM filehashes WHERE path=?",
            (str(path),),
        ).fetchone()
        if row and row[0] == size and row[1] == mtime:
            return row[2], False  # unchanged -> cached
        try:
            digest = sha256_file(path)
        except OSError:
            return "", False  # unreadable (perms, vanished, I/O) -> skip, never fatal
        self._buffer.append((str(path), size, mtime, digest))
        if len(self._buffer) >= self._COMMIT_EVERY:
            self.flush()
        return digest, True

    def flush(self) -> None:
        """Write buffered hashes in one transaction. Call at the end of a scan."""
        if self._buffer:
            self.db.executemany(
                "INSERT OR REPLACE INTO filehashes VALUES (?,?,?,?)",
                self._buffer)
            self.db.commit()
            self._buffer.clear()

    def is_clean(self, sha256: str, engine_ver: str) -> bool:
        """True if this exact content was already scanned clean by the current
        engine fingerprint — so we can skip the expensive clamscan pass."""
        row = self.db.execute(
            "SELECT 1 FROM clean_scans WHERE sha256=? AND engine_ver=?",
            (sha256, engine_ver),
        ).fetchone()
        return row is not None

    def mark_clean(self, shas: list[str], engine_ver: str) -> None:
        """Record content (by sha256) the engine just found clean. INSERT OR
        REPLACE keeps one row per content, so the table grows with distinct
        files, not with every re-scan or DB update."""
        if not shas:
            return
        self.db.executemany(
            "INSERT OR REPLACE INTO clean_scans VALUES (?,?)",
            [(s, engine_ver) for s in shas],
        )
        self.db.commit()

    def has_known_bad(self) -> bool:
        """True if any local known-bad hashes are loaded. When the set is empty
        there's nothing to match a file's hash against, so the scanner can skip
        hashing files it won't also content-scan — a big saving on a full scan."""
        return self.db.execute(
            "SELECT 1 FROM known_bad LIMIT 1").fetchone() is not None

    def known_bad_label(self, sha256: str) -> str | None:
        row = self.db.execute(
            "SELECT label FROM known_bad WHERE sha256=?", (sha256,)
        ).fetchone()
        return row[0] if row else None

    def load_known_bad(self, pairs: list[tuple[str, str]]) -> int:
        """Bulk-load (sha256, label) from a locally downloaded hash list."""
        self.db.executemany(
            "INSERT OR REPLACE INTO known_bad VALUES (?,?)", pairs
        )
        self.db.commit()
        return len(pairs)
