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
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS filehashes (
                path TEXT PRIMARY KEY, size INTEGER, mtime REAL, sha256 TEXT
            );
            CREATE TABLE IF NOT EXISTS known_bad (
                sha256 TEXT PRIMARY KEY, label TEXT
            );
            """
        )
        self.db.commit()
        self._pending = 0

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
        digest = sha256_file(path)
        self.db.execute(
            "INSERT OR REPLACE INTO filehashes VALUES (?,?,?,?)",
            (str(path), size, mtime, digest),
        )
        self._pending += 1
        if self._pending >= self._COMMIT_EVERY:
            self.flush()
        return digest, True

    def flush(self) -> None:
        """Commit any batched hash writes. Call at the end of a scan."""
        if self._pending:
            self.db.commit()
            self._pending = 0

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
