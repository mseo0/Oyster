"""Reversible quarantine vault — "delete" never means rm.

Files are moved (XOR-obfuscated so the stored copy can't execute or be matched
in place) into ~/.oyster/quarantine with a manifest so they can be restored.
This is the safety net behind the human-in-the-loop approval gate.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path

_XOR_KEY = 0x4C  # neutralizes the stored copy; not security, just defang

_BUF = 1024 * 1024


def _xor_copy(src: Path, dst: Path) -> None:
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        while chunk := fi.read(_BUF):
            fo.write(bytes(b ^ _XOR_KEY for b in chunk))


class Quarantine:
    def __init__(self, vault_dir: Path):
        self.vault = vault_dir
        self.vault.mkdir(parents=True, exist_ok=True)
        self.manifest = self.vault / "manifest.json"
        if not self.manifest.exists():
            self.manifest.write_text("{}")

    def _load(self) -> dict:
        return json.loads(self.manifest.read_text() or "{}")

    def _save(self, data: dict) -> None:
        self.manifest.write_text(json.dumps(data, indent=2))

    def quarantine(self, path: Path, reason: str = "") -> str:
        """Move file into the vault (defanged). Returns the quarantine id."""
        qid = uuid.uuid4().hex[:12]
        stored = self.vault / f"{qid}.qbin"
        _xor_copy(path, stored)
        data = self._load()
        data[qid] = {
            "original": str(path),
            "reason": reason,
            "ts": time.time(),
            "size": path.stat().st_size,
        }
        self._save(data)
        os.remove(path)  # safe: we hold a reversible copy
        return qid

    def empty(self) -> dict:
        """Permanently delete everything in the vault — the one place in Oyster
        where files really are erased. Returns how many items and bytes were
        freed. Irreversible by design: this is the user emptying their trash."""
        data = self._load()
        removed, freed = 0, 0
        for qid, entry in list(data.items()):
            stored = self.vault / f"{qid}.qbin"
            try:
                freed += stored.stat().st_size
            except OSError:
                pass
            stored.unlink(missing_ok=True)
            removed += 1
        # Sweep any orphaned .qbin files not tracked in the manifest, too.
        for stray in self.vault.glob("*.qbin"):
            try:
                freed += stray.stat().st_size
            except OSError:
                pass
            stray.unlink(missing_ok=True)
        self._save({})
        return {"removed": removed, "bytes": freed}

    def restore(self, qid: str) -> Path:
        # qids are uuid4 hex (see quarantine()); reject anything else so a
        # tampered/garbage id can never traverse out of the vault via {qid}.qbin.
        if not (len(qid) == 12 and all(c in "0123456789abcdef" for c in qid)):
            raise ValueError(f"malformed quarantine id {qid!r}")
        data = self._load()
        entry = data.get(qid)
        if not entry:
            raise KeyError(f"unknown quarantine id {qid}")
        original = Path(entry["original"])
        original.parent.mkdir(parents=True, exist_ok=True)
        _xor_copy(self.vault / f"{qid}.qbin", original)  # XOR is its own inverse
        (self.vault / f"{qid}.qbin").unlink(missing_ok=True)
        del data[qid]
        self._save(data)
        return original

    def list(self) -> dict:
        return self._load()
