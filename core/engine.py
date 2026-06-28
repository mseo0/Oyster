"""ClamAV integration — signatures + YARA + archive unpacking in one engine.

We shell out to `clamscan` (or talk to a running `clamd` if present). If ClamAV
isn't installed we degrade gracefully: hash/known-bad checks still work, content
scanning is reported as unavailable rather than crashing. No network imports.
"""
from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .toolpaths import bundled_clamav, find_clamav_db, find_tool


@dataclass
class EngineResult:
    available: bool
    infected: bool
    signature: str = ""
    detail: str = ""


class ClamEngine:
    def __init__(self, extra_yara_dir: Path | None = None):
        # Prefer a clamscan bundled with the app (Windows ships its own); else
        # find one on the system (find_tool, not shutil.which, so the minimal-PATH
        # .app still locates Homebrew's).
        self.bundled_db: str | None = None
        b = bundled_clamav()
        if b:
            self.clamscan = str(b)
            db = b.parent / "db"
            self.bundled_db = str(db) if db.is_dir() else None
        else:
            self.clamscan = find_tool("clamscan")
            self.bundled_db = find_clamav_db()
        self.extra_yara_dir = extra_yara_dir

    @property
    def available(self) -> bool:
        return self.clamscan is not None

    def status(self) -> str:
        if not self.available:
            return ("ClamAV not found. Install it (brew install clamav / "
                    "winget install ClamAV.ClamAV) and run `freshclam`.")
        return f"ClamAV engine: {self.clamscan}"

    def scan_file(self, path: Path) -> EngineResult:
        if not self.available:
            return EngineResult(available=False, infected=False,
                                detail="engine unavailable")
        cmd = self._base_cmd() + [str(path)]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )
        except subprocess.TimeoutExpired:
            return EngineResult(True, False, detail="scan timeout")
        # clamscan exit codes: 0 clean, 1 infected, 2 error
        if proc.returncode == 1:
            sig = ""
            for line in proc.stdout.splitlines():
                if line.strip().endswith("FOUND"):
                    # "<path>: <Signature> FOUND"
                    sig = line.split(":", 1)[-1].rsplit("FOUND", 1)[0].strip()
                    break
            return EngineResult(True, True, signature=sig, detail=proc.stdout)
        if proc.returncode == 2:
            return EngineResult(True, False, detail=proc.stderr.strip())
        return EngineResult(True, False)

    def _base_cmd(self) -> list[str]:
        cmd = [self.clamscan, "--no-summary", "--stdout"]
        if self.bundled_db:        # point bundled clamscan at its bundled DB
            cmd += ["--database", self.bundled_db]
        if self.extra_yara_dir and self.extra_yara_dir.exists():
            cmd += ["-d", str(self.extra_yara_dir)]
        return cmd

    def scan_files(self, paths: list[Path]) -> dict[str, str]:
        """Scan a *batch* of files in a single clamscan invocation.

        This is the key to a full-disk scan finishing: clamscan loads the entire
        signature database (hundreds of MB) on every launch, so scanning files
        one process-per-file reloads it thousands of times and the scan appears
        to hang on "Inspecting…". Passing a whole batch via --file-list loads the
        DB once and scans them all, turning hours into minutes.

        Returns a map of {infected_path: signature}. Clean files are absent.
        """
        if not self.available or not paths:
            return {}
        # A file list avoids OS command-line length limits on large batches.
        listf = None
        try:
            with tempfile.NamedTemporaryFile(
                "w", suffix=".txt", delete=False, encoding="utf-8"
            ) as fh:
                listf = fh.name
                for p in paths:
                    fh.write(f"{p}\n")
            cmd = self._base_cmd() + [f"--file-list={listf}"]
            # DB load dominates; per-file work after that is tiny. Scale the
            # ceiling with batch size but keep a generous floor and a hard cap.
            timeout = min(900, 120 + len(paths))
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=timeout
                )
            except subprocess.TimeoutExpired:
                return {}
            if proc.returncode not in (0, 1):   # 2 = error; nothing reliable
                return {}
            hits: dict[str, str] = {}
            for line in proc.stdout.splitlines():
                line = line.rstrip()
                if not line.endswith("FOUND"):
                    continue
                # "<path>: <Signature> FOUND" — split off the trailing verdict,
                # then the last ": " separates path from signature.
                head = line[: -len("FOUND")].rstrip()
                path, sep, sig = head.rpartition(": ")
                if sep:
                    hits[path] = sig.strip()
            return hits
        finally:
            if listf:
                try:
                    Path(listf).unlink()
                except OSError:
                    pass
