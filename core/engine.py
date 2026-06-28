"""ClamAV integration — signatures + YARA + archive unpacking in one engine.

We shell out to `clamscan` (or talk to a running `clamd` if present). If ClamAV
isn't installed we degrade gracefully: hash/known-bad checks still work, content
scanning is reported as unavailable rather than crashing. No network imports.
"""
from __future__ import annotations

import hashlib
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .toolpaths import bundled_clamav, find_clamav_db, find_tool

# Bump when the scan logic (rules, limits, parsing) changes in a way that could
# change a verdict, so cached "clean" results from older builds are invalidated.
_SCAN_LOGIC_VERSION = "2"

# Bound per-file and per-archive work so one large file or a deeply-nested
# archive can't grind forever and hang an entire batch — the classic
# "the scan got stuck while inspecting files" symptom. clamscan skips anything
# that exceeds a limit and assumes it clean; --alert-exceeds-max=no keeps those
# skips from being reported as suspicious (which would be a false positive).
_SCAN_LIMITS = [
    "--max-scantime=20000",     # ms: give up on any single file after 20s
    "--max-filesize=200M",      # skip very large files
    "--max-scansize=200M",      # cap total data scanned per archive/container
    "--max-files=10000",        # cap files extracted from one archive
    "--max-recursion=8",        # cap archive nesting depth (zip-bomb guard)
    "--alert-exceeds-max=no",   # a skipped-because-too-big file is NOT a threat
]


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
        self._sig_ver: str | None = None

    @property
    def available(self) -> bool:
        return self.clamscan is not None

    def signature_version(self) -> str:
        """A short fingerprint of everything that affects a verdict: the clamscan
        + virus-DB version, our bundled YARA rules, and the scan-logic version.

        Cached clean verdicts are keyed on this, so a virus-DB update, a rules
        change, or a logic bump automatically invalidates them and the affected
        files get re-scanned. Computed once and memoised per engine instance.
        """
        if self._sig_ver is not None:
            return self._sig_ver
        parts = [_SCAN_LOGIC_VERSION]
        if self.available:
            try:
                # `--version` prints "ClamAV <ver>/<db-ver>/<date>" and is cheap
                # (it does NOT load the full signature DB). The db-ver bumps on
                # every freshclam update, which is exactly the invalidation we want.
                out = subprocess.run(
                    [self.clamscan, "--version"],
                    capture_output=True, text=True, timeout=30,
                )
                parts.append(out.stdout.strip() or "nover")
            except Exception:
                parts.append("nover")
        if self.extra_yara_dir and self.extra_yara_dir.exists():
            for f in sorted(self.extra_yara_dir.glob("*.yar")):
                try:
                    st = f.stat()
                    parts.append(f"{f.name}:{st.st_size}:{int(st.st_mtime)}")
                except OSError:
                    pass
        self._sig_ver = hashlib.sha1("|".join(parts).encode()).hexdigest()[:16]
        return self._sig_ver

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
        cmd = [self.clamscan, "--no-summary", "--stdout", *_SCAN_LIMITS]
        if self.bundled_db:        # point bundled clamscan at its bundled DB
            cmd += ["--database", self.bundled_db]
        if self.extra_yara_dir and self.extra_yara_dir.exists():
            cmd += ["-d", str(self.extra_yara_dir)]
        return cmd

    def scan_files(
        self, paths: list[Path],
        on_file: Callable[[str, str | None], None] | None = None,
    ) -> dict[str, str]:
        """Scan a *batch* of files in a single clamscan invocation, streaming
        each per-file result as it lands.

        This is the key to a full-disk scan finishing: clamscan loads the entire
        signature database (hundreds of MB) on every launch, so scanning files
        one process-per-file reloads it thousands of times and the scan appears
        to hang on "Inspecting…". Passing a whole batch via --file-list loads the
        DB once and scans them all, turning hours into minutes.

        clamscan prints a verdict line per file as it goes ("<path>: OK" /
        "<path>: <Sig> FOUND"). We read those incrementally on a background
        thread and call `on_file(path, signature_or_None)` for each, so the UI
        keeps moving instead of freezing for the whole batch. A wall-clock
        deadline kills a wedged process as a backstop to the per-file limit.

        Returns a map of {infected_path: signature}. Clean files are absent.
        """
        if not self.available or not paths:
            return {}
        # A file list avoids OS command-line length limits on large batches.
        listf = None
        hits: dict[str, str] = {}
        try:
            with tempfile.NamedTemporaryFile(
                "w", suffix=".txt", delete=False, encoding="utf-8"
            ) as fh:
                listf = fh.name
                for p in paths:
                    fh.write(f"{p}\n")
            cmd = self._base_cmd() + [f"--file-list={listf}"]
            # The per-file --max-scantime bounds real work; this wall-clock
            # deadline is only a backstop against a fully wedged process.
            deadline = min(1800, 90 + 2 * len(paths))
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True,
            )

            def reader() -> None:
                for line in proc.stdout:          # blocks until each line lands
                    line = line.rstrip()
                    if line.endswith("FOUND"):
                        # "<path>: <Signature> FOUND"
                        head = line[: -len("FOUND")].rstrip()
                        path, sep, sig = head.rpartition(": ")
                        if sep:
                            sig = sig.strip()
                            hits[path] = sig
                            if on_file:
                                on_file(path, sig)
                    elif line.endswith(": OK"):
                        if on_file:
                            on_file(line[: -len(": OK")], None)

            t = threading.Thread(target=reader, daemon=True)
            t.start()
            try:
                proc.wait(timeout=deadline)
            except subprocess.TimeoutExpired:
                proc.kill()                       # backstop: drop a wedged batch
            t.join(timeout=5)
            return hits
        finally:
            if listf:
                try:
                    Path(listf).unlink()
                except OSError:
                    pass
