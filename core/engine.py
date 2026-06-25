"""ClamAV integration — signatures + YARA + archive unpacking in one engine.

We shell out to `clamscan` (or talk to a running `clamd` if present). If ClamAV
isn't installed we degrade gracefully: hash/known-bad checks still work, content
scanning is reported as unavailable rather than crashing. No network imports.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from .toolpaths import find_tool


@dataclass
class EngineResult:
    available: bool
    infected: bool
    signature: str = ""
    detail: str = ""


class ClamEngine:
    def __init__(self, extra_yara_dir: Path | None = None):
        # find_tool (not shutil.which) so the bundled .app, which launches with
        # a minimal PATH, still locates Homebrew's clamscan.
        self.clamscan = find_tool("clamscan")
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
        cmd = [self.clamscan, "--no-summary", "--stdout"]
        if self.extra_yara_dir and self.extra_yara_dir.exists():
            cmd += ["-d", str(self.extra_yara_dir)]
        cmd.append(str(path))
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
