"""Frozen entry point for the Oyster CLI.

PyInstaller analyzes this file with the repo root on sys.path (set via the
spec's `pathex`), so the absolute `cli.scan` / `core.*` / `agent.*` imports
resolve cleanly. We just hand off to the real CLI main().
"""
import sys

from cli.scan import main

if __name__ == "__main__":
    sys.exit(main())
