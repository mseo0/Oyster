"""Filesystem walker with cheap skip rules — the wide end of the funnel.

Yields candidate files only. Most of the disk is filtered out here, before any
hashing or engine work, so the expensive stages see a tiny fraction of files.
"""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from . import config


@dataclass
class Candidate:
    path: Path
    size: int
    ext: str
    interesting: bool   # worth a content scan vs. hash-only
    mtime: float = 0.0  # passed to the hash cache to skip a second stat()


def _skip_dir(dirpath: str, name: str, cfg: "config.ScanConfig") -> bool:
    # include_noise = scan absolutely everything (caches, node_modules, build
    # junk) for a true whole-computer sweep.
    if not cfg.include_noise and name in config.SKIP_DIR_NAMES:
        return True
    if not cfg.deep:
        full = os.path.join(dirpath, name)
        if full.startswith(config.SKIP_DIR_PREFIXES):
            return True
    return False


def walk(cfg: config.ScanConfig) -> Iterator[Candidate]:
    for root in cfg.roots:
        root = Path(root)
        if not root.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(
            root, followlinks=cfg.follow_symlinks
        ):
            # prune in place so os.walk never descends into skipped trees
            dirnames[:] = [
                d for d in dirnames if not _skip_dir(dirpath, d, cfg)
            ]
            for fn in filenames:
                p = Path(dirpath) / fn
                try:
                    # one lstat tells us symlink-ness, size and mtime at once,
                    # replacing the old is_symlink() + stat() double syscall.
                    st = os.lstat(p)
                    if stat.S_ISLNK(st.st_mode):
                        if not cfg.follow_symlinks:
                            continue
                        st = os.stat(p)  # resolve to the target
                except OSError:
                    continue
                # Only regular files. Skip devices/FIFOs/sockets — hashing e.g.
                # /dev/zero would read an infinite stream and hang the scan.
                if not stat.S_ISREG(st.st_mode):
                    continue
                ext = p.suffix.lower()
                yield Candidate(
                    path=p,
                    size=st.st_size,
                    ext=ext,
                    interesting=ext in config.INTERESTING_EXTENSIONS,
                    mtime=st.st_mtime,
                )
