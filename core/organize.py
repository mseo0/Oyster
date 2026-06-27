"""File cleanup & organization — analyze a folder, return reviewable detail, and
execute approved actions.

Analysis is read-only and returns enough per-file detail for the UI to let the
user *review* before acting: the organize plan (which files go to which folder),
the full junk list, duplicate groups (keep + redundant copies), large files, and
files not opened in months. Execution is reversible — files move to category
subfolders, an archive folder, or a dated cleanup vault; never a hard delete.
"""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

CATEGORIES = {
    "Images": {".jpg", ".jpeg", ".png", ".gif", ".heic", ".webp", ".tiff", ".bmp", ".svg"},
    "Documents": {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".pages", ".numbers", ".key", ".csv", ".md"},
    "Videos": {".mp4", ".mov", ".avi", ".mkv", ".webm", ".m4v"},
    "Audio": {".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg"},
    "Archives": {".zip", ".rar", ".7z", ".tar", ".gz", ".dmg", ".pkg", ".iso"},
    "Code": {".py", ".js", ".ts", ".html", ".css", ".json", ".sh", ".c", ".cpp", ".java", ".go", ".rs"},
}
_JUNK_NAMES = {".ds_store", "thumbs.db", "desktop.ini"}
_JUNK_EXTS = {".tmp", ".temp", ".log", ".crdownload", ".part", ".cache"}
_LARGE_BYTES = 100 * 1024 * 1024
_STALE_DAYS = 180
_BUF = 1024 * 1024
_CAP = 500   # max items returned per recommendation


def _human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _category(p: Path) -> str:
    ext = p.suffix.lower()
    for cat, exts in CATEGORIES.items():
        if ext in exts:
            return cat
    return "Other"


def _info(p: Path, st=None) -> dict:
    try:
        st = st or p.stat()
        return {"path": str(p), "name": p.name, "size": st.st_size,
                "human": _human(st.st_size),
                "modified": _date(st.st_mtime), "accessed": _date(st.st_atime),
                "atime": st.st_atime}
    except OSError:
        return {"path": str(p), "name": p.name, "size": 0, "human": "0 B",
                "modified": "", "accessed": "", "atime": 0}


def _date(ts: float) -> str:
    try:
        return time.strftime("%b %-d, %Y", time.localtime(ts))
    except Exception:
        return ""


@dataclass
class Rec:
    key: str
    title: str
    detail: str
    kind: str
    bytes: int = 0
    count: int = 0
    items: list = field(default_factory=list)
    groups: list = field(default_factory=list)
    categories: dict = field(default_factory=dict)


def analyze(folder: str, progress=lambda s: None) -> dict:
    root = Path(folder).expanduser()
    by_cat: dict[str, list] = {}
    junk, large, stale = [], [], []
    by_size: dict[int, list[Path]] = {}
    now = time.time()
    total_files = total_bytes = 0

    for dirpath, dirnames, filenames in os.walk(root):
        # don't descend into our own archive/vault output
        dirnames[:] = [d for d in dirnames if d not in
                       ("Oyster Archive", ".oyster")]
        if len(Path(dirpath).relative_to(root).parts) >= 5:
            dirnames[:] = []
        for fn in filenames:
            p = Path(dirpath) / fn
            try:
                st = p.stat()
            except OSError:
                continue
            total_files += 1
            total_bytes += st.st_size
            info = _info(p, st)
            cat = _category(p)
            if cat != "Other":
                by_cat.setdefault(cat, []).append(info)
            if fn.lower() in _JUNK_NAMES or p.suffix.lower() in _JUNK_EXTS:
                junk.append(info)
            if st.st_size >= _LARGE_BYTES:
                large.append(info)
            if (now - st.st_atime) > _STALE_DAYS * 86400 and st.st_size > 1024:
                stale.append(info)
            by_size.setdefault(st.st_size, []).append(p)
            if total_files % 500 == 0:
                progress(f"Analyzing · {total_files:,} files")

    recs: list[Rec] = []

    cats = {c: items for c, items in by_cat.items() if len(items) >= 3}
    if cats:
        recs.append(Rec(
            "organize", "Organize into folders by type",
            "Sort " + ", ".join(f"{len(i)} {c.lower()}" for c, i in
                                sorted(cats.items(), key=lambda x: -len(x[1]))[:4])
            + " into tidy subfolders.", "organize",
            count=sum(len(i) for i in cats.values()),
            categories={c: i[:_CAP] for c, i in cats.items()}))

    if junk:
        recs.append(Rec("junk", "Clear junk & temp files",
                        f"{len(junk)} cache/temp files reclaiming "
                        f"{_human(sum(i['size'] for i in junk))}.", "junk",
                        bytes=sum(i["size"] for i in junk), count=len(junk),
                        items=junk[:_CAP]))

    groups = _dup_groups(by_size, progress)
    if groups:
        dup_bytes = sum(g["size"] * len(g["copies"]) for g in groups)
        recs.append(Rec("duplicates", "Review duplicate files",
                        f"{sum(len(g['copies']) for g in groups)} duplicates in "
                        f"{len(groups)} group(s) wasting {_human(dup_bytes)}.",
                        "duplicates", bytes=dup_bytes,
                        count=sum(len(g["copies"]) for g in groups),
                        groups=groups[:_CAP]))

    if large:
        large.sort(key=lambda i: -i["size"])
        recs.append(Rec("large", "Review large files",
                        f"{len(large)} files over 100 MB "
                        f"({_human(sum(i['size'] for i in large))} total).",
                        "large", bytes=sum(i["size"] for i in large),
                        count=len(large), items=large[:_CAP]))

    if stale:
        stale.sort(key=lambda i: i["atime"])
        recs.append(Rec("stale", "Files you haven't opened in months",
                        f"{len(stale)} files untouched for 6+ months "
                        f"({_human(sum(i['size'] for i in stale))}).", "stale",
                        bytes=sum(i["size"] for i in stale), count=len(stale),
                        items=stale[:_CAP]))

    return {"folder": str(root), "totalFiles": total_files,
            "totalBytes": total_bytes, "totalHuman": _human(total_bytes),
            "recs": [_rec_dict(r) for r in recs]}


def _rec_dict(r: Rec) -> dict:
    return {"key": r.key, "title": r.title, "detail": r.detail, "kind": r.kind,
            "bytes": r.bytes, "human": _human(r.bytes) if r.bytes else "",
            "count": r.count, "items": r.items, "groups": r.groups,
            "categories": r.categories}


def _hash(p: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(p, "rb") as fh:
            while chunk := fh.read(_BUF):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def _dup_groups(by_size: dict, progress) -> list:
    groups = []
    for size, paths in by_size.items():
        if len(paths) < 2 or size < 4096:
            continue
        seen: dict[str, list] = {}
        for p in paths:
            d = _hash(p)
            if d:
                seen.setdefault(d, []).append(p)
        for d, dup in seen.items():
            if len(dup) < 2:
                continue
            dup.sort(key=lambda p: p.stat().st_mtime)  # oldest = keep
            groups.append({"size": size, "human": _human(size),
                           "keep": _info(dup[0]),
                           "copies": [_info(x) for x in dup[1:]]})
    groups.sort(key=lambda g: -g["size"] * len(g["copies"]))
    return groups


# --- execution (reversible) -------------------------------------------------
def _vault() -> Path:
    v = Path.home() / ".oyster" / "cleanup" / time.strftime("%Y%m%d-%H%M%S")
    v.mkdir(parents=True, exist_ok=True)
    return v


def _unique(dest: Path) -> Path:
    if not dest.exists():
        return dest
    stem, suf, i = dest.stem, dest.suffix, 1
    while True:
        cand = dest.with_name(f"{stem} ({i}){suf}")
        if not cand.exists():
            return cand
        i += 1


def execute(action: str, paths: list[str], folder: str = "",
            categories: dict | None = None) -> dict:
    """action: 'delete' (-> vault), 'archive' (-> <folder>/Oyster Archive),
    'organize' (-> <folder>/<category>). All moves, never hard deletes."""
    moved = freed = errors = 0

    if action == "organize" and categories:
        base = Path(folder).expanduser()
        for cat, items in categories.items():
            dest_dir = base / cat
            dest_dir.mkdir(exist_ok=True)
            for it in items:
                src = Path(it["path"] if isinstance(it, dict) else it)
                try:
                    if src.exists() and src.parent != dest_dir:
                        src.rename(_unique(dest_dir / src.name))
                        moved += 1
                except OSError:
                    errors += 1
        return {"moved": moved, "errors": errors, "freed": 0, "human": ""}

    if action == "archive":
        dest_dir = Path(folder).expanduser() / "Oyster Archive"
        dest_dir.mkdir(parents=True, exist_ok=True)
    else:  # delete -> reversible vault
        dest_dir = _vault()

    for f in paths:
        src = Path(f)
        try:
            sz = src.stat().st_size
            src.rename(_unique(dest_dir / src.name))
            moved += 1
            freed += sz
        except OSError:
            errors += 1
    return {"moved": moved, "errors": errors, "freed": freed,
            "human": _human(freed), "dest": str(dest_dir)}
