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
import re
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

from core import provenance

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

# Filename signals that a file is personally important — never suggest deleting
# these, and offer to set them aside in a dedicated folder.
_IMPORTANT_KW = {
    "tax": "tax document", "taxes": "tax document", "w2": "tax form",
    "w-2": "tax form", "1099": "tax form", "irs": "tax document",
    "invoice": "invoice", "receipt": "receipt", "statement": "financial statement",
    "bank": "bank record", "paystub": "pay record", "payslip": "pay record",
    "payroll": "pay record", "salary": "pay record", "401k": "retirement record",
    "ira": "retirement record", "pension": "retirement record",
    "contract": "legal contract", "agreement": "legal agreement",
    "lease": "lease", "mortgage": "mortgage", "deed": "property deed",
    "will": "legal document", "trust": "legal document",
    "passport": "identity document", "license": "identity document",
    "licence": "identity document", "ssn": "identity document",
    "birth": "identity document", "certificate": "certificate",
    "diploma": "diploma", "transcript": "transcript", "visa": "immigration doc",
    "insurance": "insurance", "policy": "insurance/policy",
    "medical": "medical record", "health": "health record",
    "prescription": "medical record", "resume": "resume", "cv": "resume",
    "password": "credentials", "passwords": "credentials",
    "recovery": "recovery/backup key", "seed": "recovery/backup key",
    "keychain": "credentials", "wallet": "crypto wallet",
    "credentials": "credentials", "backup": "backup",
    "warranty": "warranty", "registration": "registration",
}


# Extensions that are never a "personally important document", even when the
# filename matches an important keyword. e.g. resume.pdf is a resume worth
# keeping, but resume.jsx / resume.py is just source code named after one.
_NEVER_IMPORTANT_EXT = CATEGORIES["Code"] | {
    ".jsx", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".rb", ".php", ".swift",
    ".kt", ".scala", ".cs", ".h", ".hpp", ".m", ".mm", ".scss", ".less", ".sql",
    ".yml", ".yaml", ".toml", ".xml", ".map", ".lock", ".o", ".a", ".class",
    ".pyc", ".pyo", ".obj", ".dll", ".so", ".dylib", ".bin", ".tmp", ".temp",
    ".cache", ".log",
}


def important_reason(name: str) -> str:
    if Path(name).suffix.lower() in _NEVER_IMPORTANT_EXT:
        return ""                        # file type rules it out (see above)
    tokens = set(re.split(r"[^a-z0-9]+", name.lower()))
    for kw, reason in _IMPORTANT_KW.items():
        if kw in tokens:                 # exact token (handles short kws: w2, id)
            return reason
        if len(kw) >= 4 and any(kw in t for t in tokens):   # substring for long
            return reason
    return ""


# Paths/types where deleting could break a program or the OS — flag, don't hide.
_RISK_DIR = (".app/", "/applications/", "/system/", "/library/", "/usr/",
             "/bin/", "/sbin/", "/opt/", "/private/var/", "/frameworks/",
             "application support", "/node_modules/", "/site-packages/",
             "/.git/", "/vendor/", "/__pycache__/", "/.venv/")
_RISK_EXT = {".dylib", ".so", ".framework", ".kext", ".app", ".exe", ".dll",
             ".sys", ".o", ".a", ".lib", ".bundle", ".plist", ".entitlements"}
_CONFIG_EXT = {".plist", ".cfg", ".ini", ".conf", ".config", ".lock", ".db"}


def delete_risk(path: str) -> str:
    """Why removing this file might break something — '' if it's safe to remove."""
    low = path.lower()
    name = Path(path).name
    for d in _RISK_DIR:
        if d in low:
            return "lives inside an app / system / dependency folder"
    ext = Path(path).suffix.lower()
    if ext in _RISK_EXT:
        return "a program or library file an app may load"
    if ext in _CONFIG_EXT or (name.startswith(".") and ext not in
                              (".jpg", ".png", ".pdf", ".txt")):
        return "looks like a config a program may rely on"
    return ""


# Types a person almost never authors by hand and can usually re-create / re-
# download — installers, disk images and partial downloads lean "safe to
# remove" even without download provenance. (Generic archives like .zip are
# left out on purpose: those can be the user's own work, so they fall through
# to the user-created vs downloaded check below.)
_DISPOSABLE_EXT = _JUNK_EXTS | {
    ".dmg", ".pkg", ".iso", ".crdownload", ".download", ".part", ".bak", ".old"}


def suggest_tag(info: dict, source: str = "") -> dict:
    """One combined 'what should I do' suggestion per file.

    Folds together everything we know — is it personally important, could
    removing it break a program, is it empty/broken, what type it is, and
    whether the user made it here vs downloaded it — into a single level
    (keep / review / remove) with a short reason. This is what the UI tags
    each file with and lets you filter by.
    """
    name = info.get("name", "")
    ext = Path(name).suffix.lower()
    size = info.get("size", 0)
    if info.get("important"):
        return _sg("keep", "Keep", info["important"])
    if info.get("risk"):
        return _sg("review", "Review first", info["risk"])
    if size == 0:
        return _sg("remove", "Safe to remove", "empty or broken file (0 bytes)")
    if name.lower() in _JUNK_NAMES or ext in _JUNK_EXTS:
        return _sg("remove", "Safe to remove", "temporary or cache file")
    if ext in _DISPOSABLE_EXT:
        return _sg("remove", "Likely safe to remove",
                   "installer/disk image you can usually get again")
    if source == "user-created":
        return _sg("keep", "Probably keep",
                   "you made this on this computer — not downloaded")
    if source == "downloaded":
        return _sg("remove", "Likely safe to remove",
                   "downloaded — you can usually download it again")
    return _sg("review", "Review first", "no strong signal either way")


def _sg(level: str, label: str, why: str) -> dict:
    return {"level": level, "label": label, "why": why}


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
        info = {"path": str(p), "name": p.name, "size": st.st_size,
                "human": _human(st.st_size),
                "modified": _date(st.st_mtime), "accessed": _date(st.st_atime),
                "atime": st.st_atime,
                "important": important_reason(p.name),
                "risk": delete_risk(str(p))}
        source = provenance.source_label(str(p))
        info["source"] = source
        info["suggest"] = suggest_tag(info, source)
        return info
    except OSError:
        info = {"path": str(p), "name": p.name, "size": 0, "human": "0 B",
                "modified": "", "accessed": "", "atime": 0,
                "important": "", "risk": "", "source": ""}
        info["suggest"] = suggest_tag(info, "")
        return info


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


def analyze(folder: str, progress=lambda s: None,
            classify_important=None) -> dict:
    root = Path(folder).expanduser()
    all_infos: list[dict] = []
    by_size: dict[int, list[Path]] = {}
    now = time.time()
    total_files = total_bytes = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in
                       ("Oyster Archive", "Important", ".oyster")]
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
            all_infos.append(_info(p, st))
            by_size.setdefault(st.st_size, []).append(p)
            if total_files % 500 == 0:
                progress(f"Analyzing · {total_files:,} files")

    # AI pass: let the model flag important-looking files the keywords missed
    # (only the ones at risk of cleanup, and only when a classifier is given).
    if classify_important:
        cand = [i for i in all_infos if not i["important"] and
                (i["size"] >= _LARGE_BYTES or
                 (now - i["atime"]) > _STALE_DAYS * 86400)]
        try:
            flagged = classify_important([i["name"] for i in cand][:120]) or set()
            for i in cand:
                if (i["name"] in flagged and
                        Path(i["name"]).suffix.lower() not in _NEVER_IMPORTANT_EXT):
                    i["important"] = "AI: looks personally important"
        except Exception:
            pass

    important = [i for i in all_infos if i["important"]]
    imp = {i["path"] for i in important}

    by_cat: dict[str, list] = {}
    junk, large, stale = [], [], []
    for i in all_infos:
        if i["path"] in imp:
            continue   # never put important files up for cleanup
        p = Path(i["path"])
        cat = _category(p)
        if cat != "Other":
            by_cat.setdefault(cat, []).append(i)
        if p.name.lower() in _JUNK_NAMES or p.suffix.lower() in _JUNK_EXTS:
            junk.append(i)
        if i["size"] >= _LARGE_BYTES:
            large.append(i)
        if (now - i["atime"]) > _STALE_DAYS * 86400 and i["size"] > 1024:
            stale.append(i)

    recs: list[Rec] = []

    if important:
        recs.append(Rec(
            "important", "Important files — set these aside",
            f"{len(important)} files look personally important (tax, legal, "
            "identity, financial, credentials). They're kept out of every "
            "cleanup suggestion — move them to a dedicated Important folder.",
            "important", bytes=sum(i["size"] for i in important),
            count=len(important), items=important[:_CAP]))

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

    groups = _dup_groups(by_size, progress, imp)
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


def _dup_groups(by_size: dict, progress, imp: set | None = None) -> list:
    imp = imp or set()
    groups = []
    for size, paths in by_size.items():
        paths = [p for p in paths if str(p) not in imp]
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
            dup.sort(key=lambda p: p.stat().st_mtime)  # newest (last) = keep
            groups.append({"size": size, "human": _human(size),
                           "keep": _info(dup[-1]),
                           "copies": [_info(x) for x in dup[:-1]]})
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


def find_matching(folder: str, contains: list[str] | None = None,
                  ext: list[str] | None = None, older_days: int | None = None,
                  larger_mb: int | None = None, cap: int = 1000) -> list[dict]:
    """Resolve a natural-language file query (from the chat) into file infos."""
    root = Path(folder).expanduser()
    contains = [c.lower() for c in (contains or []) if c]
    exts = {e.lower() if e.startswith(".") else "." + e.lower()
            for e in (ext or [])}
    now = time.time()
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in
                       ("Oyster Archive", "Important", ".oyster")]
        for fn in filenames:
            p = Path(dirpath) / fn
            low = fn.lower()
            if contains and not any(c in low for c in contains):
                continue
            if exts and p.suffix.lower() not in exts:
                continue
            try:
                st = p.stat()
            except OSError:
                continue
            if older_days and (now - st.st_atime) < older_days * 86400:
                continue
            if larger_mb and st.st_size < larger_mb * 1024 * 1024:
                continue
            out.append(_info(p, st))
            if len(out) >= cap:
                return out
    return out


_DEST = {"archive": "Oyster Archive", "important": "Important"}


def execute(action: str, paths: list[str], folder: str = "",
            categories: dict | None = None) -> dict:
    """action: 'delete' (-> vault), 'archive'/'important' (-> a named folder),
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

    if action in _DEST:
        dest_dir = Path(folder).expanduser() / _DEST[action]
        dest_dir.mkdir(parents=True, exist_ok=True)
    else:  # delete -> reversible vault
        dest_dir = _vault()

    for f in paths:
        src = Path(f)
        try:
            sz = _tree_size(src)
            dest = _unique(dest_dir / src.name)
            try:
                src.rename(dest)
            except OSError:
                shutil.move(str(src), str(dest))   # across volumes (e.g. /Applications)
            moved += 1
            freed += sz
        except OSError:
            errors += 1
    return {"moved": moved, "errors": errors, "freed": freed,
            "human": _human(freed), "dest": str(dest_dir)}


def _tree_size(p: Path) -> int:
    """Bytes for a file or a whole directory tree (so freed-space is accurate
    when a moved item is a folder, e.g. a .app bundle)."""
    try:
        if p.is_file() or p.is_symlink():
            return p.lstat().st_size
    except OSError:
        return 0
    total = 0
    for dp, _dn, fns in os.walk(p):
        for fn in fns:
            try:
                total += (Path(dp) / fn).lstat().st_size
            except OSError:
                pass
    return total
