"""Definitions updater CLI — the lone sanctioned online step.

    python -m updater.update --clamav          # refresh ClamAV signatures
    python -m updater.update --osv PyPI npm     # download OSV CVE snapshot(s)
    python -m updater.update --all              # everything

Every network host contacted is printed before the request. Nothing here is
imported by the scanner core, so this is the only place egress can occur.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlparse

from core import config
from core.osvdb import OsvDB

# OSV publishes per-ecosystem zipped exports here.
OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com"


def _announce(url: str) -> None:
    host = urlparse(url).hostname
    print(f"  [network] contacting {host}  ({url})")


def update_clamav() -> None:
    fresh = shutil.which("freshclam")
    if not fresh:
        print("  freshclam not found — install ClamAV first.")
        return
    print("  [network] freshclam will contact the ClamAV CDN (database.clamav.net)")
    try:
        subprocess.run([fresh], timeout=600)
    except Exception as e:
        print(f"  freshclam failed: {e}")


def update_osv(ecosystems: list[str], cfg: config.ScanConfig) -> None:
    cfg.definitions_dir.mkdir(parents=True, exist_ok=True)
    extract_root = cfg.definitions_dir / "osv"
    if extract_root.exists():
        shutil.rmtree(extract_root)
    extract_root.mkdir(parents=True)

    for eco in ecosystems:
        url = f"{OSV_BASE}/{eco}/all.zip"
        _announce(url)
        try:
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                with urllib.request.urlopen(url, timeout=300) as r:
                    shutil.copyfileobj(r, tmp)
                tmp_path = Path(tmp.name)
            dest = extract_root / eco
            dest.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(tmp_path) as z:
                z.extractall(dest)
            tmp_path.unlink(missing_ok=True)
            print(f"    extracted {eco} advisories")
        except Exception as e:
            print(f"    failed {eco}: {e}")

    print("  building local OSV database (offline from here on)...")
    db = OsvDB(cfg.osv_db_path)
    n = db.build_from_dir(extract_root)
    print(f"  OSV database ready: {n} advisory ranges, {db.count} rows -> "
          f"{cfg.osv_db_path}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Oyster definitions updater (online)")
    ap.add_argument("--clamav", action="store_true")
    ap.add_argument("--osv", nargs="*", metavar="ECOSYSTEM",
                    help="ecosystems to fetch (default: PyPI npm)")
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args(argv)

    cfg = config.ScanConfig()
    print("== Oyster definitions updater ==")
    print("This is the ONLY component that accesses the internet.\n")

    did = False
    if args.clamav or args.all:
        print("Updating ClamAV signatures:")
        update_clamav()
        did = True
    if args.osv is not None or args.all:
        ecos = args.osv if args.osv else ["PyPI", "npm"]
        print(f"\nUpdating OSV snapshot for: {', '.join(ecos)}")
        update_osv(ecos, cfg)
        did = True

    if not did:
        ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
