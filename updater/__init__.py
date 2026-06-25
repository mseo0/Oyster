"""Definitions updater — the ONLY component permitted to touch the internet.

It is isolated from the scanner on purpose: the scanner core imports no network
libraries, and all sanctioned egress happens here, only when the user explicitly
runs it, and it prints exactly which hosts it contacts. Updates ClamAV
signatures, the OSV CVE snapshot, and (optionally) a known-bad hash list.
"""
