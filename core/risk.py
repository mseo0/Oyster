"""Turn raw engine hits into reliably-ranked risks (fewer false alarms).

A scanner that reports every ClamAV hit as "malware" cries wolf: generic
`Heuristics.*`, `PUA.*` and `Broken.*` signatures fire constantly on perfectly
legitimate program files — packed installers, custom-built binaries, developer
tools, game anti-cheat, etc. Flagging those as threats is exactly what makes a
user distrust the scan and what buries the one detection that matters.

This module decides *how much to trust* a hit instead of treating them all the
same. It scores each one by:

  1. the signature **class** — a named malware family (`Win.Trojan.Foo`) is
     trustworthy; a generic `Heuristics.*` / `PUA.*` / `Broken.*` hit is not, on
     its own; the EICAR test file is a deliberate test, not a real threat; and
  2. corroborating **local context** — is the file validly code-signed by a
     trusted authority (Apple / Microsoft / a Developer ID), and did it arrive
     as a download vs. being built/created on the machine?

A heuristic hit on a validly-signed system or application binary is downgraded
to an informational "potential" — or suppressed entirely — rather than reported
as malware, because that combination is overwhelmingly a false positive on a
file some program needs to run. A named-family hit, or any hit on an unsigned
*downloaded* executable, keeps its high severity. Net effect: the real risks
stand out and the everyday program files stop getting flagged.

Signing/provenance are checked only on the handful of files that actually hit a
signature, never on every walked file, so the cost stays trivial.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from . import provenance, signing
from .findings import FindingKind, Severity


class SigClass(str, Enum):
    NAMED = "named"          # a specific malware family — high confidence
    TEST = "test"            # EICAR / test signatures — a successful self-test
    HEURISTIC = "heuristic"  # generic/heuristic/PUA/broken — high false-positive rate


# Signature-name fragments that mark a *generic* detection rather than a named
# malware family. ClamAV encodes the detection class in the signature name, e.g.
# "Heuristics.Encrypted.Zip", "PUA.Win.Packer.Upx", "Broken.Executable". These
# fire on legitimate files often enough that we never treat them, alone, as
# confirmed malware.
_HEURISTIC_FRAGMENTS = (
    "heuristics.", "pua.", "broken.", "packer.", "encrypted.",
    "sanesecurity.", "porcupine.", "phishing.heuristics",
    # Matches from our own bundled YARA rules (reported as "YARA.<rule>") are
    # broad pattern heuristics, NOT curated malware-family signatures — they fire
    # on legitimate files (e.g. compiled .dll/.dylib) and must be corroborated
    # with code-signing before they're worth alarming the user.
    "yara.",
)

# Authorities we consider trusted enough that a *generic* hit on a file they
# signed is almost certainly a false positive (the OS / a real vendor shipped it).
_TRUSTED_AUTHORITIES = (
    "apple", "developer id", "software signing", "apple mac os",
    "microsoft", "microsoft windows", "microsoft corporation",
)


def classify(signature: str) -> SigClass:
    """Bucket a raw engine signature name by how much it can be trusted."""
    s = (signature or "").lower()
    if "eicar" in s or "test-signature" in s or "test.file" in s:
        return SigClass.TEST
    if any(frag in s for frag in _HEURISTIC_FRAGMENTS):
        return SigClass.HEURISTIC
    return SigClass.NAMED


def _trusted_signer(info: signing.SignInfo) -> bool:
    if not (info.checked and info.signed and info.valid):
        return False
    auth = (info.authority or "").lower()
    return any(a in auth for a in _TRUSTED_AUTHORITIES)


@dataclass
class Assessment:
    severity: Severity
    kind: FindingKind
    confidence: str            # "high" | "medium" | "low"
    reason: str                # plain-English why this severity
    suppress: bool = False     # true => almost certainly a false positive; don't surface


def assess(path: str, signature: str) -> Assessment:
    """Score one engine hit into a ranked, trustworthy potential risk.

    Combines the signature class with local code-signing + provenance so that
    legitimate, vendor-signed program files stop being reported as malware while
    genuine threats keep their high severity.
    """
    klass = classify(signature)

    # The EICAR/test signature is a deliberate detection self-test, not a threat.
    if klass == SigClass.TEST:
        return Assessment(
            Severity.MEDIUM, FindingKind.FILE_SUSPICIOUS, "high",
            "antivirus test file (EICAR) — confirms detection works; not a real threat",
        )

    # A specific, named malware family is a high-confidence signal regardless of
    # signing — real threats can be signed with stolen/abused certs.
    if klass == SigClass.NAMED:
        downloaded = provenance.source_label(path) == "downloaded"
        sev = Severity.CRITICAL if downloaded else Severity.HIGH
        where = "downloaded file" if downloaded else "local file"
        return Assessment(
            sev, FindingKind.FILE_MALWARE, "high",
            f"named malware signature on a {where}",
        )

    # Generic / heuristic hit: this is where false positives live. Corroborate
    # with code-signing + provenance before deciding it's worth the user's alarm.
    info = signing.verify_safe(path)
    downloaded = provenance.source_label(path) == "downloaded"

    if _trusted_signer(info):
        # Validly signed by Apple/Microsoft/a Developer ID + only a heuristic
        # hit => overwhelmingly a false positive on a file a program needs.
        return Assessment(
            Severity.INFO, FindingKind.FILE_SUSPICIOUS, "low",
            f"generic heuristic match on a file validly signed by "
            f"“{info.authority}” — treated as a likely false positive",
            suppress=True,
        )

    if info.checked and info.signed and info.valid:
        # Signed, but not by a top-tier authority. Low — note it, don't alarm.
        return Assessment(
            Severity.LOW, FindingKind.FILE_SUSPICIOUS, "low",
            "generic heuristic match on a signed file — low confidence",
        )

    if downloaded:
        # Unsigned + arrived as a download + heuristic hit: genuinely worth a
        # look, but still not "confirmed malware".
        return Assessment(
            Severity.MEDIUM, FindingKind.FILE_SUSPICIOUS, "medium",
            "generic heuristic match on an unsigned, downloaded file",
        )

    # Unsigned but locally built/created: common for dev work — keep it low.
    return Assessment(
        Severity.LOW, FindingKind.FILE_SUSPICIOUS, "low",
        "generic heuristic match on an unsigned local file — low confidence",
    )
