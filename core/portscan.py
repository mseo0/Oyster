"""Open-port / listening-socket inspector — the network-exposure module.

Enumerates the listening TCP/UDP sockets on this machine and the process behind
each, then flags the ones that expose the computer to the *network*: a service
bound to all interfaces (0.0.0.0 / ::), a risky legacy/database service reachable
from outside, or a listener whose program runs from a temp/Downloads dir.

Loopback-only listeners (127.0.0.1 / ::1) are normal — local apps talk to
themselves that way — so they're reported as informational, never alarmed on.

Fully local: psutil only. No packets are sent and nothing is contacted; we just
read the OS socket table. Sockets owned by other users (root daemons) may be
invisible without elevated permissions — those are skipped, never fatal, exactly
like unreadable files elsewhere in Oyster.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass, field
from pathlib import Path

from . import signing
from .findings import Finding, FindingKind, Severity
from .processes import _is_in_writable_hotspot

try:
    import psutil
except ImportError:  # keep import-safe so the rest of the app loads
    psutil = None

# Services that are dangerous to expose to the network — remote shells, file
# shares, remote-desktop, and unauthenticated-by-default databases/caches.
_RISKY_PORTS: dict[int, str] = {
    21: "FTP (unencrypted file transfer)",
    23: "Telnet (unencrypted remote shell)",
    25: "SMTP mail relay",
    135: "Windows RPC",
    139: "NetBIOS file sharing",
    445: "SMB/Windows file sharing",
    1433: "Microsoft SQL Server",
    1521: "Oracle database",
    3306: "MySQL database",
    3389: "RDP remote desktop",
    5432: "PostgreSQL database",
    5900: "VNC remote desktop",
    5985: "WinRM remote management",
    6379: "Redis (no auth by default)",
    9200: "Elasticsearch (no auth by default)",
    11211: "Memcached (no auth by default)",
    27017: "MongoDB database",
    2049: "NFS file sharing",
}

# Addresses that mean "only this machine can reach it" — safe by design.
_LOOPBACK = ("127.", "::1", "::ffff:127.")
# Addresses that mean "every network interface" — reachable from the LAN/internet.
_ALL_IFACES = ("0.0.0.0", "::", "*", "")

# OS-owned locations. A signed binary here that listens is the OS doing its job
# (Continuity/AirDrop/printing/etc.), so we don't treat "unsigned-looking" system
# daemons as suspicious — that just produced false positives.
_SYSTEM_PREFIXES = (
    "/System", "/usr/", "/usr/libexec", "/sbin", "/bin", "/Library/Apple",
    "C:\\Windows", "C:\\Program Files",
)


def _is_system_path(exe: str) -> bool:
    return bool(exe) and exe.startswith(_SYSTEM_PREFIXES)


@dataclass
class OpenPort:
    pid: int
    name: str
    exe: str
    proto: str          # "tcp" / "udp"
    address: str        # bound local IP
    port: int
    exposed: bool       # bound to a non-loopback address (network-reachable)
    score: int
    reasons: list[str] = field(default_factory=list)


def _is_loopback(ip: str) -> bool:
    return ip.startswith(_LOOPBACK)


def _is_all_interfaces(ip: str) -> bool:
    return ip in _ALL_IFACES


def inspect(check_signatures: bool = True) -> list[OpenPort]:
    """Listening TCP servers we can attribute to a process, scored by how much
    network exposure each represents. Loopback-only listeners score 0.

    We deliberately scope to TCP LISTEN sockets: that's what "an open port"
    means to a person. Bound UDP sockets are mostly the OS's own discovery
    chatter (mDNS/AirDrop/Continuity) and would bury the real signal in noise.
    """
    if psutil is None:
        return []
    # Collapse the IPv4 + IPv6 rows of one dual-stack server into a single entry.
    seen: set[tuple] = set()
    out: list[OpenPort] = []
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            conns = proc.net_connections(kind="tcp")
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            continue  # not ours / vanished — skip, never fatal
        info = proc.info
        name = info.get("name") or ""
        exe = info.get("exe") or ""
        for c in conns:
            if c.status != "LISTEN" or not c.laddr or not c.laddr.port:
                continue
            ip, port = c.laddr.ip, c.laddr.port
            key = (port, info.get("pid"))
            if key in seen:
                continue
            seen.add(key)

            exposed = not _is_loopback(ip)
            score = 0
            reasons: list[str] = []
            if exposed:
                if _is_all_interfaces(ip):
                    score += 25
                    reasons.append("listening on all network interfaces")
                else:
                    score += 15
                    reasons.append(f"reachable on the network at {ip}")
                svc = _RISKY_PORTS.get(port)
                if svc:
                    score += 45
                    reasons.append(f"exposes {svc}")
                if exe and _is_in_writable_hotspot(exe):
                    score += 40
                    reasons.append("program runs from a temp/Downloads folder")
                # Only an *unexpected* unsigned listener is interesting; a signed
                # OS daemon in a system path is normal, so don't penalise it.
                if (check_signatures and exe and score >= 25
                        and not _is_system_path(exe)):
                    si = signing.verify(Path(exe))
                    if si.checked and not si.valid:
                        score += 20
                        reasons.append("program is unsigned / signature invalid")

            out.append(OpenPort(
                pid=info.get("pid", -1), name=name, exe=exe, proto="tcp",
                address=ip, port=port, exposed=exposed,
                score=min(score, 100), reasons=reasons,
            ))
    out.sort(key=lambda p: (-p.score, p.port))
    return out


def _severity(p: OpenPort) -> Severity:
    if p.score >= 60:
        return Severity.HIGH
    if p.score >= 40:
        return Severity.MEDIUM
    if p.score > 0:
        return Severity.LOW
    return Severity.INFO


def audit() -> list[Finding]:
    """Listening sockets as VULNERABILITY findings, so open ports show up in the
    Vulnerabilities tab (and the full scan) next to CVEs and OS posture.

    Only network-exposed listeners are surfaced; loopback-only services are
    normal and would just be noise."""
    findings: list[Finding] = []
    for p in inspect():
        if not p.exposed:
            continue
        sev = _severity(p)
        who = p.name or "A program"
        where = ("all network interfaces" if _is_all_interfaces(p.address)
                 else p.address)
        detail = (
            f"{who} is accepting {p.proto.upper()} connections from the network "
            f"on port {p.port} ({where}). " + "; ".join(p.reasons) + ". "
            + ("If you don't recognise this service, it may be exposing your "
               "computer unnecessarily — close it or limit it to this machine "
               "(127.0.0.1)." if sev != Severity.INFO else
               "This is common and usually fine.")
        )
        findings.append(Finding(
            FindingKind.VULNERABILITY, sev,
            f"port:{p.proto}:{p.port}:{p.pid}",
            f"open-port:{p.port}",
            detail,
            {"process": p.name, "pid": p.pid, "exe": p.exe,
             "protocol": p.proto, "address": p.address, "port": p.port,
             "score": p.score},
        ))
    return findings
