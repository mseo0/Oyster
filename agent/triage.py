"""AI triage + the end-of-scan summary report.

The LLM receives ONLY structured findings/actions (metadata, never file bytes),
runs once, and returns prose. If Ollama is unavailable, deterministic fallbacks
produce a perfectly usable report with no AI at all.
"""
from __future__ import annotations

from core.findings import Finding

from .ollama_client import Ollama

TRIAGE_SYSTEM = (
    "You are the triage analyst inside a local, offline antivirus. You receive "
    "structured scan findings (no file contents). For each finding give a one-"
    "line plain-English explanation and a recommended action chosen from: "
    "IGNORE, QUARANTINE, SUSPEND_PROCESS, ASK_USER. Never invent findings. "
    "Anything touching a user document or system path must be ASK_USER."
)

SUMMARY_SYSTEM = (
    "You are writing the end-of-scan report for a non-technical user of a local "
    "offline antivirus. Summarize, in plain language: what was scanned, what "
    "threats were found, what actions were taken, and what was prevented. Be "
    "concrete and reassuring but honest. Only use the facts provided."
)


def triage_findings(findings: list[Finding], model: str) -> str:
    if not findings:
        return "No findings to triage — system looks clean."
    listing = "\n".join(
        f"- [{f.severity.value}] {f.kind.value} @ {f.target} :: {f.rule} "
        f"({f.detail})"
        for f in findings
    )
    client = Ollama(model)
    if not client.available():
        return _fallback_triage(findings)
    try:
        return client.generate(
            prompt=f"Findings:\n{listing}\n\nTriage each finding.",
            system=TRIAGE_SYSTEM,
        )
    except Exception:
        # Ollama is up but the request failed (e.g. model not pulled -> 404).
        # Degrade to the deterministic report rather than crashing the scan.
        return _fallback_triage(findings)


def summarize_session(summary_data: dict, model: str) -> str:
    """The 'what changed / what was prevented' report you asked for."""
    findings = summary_data.get("findings", [])
    actions = summary_data.get("actions", [])
    client = Ollama(model)
    if not client.available() or (not findings and not actions):
        return _fallback_summary(findings, actions)

    f_lines = "\n".join(
        f"- [{x['severity']}] {x['kind']} @ {x['target']}: {x['rule']}"
        for x in findings
    ) or "  (none)"
    a_lines = "\n".join(
        f"- {x['action']} {x['target']} "
        f"({'approved' if x['approved'] else 'declined'}, "
        f"{'reversible' if x['reversible'] else 'permanent'})"
        for x in actions
    ) or "  (none)"
    prompt = (
        f"THREATS FOUND:\n{f_lines}\n\n"
        f"ACTIONS TAKEN:\n{a_lines}\n\n"
        "Write the user-facing scan report."
    )
    try:
        return client.generate(prompt=prompt, system=SUMMARY_SYSTEM)
    except Exception:
        return _fallback_summary(findings, actions)


# --- deterministic fallbacks (no AI required) ------------------------------
def _fallback_triage(findings: list[Finding]) -> str:
    out = ["Triage (offline heuristic — Ollama not running):"]
    for f in findings:
        rec = ("ASK_USER" if f.kind.value.startswith("file") else
               "SUSPEND_PROCESS")
        out.append(f"  • [{f.severity.value}] {f.target} -> suggest {rec}")
    return "\n".join(out)


def _fallback_summary(findings: list[dict], actions: list[dict]) -> str:
    crit = sum(1 for f in findings if f.get("severity") in ("high", "critical"))
    quarantined = sum(1 for a in actions
                      if a.get("action") == "quarantine" and a.get("approved"))
    killed = sum(1 for a in actions
                 if a.get("action") in ("terminate", "suspend")
                 and a.get("approved"))
    return (
        "Scan report (offline summary)\n"
        f"  Threats found: {len(findings)} ({crit} high/critical)\n"
        f"  Files quarantined: {quarantined} (all reversible)\n"
        f"  Processes stopped: {killed}\n"
        "  Nothing left your machine — this scan ran fully offline."
    )
