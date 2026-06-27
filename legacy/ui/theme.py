"""Visual theme for the Oyster desktop UI (CustomTkinter).

Implements the Oyster.dc design (a frosted-glass macOS look). Tkinter can't do
backdrop-blur, translucency or gradient desktops, so the glass colours are
flattened to solid (light, dark) tuples that approximate how each panel reads
over the design's desktop. Type is Hanken Grotesk + JetBrains Mono; the accent
is a teal that brightens in dark mode. Default appearance is dark, per the
design's defaultDark.
"""
from __future__ import annotations

from tkinter import font as tkfont

import customtkinter as ctk

# --- surfaces (light, dark) — flattened from the design's glass layers --------
DESK = ("#E6E2D7", "#0B0C0D")        # app background ("desktop")
WIN = ("#F1EEE6", "#16191B")         # window body
SIDEBAR = ("#F4F2EB", "#191D20")     # left rail
CARD = ("#FBFAF6", "#23282C")        # panels / cards
INSET = ("#F0EDE6", "#1E2327")       # panel2 / inputs / inner wells
ROW_HOVER = ("#FFFFFF", "#272C30")
ROW_SEL = ("#D9E9EB", "#15333B")     # selected list row
BORDER = ("#E1DED4", "#2C3236")
BORDER_SOFT = ("#EAE7DE", "#23282C")

TEXT = ("#1B1E1D", "#ECEBE4")
MUTED = ("#5F655F", "#939891")
MUTED2 = ("#8E938A", "#71766F")

# --- accent ------------------------------------------------------------------
ACCENT = ("#0E7C8C", "#2BC2D6")
ACCENT_BTN = ("#0E7C8C", "#16808F")
ACCENT_H = ("#129DB0", "#46D4E6")
ACCENT_SOFT = ("#DCEAEC", "#16323A")   # accent-soft fill (AI triage box, chips)
ON_ACCENT = "#FFFFFF"

# semantic action colours (same in both modes, from the design)
DANGER = "#E5484D"
DANGER_H = "#C73B3F"
SUCCESS = "#17A98C"
SUCCESS_H = "#149A80"

# severity -> accent colour for a result row / chip
SEVERITY = {
    "critical": "#E5484D",
    "high": "#F5820A",
    "medium": "#E5B003",
    "low": "#17A98C",
    "info": "#8E938A",
}

# traffic-light dots for the faux title bar accent (decorative)
TRAFFIC = ("#FF5F57", "#FEBC2E", "#28C840")


def severity_color(sev: str) -> str:
    return SEVERITY.get(str(sev).lower(), "#8E938A")


def proc_color(score: int) -> str:
    if score >= 70:
        return SEVERITY["critical"]
    if score >= 40:
        return SEVERITY["high"]
    if score >= 20:
        return SEVERITY["medium"]
    return SEVERITY["info"]


def chip_bg(hex_color: str) -> tuple[str, str]:
    """A faint tinted chip background derived from a severity colour."""
    # the design uses color+'24' (~14% alpha); we precompute a light & dark mix.
    return (_mix(hex_color, "#FBFAF6", 0.16), _mix(hex_color, "#23282C", 0.22))


def _mix(fg: str, bg: str, a: float) -> str:
    fr, fg_, fb = (int(fg[i:i + 2], 16) for i in (1, 3, 5))
    br, bg_, bb = (int(bg[i:i + 2], 16) for i in (1, 3, 5))
    r = round(fr * a + br * (1 - a))
    g = round(fg_ * a + bg_ * (1 - a))
    b = round(fb * a + bb * (1 - a))
    return f"#{r:02x}{g:02x}{b:02x}"


def setup_appearance():
    ctk.set_appearance_mode("dark")   # design default
    ctk.set_default_color_theme("blue")


def _family(root, candidates, fallback):
    available = {f.lower() for f in tkfont.families(root)}
    for name in candidates:
        if name.lower() in available:
            return name
    return fallback


def make_fonts(root) -> dict:
    sans = _family(root, ["Hanken Grotesk", "SF Pro Text", "Helvetica Neue",
                          "Segoe UI", "Inter"], "Roboto")
    mono = _family(root, ["JetBrains Mono", "JetBrains Mono NL", "SF Mono",
                          "Menlo", "Consolas"], "Roboto Mono")
    return {
        "h1": ctk.CTkFont(family=sans, size=26, weight="bold"),
        "brand": ctk.CTkFont(family=sans, size=18, weight="bold"),
        "section": ctk.CTkFont(family=sans, size=11, weight="bold"),
        "nav": ctk.CTkFont(family=sans, size=14, weight="bold"),
        "body": ctk.CTkFont(family=sans, size=13),
        "body_bold": ctk.CTkFont(family=sans, size=13, weight="bold"),
        "small": ctk.CTkFont(family=sans, size=11),
        "stat": ctk.CTkFont(family=sans, size=16, weight="bold"),
        "orb": ctk.CTkFont(family=sans, size=20, weight="bold"),
        "mono": ctk.CTkFont(family=mono, size=12),
        "mono_bold": ctk.CTkFont(family=mono, size=13, weight="bold"),
        "mono_sm": ctk.CTkFont(family=mono, size=11),
        "badge": ctk.CTkFont(family=mono, size=10, weight="bold"),
    }
