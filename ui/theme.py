"""Visual theme for the Oyster desktop UI (CustomTkinter).

A modern, minimal "security dashboard" look: a left sidebar, rounded cards, soft
surfaces, and a blue primary with a teal "all-clear / offline" accent and a red
destructive colour. Design tokens were sourced from the ui-ux-pro design
intelligence MCP and adapted to a desktop app.

Every colour is a (light, dark) tuple so CustomTkinter renders the right one for
the current appearance mode — the sidebar toggle flips between them live.
"""
from __future__ import annotations

from tkinter import font as tkfont

import customtkinter as ctk

# --- surfaces (light, dark) --------------------------------------------------
BG = ("#EEF0F4", "#15161E")        # window background
SIDEBAR = ("#FFFFFF", "#1B1C26")   # left nav rail
CARD = ("#FFFFFF", "#23242F")      # raised content cards
INSET = ("#F4F5F8", "#1E1F29")     # list / report insets
ROW = ("#FFFFFF", "#23242F")       # result row (rest)
ROW_HOVER = ("#F0F3F8", "#2A2C3A")
ROW_SEL = ("#E4EFFE", "#2C3A57")   # selected result row
BORDER = ("#E3E6EC", "#2E3040")

TEXT = ("#1A1B2E", "#ECEDF3")
MUTED = ("#6B7280", "#9AA0B5")

# --- accents -----------------------------------------------------------------
PRIMARY = "#2B8CFA"
PRIMARY_H = "#1E6FD0"
TEAL = "#06C99A"
TEAL_H = "#05A883"
DANGER = "#E5484D"
DANGER_H = "#C73B3F"
ON_ACCENT = "#FFFFFF"

# severity -> accent colour for a result row
SEVERITY = {
    "critical": "#E5484D",
    "high": "#F5820A",
    "medium": "#E5B003",
    "low": "#06C99A",
    "info": "#9AA0B5",
}


def severity_color(sev: str) -> str:
    return SEVERITY.get(str(sev).lower(), "#9AA0B5")


def proc_color(score: int) -> str:
    if score >= 70:
        return SEVERITY["critical"]
    if score >= 40:
        return SEVERITY["high"]
    if score >= 20:
        return SEVERITY["medium"]
    return SEVERITY["info"]


def setup_appearance():
    ctk.set_appearance_mode("light")
    ctk.set_default_color_theme("blue")


def _family(root, candidates, fallback):
    available = {f.lower() for f in tkfont.families(root)}
    for name in candidates:
        if name.lower() in available:
            return name
    return fallback


def make_fonts(root) -> dict:
    """Build the app's CTkFont set once the root window exists."""
    sans = _family(root, ["Fira Sans", "SF Pro Text", "Helvetica Neue",
                          "Segoe UI", "Inter"], "Roboto")
    mono = _family(root, ["Fira Code", "JetBrains Mono", "SF Mono", "Menlo",
                          "Consolas"], "Roboto Mono")
    return {
        "brand": ctk.CTkFont(family=sans, size=20, weight="bold"),
        "title": ctk.CTkFont(family=sans, size=22, weight="bold"),
        "nav": ctk.CTkFont(family=sans, size=14, weight="bold"),
        "body": ctk.CTkFont(family=sans, size=13),
        "body_bold": ctk.CTkFont(family=sans, size=13, weight="bold"),
        "small": ctk.CTkFont(family=sans, size=11),
        "chip": ctk.CTkFont(family=mono, size=11),
        "mono": ctk.CTkFont(family=mono, size=12),
    }
