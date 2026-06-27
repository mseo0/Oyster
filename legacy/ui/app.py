"""Oyster — desktop UI (CustomTkinter), implementing the Oyster.dc design.

A frosted-glass macOS look adapted to Tkinter's capabilities: a left rail with
SCAN / REPORT sections and live count badges, a per-page task bar, a "pearl"
summary strip, a results list beside a rich Inspector, and an AI Summary page.
Glass blur/gradients aren't possible in Tk, so surfaces are solid colours that
approximate the design (see ui/theme.py). Still pure Python, still no sockets of
its own. Look lives in ui/theme.py; icons in ui/iconset.py.
"""
from __future__ import annotations

import subprocess
import sys
import threading
import time
from pathlib import Path
from tkinter import END, filedialog, messagebox

import customtkinter as ctk

from agent import triage
from core import config, preflight, processes, vulnaudit
from core.findings import FindingKind, Store
from core.quarantine import Quarantine
from core.scanner import Scanner

from . import iconset, theme

PAGES = ("Files", "Processes", "Vulnerabilities", "AI Summary")
SUBTITLES = {
    "Files": "On-demand file scan with reversible quarantine.",
    "Processes": "Running programs, scored by suspicious behaviour.",
    "Vulnerabilities": "Installed software & OS settings vs. offline CVE data.",
    "AI Summary": "A plain-English read-out, written locally just now.",
}
FILE_KINDS = (FindingKind.FILE_MALWARE, FindingKind.FILE_SUSPICIOUS)


def _open_permission_settings(key: str) -> None:
    if key == "fda" and sys.platform == "darwin":
        subprocess.run(
            ["open", "x-apple.systempreferences:com.apple.preference.security"
                     "?Privacy_AllFiles"], check=False)


def _sev_label(sev: str) -> str:
    return {"critical": "CRIT", "high": "HIGH", "medium": "MED",
            "low": "LOW", "info": "INFO"}.get(str(sev).lower(),
                                              str(sev).upper()[:4])


# ===========================================================================
# Preflight gate
# ===========================================================================
class PreflightGate(ctk.CTkFrame):
    def __init__(self, root: ctk.CTk, on_launch):
        super().__init__(root, fg_color=theme.DESK)
        self.root = root
        self.on_launch = on_launch
        self.fonts = theme.make_fonts(root)
        self.cfg = config.ScanConfig()
        self.model = config.recommended_model()
        root.title("Oyster — Setup")
        root.geometry("720x640")

        card = ctk.CTkFrame(self, fg_color=theme.CARD, corner_radius=18,
                            width=600)
        card.place(relx=0.5, rely=0.5, anchor="center")

        head = ctk.CTkFrame(card, fg_color="transparent")
        head.pack(fill="x", padx=30, pady=(28, 6))
        self.brand_icon = iconset.icon("oyster-mark", theme.ACCENT[0],
                                       theme.ACCENT[1], size=30)
        ctk.CTkLabel(head, text="", image=self.brand_icon).pack(side="left")
        box = ctk.CTkFrame(head, fg_color="transparent")
        box.pack(side="left", padx=12)
        ctk.CTkLabel(box, text="Welcome to Oyster", font=self.fonts["h1"],
                     text_color=theme.TEXT).pack(anchor="w")
        ctk.CTkLabel(box, text="Grant the required permissions before scanning.",
                     font=self.fonts["body"], text_color=theme.MUTED).pack(
                         anchor="w")

        self.rows = ctk.CTkFrame(card, fg_color="transparent")
        self.rows.pack(fill="x", padx=30, pady=10)

        footer = ctk.CTkFrame(card, fg_color="transparent")
        footer.pack(fill="x", padx=30, pady=(8, 26))
        self.summary = ctk.CTkLabel(footer, text="", font=self.fonts["small"],
                                    text_color=theme.MUTED)
        self.summary.pack(side="left")
        self.launch_btn = ctk.CTkButton(
            footer, text="Launch Oyster", command=self._launch, height=40,
            corner_radius=10, font=self.fonts["body_bold"],
            fg_color=theme.ACCENT_BTN, hover_color=theme.ACCENT_H,
            text_color=theme.ON_ACCENT)
        self.launch_btn.pack(side="right")
        ctk.CTkButton(
            footer, text="Re-check", command=self.refresh, height=40,
            corner_radius=10, font=self.fonts["body_bold"],
            fg_color=theme.INSET, hover_color=theme.ROW_HOVER,
            text_color=theme.TEXT).pack(side="right", padx=10)
        self.refresh()

    def refresh(self):
        for w in self.rows.winfo_children():
            w.destroy()
        checks = preflight.run_all(self.cfg.db_path.parent, self.model)
        for c in checks:
            self._row(c)
        blocked = preflight.blocking(checks)
        if blocked:
            self.launch_btn.configure(state="disabled")
            self.summary.configure(
                text="Required, still missing: "
                     + ", ".join(b.name for b in blocked),
                text_color=theme.DANGER)
        else:
            self.launch_btn.configure(state="normal")
            self.summary.configure(text="All required permissions granted.",
                                   text_color=theme.SUCCESS)

    def _row(self, c: preflight.Check):
        if c.ok:
            color, label = theme.SUCCESS, "OK"
        elif c.required:
            color, label = theme.DANGER, "REQUIRED"
        else:
            color, label = theme.SEVERITY["high"], "recommended"
        row = ctk.CTkFrame(self.rows, fg_color=theme.INSET, corner_radius=12)
        row.pack(fill="x", pady=5)
        dot = ctk.CTkFrame(row, width=11, height=11, corner_radius=6,
                           fg_color=color)
        dot.pack(side="left", padx=(16, 12), pady=16)
        dot.pack_propagate(False)
        text = ctk.CTkFrame(row, fg_color="transparent")
        text.pack(side="left", fill="x", expand=True, pady=10)
        line = ctk.CTkFrame(text, fg_color="transparent")
        line.pack(fill="x")
        ctk.CTkLabel(line, text=c.name, font=self.fonts["body_bold"],
                     text_color=theme.TEXT).pack(side="left")
        ctk.CTkLabel(line, text=f"  ·  {label}", font=self.fonts["small"],
                     text_color=color).pack(side="left")
        ctk.CTkLabel(text, text=c.detail, font=self.fonts["small"],
                     text_color=theme.MUTED, anchor="w", wraplength=380,
                     justify="left").pack(anchor="w")
        if not c.ok and c.fix:
            ctk.CTkLabel(text, text=c.fix, font=self.fonts["small"],
                         text_color=theme.ACCENT, anchor="w", wraplength=380,
                         justify="left").pack(anchor="w", pady=(2, 0))
        if not c.ok and c.key == "fda":
            ctk.CTkButton(
                row, text="Open Settings",
                command=lambda: _open_permission_settings("fda"),
                width=120, height=34, corner_radius=9, font=self.fonts["small"],
                fg_color=theme.ACCENT_BTN, hover_color=theme.ACCENT_H,
                text_color=theme.ON_ACCENT).pack(side="right", padx=16)

    def _launch(self):
        self.on_launch()


# ===========================================================================
# Main application
# ===========================================================================
class App:
    def __init__(self, root: ctk.CTk):
        self.root = root
        root.title("Oyster — Local Antivirus")
        root.geometry("1240x820")
        root.minsize(1040, 680)
        self.fonts = theme.make_fonts(root)
        root.configure(fg_color=theme.DESK)

        self.cfg = config.ScanConfig()
        self.model = config.recommended_model()
        self.store = Store(self.cfg.db_path)
        self.quar = Quarantine(self.cfg.quarantine_dir)

        # data
        self.findings: list = []          # file findings
        self.proc_threats: list = []
        self.vuln_findings: list = []
        self.sel = {"Files": None, "Processes": None, "Vulnerabilities": None}
        self.last_report = None
        self.scan_secs = 0.0
        self.target = ctk.StringVar(value=str(Path.home() / "Downloads"))
        self.page = "Files"
        self.summary_text = ""

        root.grid_columnconfigure(1, weight=1)
        root.grid_rowconfigure(0, weight=1)
        self._build_sidebar()

        self.main = ctk.CTkFrame(root, fg_color="transparent")
        self.main.grid(row=0, column=1, sticky="nsew", padx=(0, 22), pady=18)
        self.main.grid_columnconfigure(0, weight=1)
        self.main.grid_rowconfigure(1, weight=1)
        self._build_header()
        self.content = ctk.CTkFrame(self.main, fg_color="transparent")
        self.content.grid(row=1, column=0, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        self.status = ctk.CTkLabel(self.main, text="Ready.", anchor="w",
                                   font=self.fonts["small"],
                                   text_color=theme.MUTED)
        self.status.grid(row=2, column=0, sticky="ew", pady=(10, 0))

        self.show_page("Files")

    # --- sidebar ----------------------------------------------------------
    def _build_sidebar(self):
        bar = ctk.CTkFrame(self.root, width=246, corner_radius=0,
                           fg_color=theme.SIDEBAR)
        bar.grid(row=0, column=0, sticky="nsew")
        bar.grid_propagate(False)

        brand = ctk.CTkFrame(bar, fg_color="transparent")
        brand.pack(fill="x", padx=22, pady=(22, 14))
        self.brand_icon = iconset.icon("oyster-mark", theme.TEXT[0],
                                       theme.TEXT[1], size=26)
        ctk.CTkLabel(brand, text="", image=self.brand_icon).pack(side="left")
        ctk.CTkLabel(brand, text="Oyster", font=self.fonts["brand"],
                     text_color=theme.TEXT).pack(side="left", padx=10)

        self.nav_rows = {}
        self._section(bar, "SCAN")
        for key, glyph in (("Files", "folder"), ("Processes", "cpu"),
                           ("Vulnerabilities", "shield-alert")):
            self._nav_row(bar, key, glyph, badge=True)
        self._section(bar, "REPORT")
        self._nav_row(bar, "AI Summary", "shield-check", badge=False)

        ctk.CTkFrame(bar, fg_color="transparent").pack(fill="both", expand=True)

        seg = ctk.CTkSegmentedButton(
            bar, values=["Light", "Dark"], command=self._set_mode,
            font=self.fonts["small"], corner_radius=10,
            selected_color=theme.ACCENT_BTN, selected_hover_color=theme.ACCENT_H,
            unselected_color=theme.INSET, unselected_hover_color=theme.ROW_HOVER,
            text_color=theme.TEXT, fg_color=theme.INSET)
        seg.set("Dark")
        seg.pack(fill="x", padx=16, pady=16)

    def _section(self, parent, text):
        ctk.CTkLabel(parent, text=text, font=self.fonts["section"],
                     text_color=theme.MUTED2, anchor="w").pack(
                         fill="x", padx=26, pady=(14, 6))

    def _nav_row(self, parent, key, glyph, badge):
        row = ctk.CTkFrame(parent, fg_color="transparent", corner_radius=10,
                           height=40)
        row.pack(fill="x", padx=12, pady=2)
        row.pack_propagate(False)
        idle = iconset.icon(glyph, theme.MUTED[0], theme.MUTED[1], size=18)
        active = iconset.icon(glyph, theme.ACCENT[0], theme.ACCENT[1], size=18)
        ic = ctk.CTkLabel(row, text="", image=idle, width=22)
        ic.pack(side="left", padx=(12, 10))
        lbl = ctk.CTkLabel(row, text=key, font=self.fonts["nav"],
                           text_color=theme.MUTED, anchor="w")
        lbl.pack(side="left")
        badge_lbl = None
        if badge:
            badge_lbl = ctk.CTkLabel(row, text="", font=self.fonts["badge"],
                                     corner_radius=7, width=24, height=18)
            badge_lbl.pack(side="right", padx=14)
        self.nav_rows[key] = (row, ic, lbl, idle, active, badge_lbl)
        for w in (row, ic, lbl):
            w.bind("<Button-1>", lambda e, k=key: self.show_page(k))
            w.bind("<Enter>", lambda e, k=key: self._nav_hover(k, True))
            w.bind("<Leave>", lambda e, k=key: self._nav_hover(k, False))

    def _nav_hover(self, key, on):
        row = self.nav_rows[key][0]
        if key != self.page:
            row.configure(fg_color=theme.ROW_HOVER if on else "transparent")

    def _update_nav(self):
        counts = {"Files": len([f for f in self.findings]),
                  "Processes": len(self.proc_threats),
                  "Vulnerabilities": len(self.vuln_findings)}
        for key, (row, ic, lbl, idle, active, badge) in self.nav_rows.items():
            sel = key == self.page
            row.configure(fg_color=theme.ACCENT_SOFT if sel else "transparent")
            ic.configure(image=active if sel else idle)
            lbl.configure(text_color=theme.ACCENT if sel else theme.MUTED)
            if badge is not None:
                n = counts.get(key, 0)
                if n:
                    col = theme.SEVERITY["critical"] if key != "Processes" \
                        else theme.SEVERITY["high"]
                    badge.configure(text=str(n), text_color=col,
                                    fg_color=theme.chip_bg(col))
                else:
                    badge.configure(text="", fg_color="transparent")

    def _set_mode(self, value):
        ctk.set_appearance_mode("dark" if value == "Dark" else "light")

    # --- header -----------------------------------------------------------
    def _build_header(self):
        head = ctk.CTkFrame(self.main, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", pady=(2, 16))
        head.grid_columnconfigure(0, weight=1)
        self.h_title = ctk.CTkLabel(head, text="Files", font=self.fonts["h1"],
                                    text_color=theme.TEXT, anchor="w")
        self.h_title.grid(row=0, column=0, sticky="w")
        self.h_sub = ctk.CTkLabel(head, text="", font=self.fonts["body"],
                                  text_color=theme.MUTED, anchor="w")
        self.h_sub.grid(row=1, column=0, sticky="w", pady=(4, 0))
        ctk.CTkLabel(head, text=f"model · {self.model}", font=self.fonts["mono_sm"],
                     fg_color=theme.CARD, corner_radius=8, text_color=theme.MUTED,
                     padx=12, pady=6).grid(row=0, column=1, rowspan=2, sticky="e")

    # --- page routing -----------------------------------------------------
    def show_page(self, key):
        self.page = key
        self.h_title.configure(text=key)
        self.h_sub.configure(text=SUBTITLES[key])
        self._update_nav()
        for w in self.content.winfo_children():
            w.destroy()
        if key == "AI Summary":
            self._build_summary_page()
        else:
            self._build_scan_view()

    # --- scan view (Files / Processes / Vulnerabilities) ------------------
    def _build_scan_view(self):
        wrap = ctk.CTkFrame(self.content, fg_color="transparent")
        wrap.grid(row=0, column=0, sticky="nsew")
        wrap.grid_columnconfigure(0, weight=1)
        wrap.grid_rowconfigure(1, weight=1)

        self._build_taskbar(wrap)

        cols = ctk.CTkFrame(wrap, fg_color="transparent")
        cols.grid(row=1, column=0, sticky="nsew", pady=(16, 0))
        cols.grid_columnconfigure(0, weight=3, uniform="c")
        cols.grid_columnconfigure(1, weight=2, uniform="c")
        cols.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(cols, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 18))
        left.grid_columnconfigure(0, weight=1)
        left.grid_rowconfigure(1, weight=1)
        self._build_summary_strip(left)

        listcard = ctk.CTkFrame(left, fg_color=theme.CARD, corner_radius=18)
        listcard.grid(row=1, column=0, sticky="nsew")
        listcard.grid_columnconfigure(0, weight=1)
        listcard.grid_rowconfigure(1, weight=1)
        lh = ctk.CTkFrame(listcard, fg_color="transparent")
        lh.grid(row=0, column=0, sticky="ew", padx=18, pady=(13, 8))
        lh.grid_columnconfigure(0, weight=1)
        label = {"Files": "FINDINGS", "Processes": "FLAGGED PROCESSES",
                 "Vulnerabilities": "ISSUES"}[self.page]
        ctk.CTkLabel(lh, text=label, font=self.fonts["section"],
                     text_color=theme.MUTED2).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(lh, text="sorted by severity", font=self.fonts["small"],
                     text_color=theme.MUTED2).grid(row=0, column=1, sticky="e")
        self.listbox = ctk.CTkScrollableFrame(listcard, fg_color="transparent")
        self.listbox.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self.listbox.grid_columnconfigure(0, weight=1)

        self.inspector = ctk.CTkScrollableFrame(
            cols, fg_color=theme.CARD, corner_radius=18,
            label_text="  INSPECTOR", label_font=self.fonts["section"],
            label_text_color=theme.MUTED2, label_fg_color=theme.CARD)
        self.inspector.grid(row=0, column=1, sticky="nsew")
        self.inspector.grid_columnconfigure(0, weight=1)

        self._render_rows()
        self._build_inspector()

    def _build_taskbar(self, parent):
        bar = ctk.CTkFrame(parent, fg_color=theme.CARD, corner_radius=14)
        bar.grid(row=0, column=0, sticky="ew")
        bar.grid_columnconfigure(0, weight=1)
        inner = ctk.CTkFrame(bar, fg_color="transparent")
        inner.grid(row=0, column=0, sticky="ew", padx=12, pady=9)
        inner.grid_columnconfigure(0, weight=1)

        if self.page == "Files":
            field = ctk.CTkFrame(inner, fg_color=theme.INSET, corner_radius=10)
            field.grid(row=0, column=0, sticky="ew", padx=(0, 10))
            ctk.CTkLabel(field, text="Target", font=self.fonts["mono_sm"],
                         text_color=theme.MUTED).pack(side="left", padx=(14, 8),
                                                      pady=9)
            ctk.CTkLabel(field, textvariable=self.target,
                         font=self.fonts["mono"], text_color=theme.ACCENT,
                         anchor="w").pack(side="left", fill="x", expand=True,
                                          pady=9)
            self._tbtn(inner, "Choose…", self._choose, "ghost").grid(
                row=0, column=1, padx=(0, 8))
            self._tbtn(inner, "Scan", self._scan, "primary").grid(row=0, column=2)
            self._tbtn(inner, "Deep", self._deep_scan, "ghost").grid(
                row=0, column=3, padx=(8, 0))
        elif self.page == "Processes":
            n = len(self.proc_threats)
            ctk.CTkLabel(inner,
                         text=f"{n} flagged process(es)" if n else
                         "Sweep to inspect running processes",
                         font=self.fonts["body"], text_color=theme.MUTED,
                         anchor="w").grid(row=0, column=0, sticky="w", padx=4)
            self._tbtn(inner, "Sweep processes", self._proc_sweep,
                       "primary").grid(row=0, column=1)
        else:
            n = len(self.vuln_findings)
            ctk.CTkLabel(inner,
                         text=f"{n} issue(s) found" if n else
                         "Audit installed software + OS posture",
                         font=self.fonts["body"], text_color=theme.MUTED,
                         anchor="w").grid(row=0, column=0, sticky="w", padx=4)
            self._tbtn(inner, "Audit software & OS", self._vuln_audit,
                       "primary").grid(row=0, column=1)

    def _build_summary_strip(self, parent):
        strip = ctk.CTkFrame(parent, fg_color=theme.CARD, corner_radius=18)
        strip.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        strip.grid_columnconfigure(1, weight=1)
        headline, sub, color, count, stats = self._summary_data()

        orb = ctk.CTkFrame(strip, width=58, height=58, corner_radius=29,
                           fg_color=theme.chip_bg(color), border_width=2,
                           border_color=color)
        orb.grid(row=0, column=0, padx=(18, 16), pady=16)
        orb.grid_propagate(False)
        ctk.CTkLabel(orb, text=str(count), font=self.fonts["orb"],
                     text_color=color).place(relx=0.5, rely=0.5, anchor="center")

        mid = ctk.CTkFrame(strip, fg_color="transparent")
        mid.grid(row=0, column=1, sticky="ew", pady=16)
        ctk.CTkLabel(mid, text=headline, font=self.fonts["body_bold"],
                     text_color=theme.TEXT, anchor="w").pack(anchor="w")
        ctk.CTkLabel(mid, text=sub, font=self.fonts["small"],
                     text_color=theme.MUTED, anchor="w").pack(anchor="w",
                                                              pady=(2, 0))
        stat_box = ctk.CTkFrame(strip, fg_color="transparent")
        stat_box.grid(row=0, column=2, padx=(10, 20), pady=16)
        for i, (v, l) in enumerate(stats):
            col = ctk.CTkFrame(stat_box, fg_color="transparent")
            col.grid(row=0, column=i, padx=12)
            ctk.CTkLabel(col, text=str(v), font=self.fonts["stat"],
                         text_color=theme.TEXT).pack()
            ctk.CTkLabel(col, text=l.upper(), font=self.fonts["badge"],
                         text_color=theme.MUTED2).pack()

    def _summary_data(self):
        if self.page == "Files":
            n = len(self.findings)
            crit = sum(1 for f in self.findings
                       if f.severity.value in ("critical", "high"))
            color = (theme.SEVERITY["critical"] if crit else
                     theme.SEVERITY["low"] if n else theme.ACCENT[1])
            headline = ("Review recommended" if n else "All clear")
            sub = (f"{crit} high/critical of {n} findings" if n else
                   "Nothing suspicious in the last scan")
            seen = self.last_report.files_seen if self.last_report else 0
            unread = self.last_report.files_unreadable if self.last_report else 0
            stats = [(f"{seen:,}", "files"), (str(n), "findings"),
                     (str(unread), "unread")]
            return headline, sub, color, n, stats
        if self.page == "Processes":
            n = len(self.proc_threats)
            prot = sum(1 for t in self.proc_threats if t.protected)
            color = (theme.proc_color(max((t.score for t in self.proc_threats),
                                          default=0)) if n else theme.ACCENT[1])
            headline = (f"{n} process(es) flagged" if n else "Nothing flagged")
            sub = ("Highest-scoring shown first" if n else
                   "Sweep to inspect running processes")
            stats = [(str(n), "flagged"), (str(prot), "protected"),
                     ("0", "stopped")]
            return headline, sub, color, n, stats
        n = len(self.vuln_findings)
        cves = sum(1 for f in self.vuln_findings if "cve" in f.rule.lower())
        color = (theme.SEVERITY["critical"] if any(
            f.severity.value in ("critical", "high") for f in self.vuln_findings)
            else theme.SEVERITY["low"] if n else theme.ACCENT[1])
        headline = (f"{n} issue(s) found" if n else "No known issues")
        sub = (f"{cves} CVEs, {n - cves} other" if n else
               "Audit software & OS posture")
        stats = [(str(n), "issues"), (str(cves), "CVEs"),
                 (str(n - cves), "other")]
        return headline, sub, color, n, stats

    # --- list rows --------------------------------------------------------
    def _render_rows(self):
        for w in self.listbox.winfo_children():
            w.destroy()
        items = {"Files": self.findings, "Processes": self.proc_threats,
                 "Vulnerabilities": self.vuln_findings}[self.page]
        if not items:
            empty = {"Files": "Run a scan to see findings.",
                     "Processes": "Sweep to inspect processes.",
                     "Vulnerabilities": "Audit to list issues."}[self.page]
            ctk.CTkLabel(self.listbox, text=empty, font=self.fonts["body"],
                         text_color=theme.MUTED).grid(row=0, column=0, pady=28)
            return
        for i, obj in enumerate(items):
            self._row_widget(i, obj)

    def _row_widget(self, i, obj):
        sel = self.sel[self.page] is obj
        row = ctk.CTkFrame(self.listbox,
                           fg_color=theme.ROW_SEL if sel else "transparent",
                           corner_radius=11)
        row.grid(row=i, column=0, sticky="ew", pady=2)
        row.grid_columnconfigure(1, weight=1)

        if self.page == "Processes":
            color = theme.proc_color(obj.score)
            chip = ctk.CTkLabel(row, text=str(obj.score), width=38, height=38,
                                corner_radius=10, font=self.fonts["body_bold"],
                                fg_color=theme.chip_bg(color), text_color=color)
            chip.grid(row=0, column=0, rowspan=2, padx=(10, 12), pady=10)
            name = f"{obj.name}"
            meta = f"pid {obj.pid}" + ("  · PROTECTED" if obj.protected else "")
            sub = "; ".join(obj.reasons) if obj.reasons else "—"
        else:
            color = theme.severity_color(obj.severity.value)
            bar = ctk.CTkFrame(row, width=4, height=34, corner_radius=3,
                               fg_color=color)
            bar.grid(row=0, column=0, rowspan=2, padx=(12, 12), pady=10)
            if self.page == "Files":
                name = Path(obj.target).name
                meta = ""
                sub = f"{Path(obj.target).parent} · {obj.rule}"
            else:
                name = obj.rule
                meta = obj.target
                sub = obj.detail or obj.rule
            chip = ctk.CTkLabel(row, text=_sev_label(obj.severity.value),
                                height=20, corner_radius=6,
                                font=self.fonts["badge"],
                                fg_color=theme.chip_bg(color), text_color=color)
            chip.grid(row=0, column=2, rowspan=2, padx=(8, 12))

        top = ctk.CTkFrame(row, fg_color="transparent")
        top.grid(row=0, column=1, sticky="ew", pady=(10, 0))
        ctk.CTkLabel(top, text=name, font=self.fonts["mono_bold"],
                     text_color=theme.TEXT, anchor="w").pack(side="left")
        if meta:
            ctk.CTkLabel(top, text="  " + meta, font=self.fonts["mono_sm"],
                         text_color=theme.MUTED2, anchor="w").pack(side="left")
        ctk.CTkLabel(row, text=sub, font=self.fonts["small"],
                     text_color=theme.MUTED, anchor="w").grid(
                         row=1, column=1, sticky="ew", pady=(1, 10))

        for w in (row, top):
            w.bind("<Button-1>", lambda e, o=obj: self._select(o))
            w.bind("<Enter>", lambda e, r=row, s=sel: r.configure(
                fg_color=theme.ROW_SEL if s else theme.ROW_HOVER))
            w.bind("<Leave>", lambda e, r=row, s=sel: r.configure(
                fg_color=theme.ROW_SEL if s else "transparent"))

    def _select(self, obj):
        self.sel[self.page] = obj
        self._render_rows()
        self._build_inspector()

    # --- inspector --------------------------------------------------------
    def _ins_label(self, text, top=18):
        ctk.CTkLabel(self.inspector, text=text, font=self.fonts["badge"],
                     text_color=theme.MUTED2, anchor="w").grid(
                         sticky="ew", padx=20, pady=(top, 6))

    def _build_inspector(self):
        for w in self.inspector.winfo_children():
            w.destroy()
        obj = self.sel[self.page]
        if obj is None:
            ctk.CTkLabel(self.inspector,
                         text="Select an item to review it here.",
                         font=self.fonts["body"], text_color=theme.MUTED).grid(
                             padx=20, pady=24)
            return
        if self.page == "Processes":
            self._inspect_proc(obj)
        elif self.page == "Vulnerabilities":
            self._inspect_finding(obj, vuln=True)
        else:
            self._inspect_finding(obj, vuln=False)

    def _ai_box(self, text, action=None, action_color=None):
        box = ctk.CTkFrame(self.inspector, fg_color=theme.ACCENT_SOFT,
                           corner_radius=12)
        box.grid(sticky="ew", padx=20, pady=(16, 4))
        box.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(box, text="LOCAL AI TRIAGE", font=self.fonts["badge"],
                     text_color=theme.ACCENT, anchor="w").grid(
                         sticky="w", padx=14, pady=(12, 4))
        ctk.CTkLabel(box, text=text, font=self.fonts["small"],
                     text_color=theme.TEXT, anchor="w", justify="left",
                     wraplength=360).grid(sticky="ew", padx=14, pady=(0, 10))
        if action:
            ctk.CTkLabel(box, text=f"→ {action}", font=self.fonts["badge"],
                         fg_color=theme.chip_bg(action_color or theme.ACCENT[1]),
                         text_color=action_color or theme.ACCENT,
                         corner_radius=7, padx=10, pady=4).grid(
                             sticky="w", padx=14, pady=(0, 12))

    def _kv_table(self, pairs):
        tbl = ctk.CTkFrame(self.inspector, fg_color=theme.INSET,
                           corner_radius=10)
        tbl.grid(sticky="ew", padx=20, pady=(0, 4))
        tbl.grid_columnconfigure(1, weight=1)
        for r, (k, v) in enumerate(pairs):
            ctk.CTkLabel(tbl, text=k, font=self.fonts["mono_sm"],
                         text_color=theme.MUTED, anchor="w").grid(
                             row=r, column=0, sticky="w", padx=(12, 10), pady=7)
            ctk.CTkLabel(tbl, text=str(v), font=self.fonts["mono_sm"],
                         text_color=theme.TEXT, anchor="e", wraplength=240,
                         justify="right").grid(row=r, column=1, sticky="e",
                                               padx=(0, 12), pady=7)

    def _inspect_finding(self, f, vuln):
        color = theme.severity_color(f.severity.value)
        head = ctk.CTkFrame(self.inspector, fg_color="transparent")
        head.grid(sticky="ew", padx=20, pady=(18, 4))
        ctk.CTkLabel(head, text=_sev_label(f.severity.value), height=22,
                     corner_radius=7, font=self.fonts["badge"],
                     fg_color=theme.chip_bg(color), text_color=color,
                     padx=9).pack(side="left")
        ctk.CTkLabel(head, text="  " + f.kind.value.replace("_", " "),
                     font=self.fonts["small"], text_color=theme.MUTED2).pack(
                         side="left")
        title = Path(f.target).name if not vuln else f.rule
        ctk.CTkLabel(self.inspector, text=title, font=self.fonts["mono_bold"],
                     text_color=theme.TEXT, anchor="w", wraplength=360,
                     justify="left").grid(sticky="ew", padx=20, pady=(8, 0))
        sub = (str(Path(f.target).parent) + "/") if not vuln else f.target
        ctk.CTkLabel(self.inspector, text=sub, font=self.fonts["mono_sm"],
                     text_color=theme.ACCENT if vuln else theme.MUTED,
                     anchor="w", wraplength=360, justify="left").grid(
                         sticky="ew", padx=20, pady=(4, 0))
        if f.detail:
            ctk.CTkLabel(self.inspector, text=f.detail, font=self.fonts["body"],
                         text_color=theme.TEXT, anchor="w", justify="left",
                         wraplength=360).grid(sticky="ew", padx=20, pady=(12, 0))

        crit = f.severity.value in ("critical", "high")
        if vuln:
            self._ai_box(f.detail or "Known vulnerability in installed software.")
        else:
            self._ai_box(
                "Strong match — recommend isolating this file." if crit else
                "Low confidence; review before acting.",
                "QUARANTINE" if crit else "ASK_USER",
                theme.DANGER if crit else theme.SEVERITY["medium"])

        self._ins_label("DETAILS" if vuln else "EVIDENCE")
        pairs = list((f.evidence or {}).items()) or [("rule", f.rule)]
        self._kv_table(pairs)

        if vuln:
            self._btn_full("Copy upgrade command", lambda: None, "ghost")
        else:
            btns = ctk.CTkFrame(self.inspector, fg_color="transparent")
            btns.grid(sticky="ew", padx=20, pady=(16, 4))
            btns.grid_columnconfigure((0, 1), weight=1)
            self._tbtn(btns, "Quarantine", self._quarantine, "danger").grid(
                row=0, column=0, sticky="ew", padx=(0, 5))
            self._tbtn(btns, "Mark safe", self._mark_safe, "ghost").grid(
                row=0, column=1, sticky="ew", padx=(5, 0))
            ctk.CTkLabel(self.inspector,
                         text="Quarantine is reversible — files move to a "
                              "vault, never deleted.",
                         font=self.fonts["small"], text_color=theme.MUTED2,
                         wraplength=360).grid(padx=20, pady=(8, 16))

    def _inspect_proc(self, t):
        color = theme.proc_color(t.score)
        head = ctk.CTkFrame(self.inspector, fg_color="transparent")
        head.grid(sticky="ew", padx=20, pady=(18, 4))
        ctk.CTkLabel(head, text=str(t.score), width=44, height=44,
                     corner_radius=12, font=self.fonts["stat"],
                     fg_color=theme.chip_bg(color), text_color=color).pack(
                         side="left")
        box = ctk.CTkFrame(head, fg_color="transparent")
        box.pack(side="left", padx=12)
        ctk.CTkLabel(box, text=t.name, font=self.fonts["mono_bold"],
                     text_color=theme.TEXT, anchor="w").pack(anchor="w")
        ctk.CTkLabel(box, text=f"pid {t.pid}", font=self.fonts["mono_sm"],
                     text_color=theme.MUTED, anchor="w").pack(anchor="w")
        bar = ctk.CTkProgressBar(self.inspector, height=6, corner_radius=4,
                                 progress_color=color, fg_color=theme.INSET)
        bar.set(min(t.score, 100) / 100)
        bar.grid(sticky="ew", padx=20, pady=(10, 2))
        ctk.CTkLabel(self.inspector, text=f"threat score {t.score} / 100",
                     font=self.fonts["small"], text_color=theme.MUTED2,
                     anchor="w").grid(sticky="ew", padx=20)
        if t.exe:
            ctk.CTkLabel(self.inspector, text=t.exe, font=self.fonts["mono_sm"],
                         text_color=theme.MUTED, anchor="w", wraplength=360,
                         justify="left").grid(sticky="ew", padx=20, pady=(8, 0))

        self._ins_label("WHY IT WAS FLAGGED")
        for r in (t.reasons or ["No specific reasons recorded."]):
            line = ctk.CTkFrame(self.inspector, fg_color="transparent")
            line.grid(sticky="ew", padx=20, pady=2)
            ctk.CTkLabel(line, text="•", text_color=color,
                         font=self.fonts["body"]).pack(side="left", padx=(2, 8))
            ctk.CTkLabel(line, text=r, font=self.fonts["small"],
                         text_color=theme.TEXT, anchor="w", justify="left",
                         wraplength=330).pack(side="left")

        self._ai_box(
            "Behaviour is consistent with masquerading — suspend and review."
            if t.score >= 50 else "Looks unusual but low risk.",
            "SUSPEND" if t.score >= 50 else "REVIEW",
            theme.SUCCESS if t.score >= 50 else theme.SEVERITY["medium"])

        btns = ctk.CTkFrame(self.inspector, fg_color="transparent")
        btns.grid(sticky="ew", padx=20, pady=(16, 4))
        btns.grid_columnconfigure((0, 1), weight=1)
        self._tbtn(btns, "Suspend", lambda: self._proc_action("suspend"),
                   "success").grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self._tbtn(btns, "Kill", lambda: self._proc_action("kill"),
                   "danger").grid(row=0, column=1, sticky="ew", padx=(5, 0))
        ctk.CTkLabel(self.inspector,
                     text="Suspend freezes the process — reversible. Protected "
                          "processes are never killed.",
                     font=self.fonts["small"], text_color=theme.MUTED2,
                     wraplength=360).grid(padx=20, pady=(8, 16))

    # --- AI Summary page --------------------------------------------------
    def _build_summary_page(self):
        scroll = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
        scroll.grid(row=0, column=0, sticky="nsew")
        scroll.grid_columnconfigure(0, weight=1)

        hero = ctk.CTkFrame(scroll, fg_color=theme.CARD, corner_radius=16)
        hero.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        orb = ctk.CTkFrame(hero, width=54, height=54, corner_radius=27,
                           fg_color=theme.chip_bg(theme.ACCENT[1]),
                           border_width=2, border_color=theme.ACCENT[1])
        orb.grid(row=0, column=0, padx=(20, 16), pady=18)
        orb.grid_propagate(False)
        self._orb_icon = iconset.icon("shield-check", theme.ACCENT[0],
                                      theme.ACCENT[1], size=22)
        ctk.CTkLabel(orb, text="", image=self._orb_icon).place(
            relx=0.5, rely=0.5, anchor="center")
        n = len(self.findings) + len(self.proc_threats) + len(self.vuln_findings)
        col = ctk.CTkFrame(hero, fg_color="transparent")
        col.grid(row=0, column=1, sticky="w", pady=18)
        ctk.CTkLabel(col, text=f"Scan complete — {n} thing(s) to review."
                     if n else "Nothing needs your attention.",
                     font=self.fonts["h1"], text_color=theme.TEXT,
                     anchor="w").pack(anchor="w")
        ctk.CTkLabel(col, text=f"Generated locally by {self.model} · nothing "
                     "was uploaded.", font=self.fonts["small"],
                     text_color=theme.MUTED, anchor="w").pack(anchor="w",
                                                              pady=(3, 0))

        body = ctk.CTkFrame(scroll, fg_color=theme.CARD, corner_radius=16)
        body.grid(row=1, column=0, sticky="ew", pady=(0, 16))
        body.grid_columnconfigure(0, weight=1)
        self.summary_label = ctk.CTkLabel(
            body, text=self.summary_text or "Generating local summary…",
            font=self.fonts["body"], text_color=theme.TEXT, anchor="w",
            justify="left", wraplength=720)
        self.summary_label.grid(sticky="ew", padx=22, pady=20)

        note = ctk.CTkFrame(scroll, fg_color=theme.ACCENT_SOFT, corner_radius=14)
        note.grid(row=2, column=0, sticky="ew")
        ctk.CTkLabel(note, text="This ran entirely on your Mac.",
                     font=self.fonts["body_bold"], text_color=theme.ACCENT,
                     anchor="w").grid(sticky="w", padx=18, pady=(14, 2))
        ctk.CTkLabel(note, text="No uploads, no account, no telemetry. The "
                     "scanner never opened a network socket.",
                     font=self.fonts["small"], text_color=theme.TEXT,
                     anchor="w", wraplength=720, justify="left").grid(
                         sticky="w", padx=18, pady=(0, 14))
        self._generate_summary()

    def _generate_summary(self):
        def work():
            try:
                text = triage.summarize_session(
                    self.store.session_summary_data(), self.model)
            except Exception as e:
                text = f"(summary unavailable: {e})"
            self.summary_text = text
            self.root.after(0, lambda: self.summary_label.configure(text=text)
                            if self.summary_label.winfo_exists() else None)
        threading.Thread(target=work, daemon=True).start()

    # --- buttons ----------------------------------------------------------
    def _tbtn(self, parent, text, command, kind):
        styles = {
            "primary": dict(fg_color=theme.ACCENT_BTN, hover_color=theme.ACCENT_H,
                            text_color=theme.ON_ACCENT),
            "success": dict(fg_color=theme.SUCCESS, hover_color=theme.SUCCESS_H,
                            text_color="#FFFFFF"),
            "danger": dict(fg_color=theme.DANGER, hover_color=theme.DANGER_H,
                           text_color="#FFFFFF"),
            "ghost": dict(fg_color=theme.INSET, hover_color=theme.ROW_HOVER,
                          text_color=theme.TEXT),
        }[kind]
        return ctk.CTkButton(parent, text=text, command=command, height=38,
                             corner_radius=10, font=self.fonts["body_bold"],
                             **styles)

    def _btn_full(self, text, command, kind):
        self._tbtn(self.inspector, text, command, kind).grid(
            sticky="ew", padx=20, pady=(16, 16))

    # --- status -----------------------------------------------------------
    def _set_status(self, text):
        if self.status.winfo_exists():
            self.status.configure(text=text)

    def _progress(self, text):
        self.root.after(0, self._set_status, text)

    # --- file actions -----------------------------------------------------
    def _choose(self):
        d = filedialog.askdirectory()
        if d:
            self.target.set(d)

    def _scan(self):
        self._run_scan(config.ScanConfig(roots=[Path(self.target.get())]),
                       "Scanning…")

    def _deep_scan(self):
        where = ("all drives" if sys.platform.startswith("win")
                 else "the entire filesystem (/)")
        fda = ("\n\nmacOS: grant Oyster Full Disk Access under System Settings "
               "→ Privacy & Security, or private folders will be skipped.") \
            if sys.platform == "darwin" else ""
        if not messagebox.askyesno(
                "Deep scan — entire computer",
                f"Scan {where}, including system, hidden and cache/build "
                "folders.\n\nThis can take a long time." + fda + "\n\nProceed?"):
            return
        self._run_scan(
            config.ScanConfig(roots=config.full_system_roots(), deep=True,
                              include_noise=True),
            "Deep scan — walking the whole computer…")

    def _run_scan(self, cfg, status):
        self._set_status(status)
        self.sel["Files"] = None
        rules = Path(__file__).resolve().parent.parent / "rules"
        scanner = Scanner(cfg, rules_dir=rules)

        def work():
            t0 = time.time()
            try:
                report = scanner.scan(progress=self._progress)
            except Exception as e:
                self.root.after(0, self._set_status,
                                f"Scan stopped: {type(e).__name__}: {e}")
                return
            self.scan_secs = time.time() - t0
            self.last_report = report
            self.findings = [f for f in report.findings
                             if f.kind in FILE_KINDS]
            self.root.after(0, self._after_scan)

        threading.Thread(target=work, daemon=True).start()

    def _after_scan(self):
        if self.page == "Files":
            self.show_page("Files")

    def _quarantine(self):
        f = self.sel["Files"]
        if not f:
            return
        path = Path(f.target)
        protected = any(str(path).startswith(str(r))
                        for r in config.protected_path_roots())
        msg = f"Quarantine (reversible):\n{path}\n\nReason: {f.rule}"
        if protected:
            msg = "WARNING — PROTECTED LOCATION. Confirm carefully.\n\n" + msg
        if messagebox.askyesno("Confirm quarantine", msg):
            try:
                qid = self.quar.quarantine(path, reason=f.rule)
                self.store.log_action("quarantine", str(path), True,
                                      detail=f"qid={qid}", reversible=True)
                messagebox.showinfo("Quarantined",
                                    f"Moved to vault ({qid}). Restorable.")
            except OSError as e:
                messagebox.showerror("Failed", str(e))
        else:
            self.store.log_action("quarantine", str(path), False)

    def _mark_safe(self):
        f = self.sel["Files"]
        if f:
            self.store.log_action("mark_safe", f.target, True, reversible=False)
            messagebox.showinfo("Marked safe", f"{f.target} marked safe.")

    # --- process actions --------------------------------------------------
    def _proc_sweep(self):
        self._set_status("Inspecting processes…")
        self.sel["Processes"] = None

        def work():
            self.proc_threats = processes.inspect()
            self.root.after(0, lambda: self.show_page("Processes"))

        threading.Thread(target=work, daemon=True).start()

    def _proc_action(self, kind: str):
        t = self.sel["Processes"]
        if not t:
            return
        if t.protected:
            messagebox.showwarning(
                "Protected", f"{t.name} is a protected system process and "
                             "will not be killed.")
            return
        verb = "Suspend (freeze)" if kind == "suspend" else "KILL"
        if not messagebox.askyesno(
                f"Confirm {verb}",
                f"{verb} pid {t.pid} ({t.name})?\n\nReasons: "
                f"{'; '.join(t.reasons)}"):
            self.store.log_action(kind, f"pid:{t.pid}:{t.name}", False)
            return
        try:
            if kind == "suspend":
                processes.suspend(t.pid)
            else:
                processes.terminate(t.pid, t.name)
            self.store.log_action(kind, f"pid:{t.pid}:{t.name}", True,
                                  reversible=(kind == "suspend"))
            messagebox.showinfo("Done", f"{verb} applied to pid {t.pid}.")
        except Exception as e:
            messagebox.showerror("Failed", str(e))

    # --- vuln audit -------------------------------------------------------
    def _vuln_audit(self):
        self._set_status("Auditing software + posture…")
        self.sel["Vulnerabilities"] = None

        def work():
            findings = vulnaudit.audit(self.cfg.osv_db_path)
            for f in findings:
                self.store.add_finding(f)
            self.vuln_findings = findings
            self.root.after(0, lambda: self.show_page("Vulnerabilities"))

        threading.Thread(target=work, daemon=True).start()


def main():
    from core import toolpaths
    toolpaths.ensure_path()
    theme.setup_appearance()
    root = ctk.CTk()

    def start_app():
        gate.destroy()
        App(root)

    gate = PreflightGate(root, on_launch=start_app)
    gate.pack(fill="both", expand=True)
    root.mainloop()


if __name__ == "__main__":
    main()
