"""Oyster — desktop UI (CustomTkinter, cross-platform, zero network).

A modern sidebar app: a left nav rail (Files / Processes / Vulnerabilities), a
rounded content card per page, and a shared AI report panel. Built on
CustomTkinter for rounded surfaces, hover states, and a live light/dark toggle —
still pure Python, still opens no sockets of its own.

    python -m ui.app

Every destructive action is gated behind an explicit button + confirmation, and
protected paths/processes are never auto-actioned. The look lives in ui/theme.py.
"""
from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path
from tkinter import END, filedialog, messagebox

import customtkinter as ctk

from agent import triage
from core import config, preflight, processes, vulnaudit
from core.findings import FindingKind, Store
from core.quarantine import Quarantine
from core.scanner import Scanner

from . import iconset, theme


def _open_permission_settings(key: str) -> None:
    """Deep-link the user to the relevant OS settings pane (best effort)."""
    if key == "fda" and sys.platform == "darwin":
        subprocess.run(
            ["open", "x-apple.systempreferences:com.apple.preference.security"
                     "?Privacy_AllFiles"], check=False)


class ResultList(ctk.CTkScrollableFrame):
    """A scrollable list of selectable, severity-accented result rows."""

    def __init__(self, master, fonts, on_select=None, empty="No results yet."):
        super().__init__(master, fg_color=theme.INSET, corner_radius=12,
                         border_width=0)
        self.fonts = fonts
        self.on_select = on_select
        self.empty_text = empty
        self._rows = []          # (frame, data)
        self._selected = None
        self._empty = ctk.CTkLabel(self, text=empty, text_color=theme.MUTED,
                                   font=fonts["body"])
        self._empty.pack(pady=26)

    def clear(self):
        for fr, _ in self._rows:
            fr.destroy()
        self._rows.clear()
        self._selected = None
        self._empty.configure(text=self.empty_text)
        self._empty.pack(pady=26)

    def add(self, data, text, accent):
        self._empty.pack_forget()
        row = ctk.CTkFrame(self, fg_color="transparent", corner_radius=8,
                           height=40)
        row.pack(fill="x", padx=6, pady=2)
        bar = ctk.CTkFrame(row, width=4, height=26, fg_color=accent,
                           corner_radius=2)
        bar.pack(side="left", padx=(8, 10), pady=7)
        lbl = ctk.CTkLabel(row, text=text, anchor="w", justify="left",
                           font=self.fonts["body"], text_color=theme.TEXT)
        lbl.pack(side="left", fill="x", expand=True, padx=(0, 8), pady=7)
        idx = len(self._rows)
        for w in (row, bar, lbl):
            w.bind("<Button-1>", lambda e, i=idx: self.select(i))
            w.bind("<Enter>", lambda e, i=idx: self._hover(i, True))
            w.bind("<Leave>", lambda e, i=idx: self._hover(i, False))
        self._rows.append((row, data))

    def _hover(self, i, on):
        if i == self._selected:
            return
        self._rows[i][0].configure(
            fg_color=theme.ROW_HOVER if on else "transparent")

    def select(self, i):
        for j, (fr, _) in enumerate(self._rows):
            fr.configure(fg_color=theme.ROW_SEL if j == i else "transparent")
        self._selected = i
        if self.on_select:
            self.on_select()

    def selected(self):
        if self._selected is None:
            return None
        return self._rows[self._selected][1]


class PreflightGate(ctk.CTkFrame):
    """Startup screen: check permissions/capabilities and block launch until
    every REQUIRED one is satisfied."""

    def __init__(self, root: ctk.CTk, on_launch):
        super().__init__(root, fg_color=theme.BG)
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
        self.brand_icon = iconset.icon("shield-check", theme.PRIMARY,
                                       theme.PRIMARY, size=30)
        ctk.CTkLabel(head, text="", image=self.brand_icon).pack(side="left")
        box = ctk.CTkFrame(head, fg_color="transparent")
        box.pack(side="left", padx=12)
        ctk.CTkLabel(box, text="Welcome to Oyster", font=self.fonts["title"],
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
            fg_color=theme.PRIMARY, hover_color=theme.PRIMARY_H,
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
            need = ", ".join(b.name for b in blocked)
            self.summary.configure(
                text=f"Required, still missing: {need}",
                text_color=theme.DANGER)
        else:
            self.launch_btn.configure(state="normal")
            self.summary.configure(text="All required permissions granted.",
                                   text_color=theme.TEAL)

    def _row(self, c: preflight.Check):
        if c.ok:
            color, label = theme.TEAL, "OK"
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
                     text_color=theme.MUTED, anchor="w",
                     wraplength=380, justify="left").pack(anchor="w")
        if not c.ok and c.fix:
            ctk.CTkLabel(text, text=c.fix, font=self.fonts["small"],
                         text_color=theme.PRIMARY, anchor="w", wraplength=380,
                         justify="left").pack(anchor="w", pady=(2, 0))

        if not c.ok and c.key == "fda":
            ctk.CTkButton(
                row, text="Open Settings",
                command=lambda: _open_permission_settings("fda"),
                width=120, height=34, corner_radius=9,
                font=self.fonts["small"], fg_color=theme.PRIMARY,
                hover_color=theme.PRIMARY_H,
                text_color=theme.ON_ACCENT).pack(side="right", padx=16)

    def _launch(self):
        self.on_launch()


class App:
    def __init__(self, root: ctk.CTk):
        self.root = root
        root.title("Oyster — Local Agentic Antivirus")
        root.geometry("980x740")
        root.minsize(860, 620)
        self.fonts = theme.make_fonts(root)
        root.configure(fg_color=theme.BG)

        self.cfg = config.ScanConfig()
        self.model = config.recommended_model()
        self.store = Store(self.cfg.db_path)
        self.quar = Quarantine(self.cfg.quarantine_dir)
        self.findings = []
        self.proc_threats = []

        root.grid_columnconfigure(1, weight=1)
        root.grid_rowconfigure(0, weight=1)
        self._build_sidebar()
        self._build_main()
        self.show_page("Files")

    # --- sidebar ----------------------------------------------------------
    def _build_sidebar(self):
        bar = ctk.CTkFrame(self.root, width=216, corner_radius=0,
                           fg_color=theme.SIDEBAR)
        bar.grid(row=0, column=0, sticky="nsew")
        bar.grid_propagate(False)
        bar.grid_rowconfigure(5, weight=1)

        brand = ctk.CTkFrame(bar, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="ew", padx=20, pady=(22, 6))
        self.brand_icon = iconset.icon("shield-check", theme.PRIMARY,
                                       theme.PRIMARY, size=24)
        ctk.CTkLabel(brand, text="", image=self.brand_icon,
                     width=24).pack(side="left")
        ctk.CTkLabel(brand, text="Oyster", font=self.fonts["brand"],
                     text_color=theme.TEXT).pack(side="left", padx=8)

        ctk.CTkLabel(bar, text="LOCAL ANTIVIRUS", font=self.fonts["small"],
                     text_color=theme.MUTED).grid(row=1, column=0, sticky="w",
                                                   padx=22, pady=(0, 16))

        self.nav_buttons = {}
        self.nav_icons = {}   # key -> (idle CTkImage, active CTkImage)
        items = [("Files", "folder"),
                 ("Processes", "cpu"),
                 ("Vulnerabilities", "shield-alert")]
        for i, (key, glyph) in enumerate(items):
            idle = iconset.icon(glyph, theme.MUTED[0], theme.MUTED[1], size=18)
            active = iconset.icon(glyph, "#FFFFFF", "#FFFFFF", size=18)
            self.nav_icons[key] = (idle, active)
            b = ctk.CTkButton(
                bar, text=key, image=idle, compound="left", anchor="w",
                font=self.fonts["nav"], corner_radius=10, height=42,
                fg_color="transparent", text_color=theme.MUTED,
                hover_color=theme.ROW_HOVER,
                command=lambda k=key: self.show_page(k))
            b.grid(row=2 + i, column=0, sticky="ew", padx=14, pady=3)
            self.nav_buttons[key] = b

        # bottom: offline badge + appearance toggle
        footer = ctk.CTkFrame(bar, fg_color="transparent")
        footer.grid(row=6, column=0, sticky="ew", padx=20, pady=18)
        badge = ctk.CTkFrame(footer, fg_color="transparent")
        badge.pack(anchor="w")
        dot = ctk.CTkFrame(badge, width=9, height=9, corner_radius=5,
                           fg_color=theme.TEAL)
        dot.pack(side="left", pady=2)
        dot.pack_propagate(False)
        ctk.CTkLabel(badge, text="fully offline", font=self.fonts["body_bold"],
                     text_color=theme.TEAL).pack(side="left", padx=7)
        ctk.CTkLabel(footer, text="nothing leaves this machine",
                     font=self.fonts["small"],
                     text_color=theme.MUTED).pack(anchor="w", pady=(0, 12))
        self.mode_switch = ctk.CTkSwitch(
            footer, text="Dark mode", font=self.fonts["small"],
            text_color=theme.MUTED, command=self._toggle_mode,
            progress_color=theme.PRIMARY)
        self.mode_switch.pack(anchor="w")

    def _toggle_mode(self):
        ctk.set_appearance_mode(
            "dark" if self.mode_switch.get() else "light")

    # --- main area --------------------------------------------------------
    def _build_main(self):
        main = ctk.CTkFrame(self.root, fg_color="transparent")
        main.grid(row=0, column=1, sticky="nsew", padx=24, pady=20)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)

        # header
        head = ctk.CTkFrame(main, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        head.grid_columnconfigure(0, weight=1)
        self.page_title = ctk.CTkLabel(head, text="Files",
                                       font=self.fonts["title"],
                                       text_color=theme.TEXT)
        self.page_title.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(head, text=f"model · {self.model}", font=self.fonts["chip"],
                     fg_color=theme.CARD, corner_radius=8, text_color=theme.MUTED,
                     padx=12, pady=6).grid(row=0, column=1, sticky="e")

        # stacked page cards
        self.pages = {}
        holder = ctk.CTkFrame(main, fg_color="transparent")
        holder.grid(row=1, column=0, sticky="nsew")
        holder.grid_columnconfigure(0, weight=1)
        holder.grid_rowconfigure(0, weight=1)
        for key, builder in (("Files", self._page_files),
                             ("Processes", self._page_procs),
                             ("Vulnerabilities", self._page_vulns)):
            card = ctk.CTkFrame(holder, fg_color=theme.CARD, corner_radius=16)
            card.grid(row=0, column=0, sticky="nsew")
            builder(card)
            self.pages[key] = card

        # shared status + AI report
        self.status = ctk.CTkLabel(main, text="Ready.", anchor="w",
                                   font=self.fonts["small"],
                                   text_color=theme.MUTED)
        self.status.grid(row=2, column=0, sticky="ew", pady=(14, 6))

        rep = ctk.CTkFrame(main, fg_color=theme.CARD, corner_radius=16)
        rep.grid(row=3, column=0, sticky="ew")
        rep.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(rep, text="AI SUMMARY REPORT", font=self.fonts["small"],
                     text_color=theme.MUTED).grid(row=0, column=0, sticky="w",
                                                   padx=18, pady=(14, 4))
        self.report = ctk.CTkTextbox(rep, height=132, fg_color=theme.INSET,
                                     corner_radius=12, font=self.fonts["mono"],
                                     text_color=theme.TEXT, border_width=0)
        self.report.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 16))

    def show_page(self, key):
        self.pages[key].tkraise()
        self.page_title.configure(text=key)
        for k, b in self.nav_buttons.items():
            idle, active = self.nav_icons[k]
            if k == key:
                b.configure(fg_color=theme.PRIMARY, text_color=theme.ON_ACCENT,
                            hover_color=theme.PRIMARY_H, image=active)
            else:
                b.configure(fg_color="transparent", text_color=theme.MUTED,
                            hover_color=theme.ROW_HOVER, image=idle)

    def _action_col(self, parent):
        col = ctk.CTkFrame(parent, fg_color="transparent", width=210)
        col.grid_propagate(False)
        return col

    def _btn(self, parent, text, command, kind="secondary"):
        styles = {
            "primary": dict(fg_color=theme.PRIMARY, hover_color=theme.PRIMARY_H,
                            text_color=theme.ON_ACCENT),
            "success": dict(fg_color=theme.TEAL, hover_color=theme.TEAL_H,
                            text_color=theme.ON_ACCENT),
            "danger": dict(fg_color=theme.DANGER, hover_color=theme.DANGER_H,
                           text_color=theme.ON_ACCENT),
            "secondary": dict(fg_color=theme.INSET, hover_color=theme.ROW_HOVER,
                              text_color=theme.TEXT),
        }[kind]
        return ctk.CTkButton(parent, text=text, command=command, height=40,
                             corner_radius=10, font=self.fonts["body_bold"],
                             **styles)

    # --- Files page -------------------------------------------------------
    def _page_files(self, card):
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(card, fg_color="transparent")
        top.grid(row=0, column=0, columnspan=2, sticky="ew", padx=18,
                 pady=(18, 12))
        top.grid_columnconfigure(0, weight=1)
        self.target = ctk.StringVar(value=str(Path.home() / "Downloads"))
        field = ctk.CTkFrame(top, fg_color=theme.INSET, corner_radius=10)
        field.grid(row=0, column=0, sticky="ew", padx=(0, 12))
        ctk.CTkLabel(field, text="Target", font=self.fonts["small"],
                     text_color=theme.MUTED).pack(side="left", padx=(14, 8),
                                                  pady=10)
        ctk.CTkLabel(field, textvariable=self.target, font=self.fonts["chip"],
                     text_color=theme.PRIMARY, anchor="w").pack(
                         side="left", fill="x", expand=True, pady=10)
        self._btn(top, "Choose…", self._choose, "secondary").grid(
            row=0, column=1, padx=(0, 8))
        self._btn(top, "Scan", self._scan, "primary").grid(row=0, column=2)

        self.files_list = ResultList(card, self.fonts, empty="Run a scan to see findings.")
        self.files_list.grid(row=1, column=0, sticky="nsew", padx=(18, 8),
                             pady=(0, 18))

        col = self._action_col(card)
        col.grid(row=1, column=1, sticky="ns", padx=(0, 18), pady=(0, 18))
        self._btn(col, "Deep scan: whole computer", self._deep_scan,
                  "primary").pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(col, text="entire filesystem · hidden + system folders",
                     font=self.fonts["small"], text_color=theme.MUTED,
                     wraplength=200).pack(fill="x", pady=(0, 16))
        self._btn(col, "Quarantine selected", self._quarantine,
                  "danger").pack(fill="x", pady=4)
        self._btn(col, "Mark safe", self._mark_safe, "success").pack(fill="x",
                                                                     pady=4)
        self._btn(col, "AI Report", self._report, "secondary").pack(
            fill="x", pady=(18, 0))

    # --- Processes page ---------------------------------------------------
    def _page_procs(self, card):
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(1, weight=1)
        self._btn(card, "Sweep running processes", self._proc_sweep,
                  "primary").grid(row=0, column=0, columnspan=2, sticky="w",
                                  padx=18, pady=(18, 12))
        self.proc_list = ResultList(card, self.fonts,
                                    empty="Sweep to inspect processes.")
        self.proc_list.grid(row=1, column=0, sticky="nsew", padx=(18, 8),
                            pady=(0, 18))
        col = self._action_col(card)
        col.grid(row=1, column=1, sticky="ns", padx=(0, 18), pady=(0, 18))
        self._btn(col, "Suspend (reversible)",
                  lambda: self._proc_action("suspend"), "success").pack(
                      fill="x", pady=4)
        self._btn(col, "Kill process", lambda: self._proc_action("kill"),
                  "danger").pack(fill="x", pady=4)
        self._btn(col, "Quarantine its binary", self._proc_quarantine,
                  "danger").pack(fill="x", pady=4)

    # --- Vulnerabilities page --------------------------------------------
    def _page_vulns(self, card):
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(1, weight=1)
        self._btn(card, "Audit software + OS posture", self._vuln_audit,
                  "primary").grid(row=0, column=0, sticky="w", padx=18,
                                  pady=(18, 12))
        self.vuln_list = ResultList(card, self.fonts,
                                    empty="Audit to list known weaknesses.")
        self.vuln_list.grid(row=1, column=0, sticky="nsew", padx=18,
                            pady=(0, 18))

    # --- file actions -----------------------------------------------------
    def _choose(self):
        d = filedialog.askdirectory()
        if d:
            self.target.set(d)

    def _scan(self):
        self._run_scan(config.ScanConfig(roots=[Path(self.target.get())]),
                       "Scanning…")

    def _deep_scan(self):
        import sys
        where = ("all drives" if sys.platform.startswith("win")
                 else "the entire filesystem (/)")
        fda = ("\n\nmacOS: grant Oyster (or your terminal) Full Disk Access "
               "under System Settings → Privacy & Security, or private folders "
               "(Mail, Messages, other users) will be skipped.") \
            if sys.platform == "darwin" else ""
        if not messagebox.askyesno(
                "Deep scan — entire computer",
                f"Scan {where}, including system, hidden and cache/build "
                "folders.\n\nThis can take a long time and walk hundreds of "
                "thousands of files." + fda + "\n\nProceed?"):
            return
        self._run_scan(
            config.ScanConfig(roots=config.full_system_roots(), deep=True,
                              include_noise=True),
            "Deep scan — walking the whole computer…")

    def _run_scan(self, cfg, status):
        self.status.configure(text=status)
        self.files_list.clear()
        rules = Path(__file__).resolve().parent.parent / "rules"
        scanner = Scanner(cfg, rules_dir=rules)

        def work():
            report = scanner.scan(
                progress=lambda s: self.status.configure(text=s))
            self.findings = report.findings
            self.root.after(0, self._render, report)

        threading.Thread(target=work, daemon=True).start()

    def _render(self, report):
        self.files_list.clear()
        for f in self.findings:
            if f.kind == FindingKind.PROCESS_SUSPICIOUS:
                continue
            self.files_list.add(
                f, f"[{f.severity.value}]  {f.target}   —   {f.rule}",
                theme.severity_color(f.severity.value))
        self.status.configure(
            text=f"Done. {report.files_seen} files · {len(self.findings)} "
                 f"finding(s) · {report.vulnerabilities} vuln(s) · offline.")

    def _selected(self):
        return self.files_list.selected()

    def _quarantine(self):
        f = self._selected()
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
        f = self._selected()
        if f:
            self.store.log_action("mark_safe", f.target, True, reversible=False)
            messagebox.showinfo("Marked safe", f"{f.target} marked safe.")

    # --- process actions --------------------------------------------------
    def _proc_sweep(self):
        self.status.configure(text="Inspecting processes…")
        self.proc_list.clear()

        def work():
            self.proc_threats = processes.inspect()
            self.root.after(0, self._render_procs)

        threading.Thread(target=work, daemon=True).start()

    def _render_procs(self):
        self.proc_list.clear()
        for t in self.proc_threats:
            flag = "  [PROTECTED]" if t.protected else ""
            self.proc_list.add(
                t, f"[{t.score:3d}]  pid {t.pid}  {t.name}{flag}  —  "
                   f"{'; '.join(t.reasons)}", theme.proc_color(t.score))
        self.status.configure(
            text=f"{len(self.proc_threats)} suspicious process(es).")

    def _selected_proc(self):
        return self.proc_list.selected()

    def _proc_action(self, kind: str):
        t = self._selected_proc()
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

    def _proc_quarantine(self):
        t = self._selected_proc()
        if not t or not t.exe:
            return
        if messagebox.askyesno(
                "Quarantine binary",
                f"Quarantine the executable behind pid {t.pid}?\n{t.exe}"):
            try:
                qid = self.quar.quarantine(Path(t.exe), reason="process binary")
                self.store.log_action("quarantine", t.exe, True,
                                      detail=f"qid={qid}", reversible=True)
                messagebox.showinfo("Quarantined", f"Binary vaulted ({qid}).")
            except OSError as e:
                messagebox.showerror("Failed", str(e))

    # --- vuln audit -------------------------------------------------------
    def _vuln_audit(self):
        self.status.configure(text="Auditing software + posture…")
        self.vuln_list.clear()

        def work():
            findings = vulnaudit.audit(self.cfg.osv_db_path)
            for f in findings:
                self.store.add_finding(f)
            self.root.after(0, lambda: self._render_vulns(findings))

        threading.Thread(target=work, daemon=True).start()

    def _render_vulns(self, findings):
        self.vuln_list.clear()
        for f in findings:
            self.vuln_list.add(
                f, f"[{f.severity.value}]  {f.target}  —  {f.rule}: {f.detail}",
                theme.severity_color(f.severity.value))
        self.status.configure(text=f"{len(findings)} vulnerability finding(s).")

    # --- report -----------------------------------------------------------
    def _report(self):
        self.report.delete("1.0", END)
        self.report.insert(END, "Generating report…\n")

        def work():
            text = triage.summarize_session(
                self.store.session_summary_data(), self.model)
            self.root.after(0, lambda: (self.report.delete("1.0", END),
                                        self.report.insert(END, text)))

        threading.Thread(target=work, daemon=True).start()


def main():
    from core import toolpaths
    toolpaths.ensure_path()  # so a Finder-launched app finds clamscan etc.
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
