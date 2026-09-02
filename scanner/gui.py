"""Tkinter desktop window.

Why Tkinter and not PySimpleGUI (which this project used to depend on):
PySimpleGUI moved to a paid licence in 2024 and its old versions were pulled
from PyPI — which is why ``pip install -r requirements.txt`` failed outright on
this project. The v5 code was re-released under LGPL3 in 2026, but LGPL3
complicates the single-file frozen binary that a teacher on a locked-down school
laptop actually needs. Tkinter ships with CPython, has no licence questions, and
freezes cleanly with PyInstaller.

All display logic lives in :mod:`scanner.gui_model`, which has no Tk import and
is unit tested. This file is deliberately only widgets and wiring.
"""
from __future__ import annotations

import queue
import sys
import threading
import time
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, List, Optional, Tuple

from . import __version__, reporters
from .findings import Verdict
from .gui_model import (
    VERDICT_COLORS,
    detail_for,
    parse_dropped_paths,
    rows_for,
    summarise_for_email,
    tally_line,
)
from .limits import DEFAULT_LIMITS
from .quarantine import QuarantineError, QuarantineStore
from .scanner_core import ScanConfig, ScanResult, scan
from .triage import TriageSummary, build_summary

DISCLAIMER = (
    "Static checks only — files are read, never opened or run. "
    "This is not antivirus."
)


class ScannerWindow:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(f"Teacher-Safe Local File Scanner {__version__}")
        self.root.geometry("1040x680")
        self.root.minsize(820, 520)

        # ("progress", (done, total, name)) | ("done", TriageSummary) | ("error", str)
        self._queue: "queue.Queue[Tuple[str, Any]]" = queue.Queue()
        self._summary: Optional[TriageSummary] = None
        self._results: List[ScanResult] = []
        self._targets: List[Path] = []
        self._scanning = False

        self._build()
        self.root.after(80, self._drain_queue)

    # -- layout --------------------------------------------------------
    def _build(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:  # pragma: no cover - platform dependent
            pass
        style.configure("Treeview", rowheight=26)
        style.configure("Head.TLabel", font=("TkDefaultFont", 15, "bold"))
        style.configure("Sub.TLabel", foreground="#5c6672")

        top = ttk.Frame(self.root, padding=(14, 12, 14, 6))
        top.pack(fill="x")

        ttk.Label(top, text="Check student files before you open them", style="Head.TLabel").pack(
            anchor="w"
        )
        ttk.Label(top, text=DISCLAIMER, style="Sub.TLabel").pack(anchor="w", pady=(2, 10))

        picker = ttk.Frame(top)
        picker.pack(fill="x")
        self.path_var = tk.StringVar()
        entry = ttk.Entry(picker, textvariable=self.path_var)
        entry.pack(side="left", fill="x", expand=True)
        ttk.Button(picker, text="Choose folder…", command=self._pick_folder).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(picker, text="Choose files…", command=self._pick_files).pack(
            side="left", padx=(6, 0)
        )
        self.scan_button = ttk.Button(picker, text="Scan", command=self._start_scan)
        self.scan_button.pack(side="left", padx=(10, 0))

        self.status_var = tk.StringVar(value="Choose a folder of submissions, then press Scan.")
        ttk.Label(self.root, textvariable=self.status_var, padding=(16, 4)).pack(anchor="w")

        self.tally_var = tk.StringVar(value="")
        ttk.Label(self.root, textvariable=self.tally_var, padding=(16, 0)).pack(anchor="w")

        self.progress = ttk.Progressbar(self.root, mode="determinate")
        self.progress.pack(fill="x", padx=16, pady=(6, 8))

        panes = ttk.PanedWindow(self.root, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=14, pady=(0, 8))

        left = ttk.Frame(panes)
        self.tree = ttk.Treeview(
            left, columns=("verdict", "file", "reason"), show="headings", selectmode="browse"
        )
        self.tree.heading("verdict", text="Verdict")
        self.tree.heading("file", text="File")
        self.tree.heading("reason", text="Why")
        self.tree.column("verdict", width=130, stretch=False)
        self.tree.column("file", width=230)
        self.tree.column("reason", width=280)
        scroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        for verdict, (fg, bg) in VERDICT_COLORS.items():
            self.tree.tag_configure(verdict.slug, foreground=fg, background=bg)
        panes.add(left, weight=3)

        right = ttk.Frame(panes)
        self.detail = tk.Text(right, wrap="word", padx=12, pady=10, relief="flat", height=10)
        detail_scroll = ttk.Scrollbar(right, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=detail_scroll.set, state="disabled")
        self.detail.pack(side="left", fill="both", expand=True)
        detail_scroll.pack(side="right", fill="y")
        panes.add(right, weight=2)

        actions = ttk.Frame(self.root, padding=(14, 0, 14, 12))
        actions.pack(fill="x")
        self.html_button = ttk.Button(
            actions, text="Save HTML report…", command=self._save_html, state="disabled"
        )
        self.html_button.pack(side="left")
        self.json_button = ttk.Button(
            actions, text="Save JSON…", command=self._save_json, state="disabled"
        )
        self.json_button.pack(side="left", padx=(8, 0))
        self.copy_button = ttk.Button(
            actions, text="Copy summary for IT", command=self._copy_summary, state="disabled"
        )
        self.copy_button.pack(side="left", padx=(8, 0))
        self.quarantine_button = ttk.Button(
            actions,
            text="Quarantine flagged files…",
            command=self._quarantine,
            state="disabled",
        )
        self.quarantine_button.pack(side="left", padx=(8, 0))
        ttk.Label(actions, text="Nothing is ever deleted.", style="Sub.TLabel").pack(
            side="right"
        )

    # -- actions -------------------------------------------------------
    def _pick_folder(self) -> None:
        chosen = filedialog.askdirectory(title="Choose a folder of submissions")
        if chosen:
            self.path_var.set(chosen)

    def _pick_files(self) -> None:
        chosen = filedialog.askopenfilenames(title="Choose files to check")
        if chosen:
            self.path_var.set(";".join(chosen))

    def _start_scan(self) -> None:
        if self._scanning:
            return
        targets = parse_dropped_paths(self.path_var.get())
        missing = [p for p in targets if not p.exists()]
        if not targets:
            messagebox.showinfo("Nothing selected", "Choose a folder or some files first.")
            return
        if missing:
            messagebox.showerror(
                "Not found", "These do not exist:\n" + "\n".join(str(p) for p in missing)
            )
            return

        self._targets = targets
        self._scanning = True
        self.scan_button.configure(state="disabled")
        for button in (
            self.html_button,
            self.json_button,
            self.copy_button,
            self.quarantine_button,
        ):
            button.configure(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self._set_detail("Scanning…")
        self.status_var.set("Scanning…")
        self.progress.configure(value=0, maximum=100)
        threading.Thread(target=self._scan_worker, args=(targets,), daemon=True).start()

    def _scan_worker(self, targets: List[Path]) -> None:
        started = time.perf_counter()
        config = ScanConfig(limits=DEFAULT_LIMITS, threads=4)
        results: List[ScanResult] = []
        try:
            for target in targets:
                results.extend(
                    scan(
                        target,
                        config,
                        progress=lambda done, total, path: self._queue.put(
                            ("progress", (done, total, path.name))
                        ),
                    )
                )
        except Exception as exc:  # pragma: no cover - defensive
            self._queue.put(("error", str(exc)))
            return
        summary = build_summary(
            results,
            roots=targets,
            scanner_version=__version__,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )
        self._queue.put(("done", summary))

    def _drain_queue(self) -> None:
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "progress":
                    done, total, name = payload
                    self.progress.configure(maximum=max(total, 1), value=done)
                    self.status_var.set(f"Checking {name}  ({done}/{total})")
                elif kind == "done":
                    self._finish(payload)
                elif kind == "error":
                    self._scanning = False
                    self.scan_button.configure(state="normal")
                    self.status_var.set("Scan failed.")
                    messagebox.showerror("Scan failed", str(payload))
        except queue.Empty:
            pass
        self.root.after(80, self._drain_queue)

    def _finish(self, summary: TriageSummary) -> None:
        self._scanning = False
        self._summary = summary
        self._results = list(summary.results)
        self.scan_button.configure(state="normal")
        self.progress.configure(value=self.progress["maximum"])
        self.status_var.set(summary.headline())
        self.tally_var.set(tally_line(summary))

        for index, row in enumerate(rows_for(summary)):
            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=(f"{row.symbol}  {row.label}", row.name, row.reason),
                tags=(row.verdict.slug,),
            )
        for button in (self.html_button, self.json_button, self.copy_button):
            button.configure(state="normal")
        if summary.needs_attention:
            self.quarantine_button.configure(state="normal")
        children = self.tree.get_children()
        if children:
            self.tree.selection_set(children[0])
            self.tree.focus(children[0])
        else:
            self._set_detail("No files were found to check.")

    def _on_select(self, _event: object) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        try:
            result = self._results[int(selection[0])]
        except (ValueError, IndexError):  # pragma: no cover
            return
        view = detail_for(result)
        text = [
            view.title,
            view.verdict_label,
            "",
            view.path,
            f"SHA-256  {view.sha256}",
            "",
            "How this verdict was reached",
            *[f"  • {line}" for line in view.rationale],
            "",
            *[block + "\n" + "-" * 58 for block in view.blocks],
        ]
        self._set_detail("\n".join(text))

    def _set_detail(self, text: str) -> None:
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.configure(state="disabled")

    def _save_html(self) -> None:
        if not self._summary:
            return
        target = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML report", "*.html")],
            initialfile="file-triage-report.html",
        )
        if not target:
            return
        reporters.write_html_report(self._summary, Path(target))
        if messagebox.askyesno("Report saved", f"Saved to {target}.\n\nOpen it now?"):
            webbrowser.open(Path(target).resolve().as_uri())

    def _save_json(self) -> None:
        if not self._summary:
            return
        target = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON report", "*.json")],
            initialfile="file-triage-report.json",
        )
        if target:
            reporters.write_json_report(self._summary, Path(target))
            messagebox.showinfo("Saved", f"Saved to {target}")

    def _copy_summary(self) -> None:
        if not self._summary:
            return
        text = summarise_for_email(self._summary)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo(
            "Copied",
            "A plain-text summary is on your clipboard. Paste it into an email to IT.\n\n"
            "Do not attach the files themselves.",
        )

    def _quarantine(self) -> None:
        if not self._summary:
            return
        flagged = [
            r for r in self._results if r.verdict is Verdict.DO_NOT_OPEN
        ]
        if not flagged:
            messagebox.showinfo("Nothing to quarantine", "No file was marked DO NOT OPEN.")
            return
        if not messagebox.askyesno(
            "Move files to quarantine?",
            f"{len(flagged)} file(s) marked DO NOT OPEN will be MOVED into a folder "
            "you choose next.\n\nNothing is deleted, and every move is logged so it "
            "can be undone.\n\nContinue?",
        ):
            return
        directory = filedialog.askdirectory(title="Choose a quarantine folder")
        if not directory:
            return
        store = QuarantineStore(Path(directory))
        moved, failed = 0, []
        for result in flagged:
            try:
                store.quarantine(
                    result.path,
                    reason=(result.top_finding.code if result.top_finding else "verdict"),
                    verdict=result.verdict.value,
                    sha256=result.sha256 or None,
                )
            except QuarantineError as exc:
                failed.append(f"{result.path.name}: {exc}")
            else:
                moved += 1
        message = f"Moved {moved} file(s) into {directory}.\n\nNothing was deleted."
        if failed:
            message += "\n\nCould not move:\n" + "\n".join(failed[:6])
        messagebox.showinfo("Quarantine complete", message)


def run() -> int:
    root = tk.Tk()
    ScannerWindow(root)
    root.mainloop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(run())
