"""Graphical user interface (Tkinter – part of the Python standard library).

The GUI reuses the *same* engine as the CLI: one single-pass read per file,
merged pattern regexes, the behavioural layer and the quarantine store.
Scans run in a worker thread pool with live progress, a stop button, and
severity-coloured results.

    python3 -m antivirus gui

If Tkinter is not installed (or no display is available) the command fails
gracefully with a helpful message and exit code 2.
"""
from __future__ import annotations

import contextlib
import io
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import __version__
from .config import Config
from .models import Finding
from .quarantine import Quarantine
from .report import ReportWriter
from .scanner import ScanResult, Scanner, walk_files
from .selftest import run_selftest
from .signatures import SignatureDB

#: Bundled signature database (same location the CLI falls back to).
BUNDLED_SIGNATURES = Path(__file__).resolve().parent.parent / "data" / "signatures.json"

try:  # Tkinter is stdlib, but distros may ship it as a separate package
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    _TK_AVAILABLE = True
except ImportError:  # pragma: no cover - platform dependent
    tk = None  # type: ignore[assignment]
    ttk = None  # type: ignore[assignment]
    _TK_AVAILABLE = False

#: severity -> (foreground, background)
SEVERITY_COLORS: Dict[str, Tuple[str, str]] = {
    "critical": ("#ffffff", "#8b0000"),
    "high": ("#ffffff", "#cc3300"),
    "medium": ("#000000", "#e6a817"),
    "low": ("#000000", "#d9e021"),
    "info": ("#000000", "#8fbf8f"),
}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

APP_TITLE = f"AntiVirus {__version__} – pure-Python antivirus (educational)"


def tk_available() -> bool:
    """True when Tkinter could be imported on this platform."""
    return _TK_AVAILABLE


def finding_row(f: Finding) -> Tuple[str, str, str, str, str]:
    """One Treeview row for a finding."""
    return (f.severity, f.name, f.path, f.kind, f.message)


def summarize(result: ScanResult, notes: Dict[str, str]) -> str:
    """One-line scan summary for the status bar / log."""
    threats = {f.path for f in result.findings}
    verdict = "CLEAN" if result.clean else f"INFECTED ({len(threats)} file(s) affected)"
    return (
        f"{verdict} – {result.files_scanned} files scanned, "
        f"{len(result.findings)} findings, {result.elapsed:.2f} s"
        + (f", {len(notes)} action(s) taken" if notes else "")
    )


def open_in_file_manager(path: Path) -> bool:
    """Best-effort: open a directory with the platform file manager."""
    path = Path(path)
    if not path.exists():
        return False
    try:
        if sys.platform.startswith("win"):
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
        return True
    except (OSError, AttributeError):
        return False


def _default_signature_path() -> Path:
    """Same fallback logic as the CLI: bundle -> ./data/signatures.json."""
    path = Path.cwd() / "data" / "signatures.json"
    if not path.exists() and BUNDLED_SIGNATURES.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(BUNDLED_SIGNATURES, path)
    return path


if _TK_AVAILABLE:

    class AntiVirusApp(tk.Tk):  # noqa: N801  (tkinter convention)
        """Main application window: scan controls + findings/quarantine/log tabs."""

        def __init__(self) -> None:
            super().__init__()
            self.title(APP_TITLE)
            self.geometry("980x640")
            self.minsize(760, 480)

            self.config = Config()
            self.config.signatures_file = _default_signature_path()
            self.config.resolve_paths(Path.cwd())
            self.db = SignatureDB(self.config.signatures_file)
            self.scanner = Scanner(self.config, self.db, threads="auto")
            self.quarantine = Quarantine(self.config.quarantine_dir)
            self.report_writer = ReportWriter(self.config.report_dir)

            self._queue: "queue.Queue[tuple]" = queue.Queue()
            self._stop = threading.Event()
            self._worker: Optional[threading.Thread] = None
            self._last_result: Optional[ScanResult] = None
            self._last_notes: Dict[str, str] = {}
            self._scanned_paths: Dict[str, List[Finding]] = {}

            self._build_ui()
            self._log(f"AntiVirus {__version__} – educational tool. "
                      f"Signatures: {len(self.db.list())}")
            self._log("Pick a target and press Scan. Nothing is ever executed; "
                      "analysis is static.")
            self.after(100, self._poll_queue)
            self.protocol("WM_DELETE_WINDOW", self._on_close)

        # ------------------------------------------------------------------ UI
        def _build_ui(self) -> None:
            pad = {"padx": 8, "pady": 4}

            top = ttk.Frame(self)
            top.pack(fill="x", **pad)
            ttk.Label(top, text="Target:").grid(row=0, column=0, sticky="w")
            self.target_var = tk.StringVar(value=str(Path.cwd()))
            entry = ttk.Entry(top, textvariable=self.target_var)
            entry.grid(row=0, column=1, sticky="ew", padx=4)
            entry.bind("<Return>", lambda _e: self._start_scan())
            ttk.Button(top, text="Browse…",
                       command=self._browse).grid(row=0, column=2)
            top.columnconfigure(1, weight=1)

            opts = ttk.Frame(self)
            opts.pack(fill="x", **pad)
            ttk.Label(opts, text="Action:").pack(side="left")
            self.action_var = tk.StringVar(value="detect")
            for value, label in (("detect", "detect only"),
                                 ("quarantine", "quarantine threats"),
                                 ("delete", "delete threats")):
                ttk.Radiobutton(opts, text=label, value=value,
                                variable=self.action_var).pack(side="left", padx=6)
            ttk.Separator(opts, orient="vertical").pack(side="left", fill="y", padx=8)
            ttk.Label(opts, text="Threads:").pack(side="left")
            self.threads_var = tk.StringVar(value="auto")
            threads_box = ttk.Combobox(opts, textvariable=self.threads_var,
                                       values=["auto", "1", "2", "4", "8", "16"],
                                       width=4, state="readonly")
            threads_box.pack(side="left", padx=4)
            self.no_behavior_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(opts, text="no behaviour analysis",
                            variable=self.no_behavior_var).pack(side="left", padx=8)

            btns = ttk.Frame(self)
            btns.pack(fill="x", **pad)
            self.scan_btn = ttk.Button(btns, text="▶  Scan", command=self._start_scan)
            self.scan_btn.pack(side="left")
            self.stop_btn = ttk.Button(btns, text="■  Stop", command=self._stop_scan,
                                       state="disabled")
            self.stop_btn.pack(side="left", padx=4)
            ttk.Button(btns, text="Self test", command=self._run_selftest).pack(
                side="left", padx=4)
            ttk.Button(btns, text="Open reports folder",
                       command=self._open_reports).pack(side="left", padx=4)
            self._set_busy(False)

            self.status_var = tk.StringVar(value="Ready.")
            status = ttk.Label(self, textvariable=self.status_var, relief="sunken",
                               anchor="w", padding=(6, 2))
            status.pack(side="bottom", fill="x")

            self.nb = ttk.Notebook(self)
            self.nb.pack(fill="both", expand=True, padx=8)

            # -- Findings tab --------------------------------------------------
            f_tab = ttk.Frame(self.nb)
            self.nb.add(f_tab, text=" Findings")
            cols = ("severity", "name", "file", "kind")
            widths = {"severity": 80, "name": 260, "file": 380, "kind": 150}
            self.findings_tree = ttk.Treeview(
                f_tab, columns=cols, show="headings", height=14)
            for c in cols:
                self.findings_tree.heading(c, text=c.capitalize())
                self.findings_tree.column(c, width=widths[c],
                                          anchor="w" if c != "severity" else "center")
            for sev, (fg, bg) in SEVERITY_COLORS.items():
                self.findings_tree.tag_configure(sev, foreground=fg, background=bg)
            vsb = ttk.Scrollbar(f_tab, orient="vertical",
                                command=self.findings_tree.yview)
            self.findings_tree.configure(yscrollcommand=vsb.set)
            self.findings_tree.pack(side="left", fill="both", expand=True, padx=(0, 0))
            vsb.pack(side="left", fill="y")
            self.findings_tree.bind("<<TreeviewSelect>>", self._on_finding_select)
            self.detail_text = tk.Text(f_tab, width=42, height=14, wrap="word",
                                       state="disabled", relief="sunken")
            self.detail_text.pack(side="left", fill="y", padx=(4, 0))

            # -- Quarantine tab --------------------------------------------------
            q_tab = ttk.Frame(self.nb)
            self.nb.add(q_tab, text=" Quarantine")
            qcols = ("id", "when", "size", "path", "reason")
            qwidths = {"id": 110, "when": 150, "size": 70, "path": 330, "reason": 220}
            self.quarantine_tree = ttk.Treeview(
                q_tab, columns=qcols, show="headings", height=14)
            for c in qcols:
                title = "File" if c == "id" else c.capitalize()
                self.quarantine_tree.heading(c, text=title)
                self.quarantine_tree.column(c, width=qwidths[c], anchor="w")
            qsb = ttk.Scrollbar(q_tab, orient="vertical",
                                command=self.quarantine_tree.yview)
            self.quarantine_tree.configure(yscrollcommand=qsb.set)
            self.quarantine_tree.pack(side="left", fill="both", expand=True)
            qsb.pack(side="left", fill="y")
            qbtns = ttk.Frame(q_tab)
            qbtns.pack(fill="x", side="bottom", pady=4, padx=4)
            ttk.Button(qbtns, text="Refresh", command=self._refresh_quarantine).pack(
                side="left")
            ttk.Button(qbtns, text="Restore selected…",
                       command=self._restore_selected).pack(side="left", padx=4)
            ttk.Button(qbtns, text="Purge selected…",
                       command=self._purge_selected).pack(side="left", padx=4)

            # -- Log tab -----------------------------------------------------------
            l_tab = ttk.Frame(self.nb)
            self.nb.add(l_tab, text=" Log")
            self.log_text = tk.Text(l_tab, state="disabled", wrap="none")
            lsb = ttk.Scrollbar(l_tab, orient="vertical",
                                command=self.log_text.yview)
            self.log_text.configure(yscrollcommand=lsb.set)
            self.log_text.pack(side="left", fill="both", expand=True)
            lsb.pack(side="left", fill="y")

            self._refresh_quarantine()

        # -------------------------------------------------------------- helpers
        def _log(self, line: str) -> None:
            self.log_text.configure(state="normal")
            self.log_text.insert("end", f"{time.strftime('%H:%M:%S')}  {line}\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")

        def _set_busy(self, busy: bool) -> None:
            self.scan_btn.configure(state="disabled" if busy else "normal")
            self.stop_btn.configure(state="normal" if busy else "disabled")

        def _browse(self) -> None:
            path = filedialog.askdirectory(initialdir=self.target_var.get() or ".")
            if path:
                self.target_var.set(path)

        def _open_reports(self) -> None:
            if not open_in_file_manager(self.config.report_dir):
                self._log(f"Reports folder: {self.config.report_dir.resolve()}")

        # ----------------------------------------------------------------- scan
        def _start_scan(self) -> None:
            if self._worker is not None and self._worker.is_alive():
                return
            target = Path(self.target_var.get().strip() or ".")
            if not target.exists():
                messagebox.showerror("AntiVirus",
                                     f"No such file or directory:\n{target}")
                return
            # Capture all Tk state on the main thread; the worker must not
            # touch Tk widgets/variables directly.
            action = self.action_var.get()
            self.scanner.threads = self.threads_var.get()
            self.config.behavior_enabled = not self.no_behavior_var.get()
            self._stop.clear()
            self._last_result = None
            self._last_notes = {}
            self._scanned_paths = {}
            for iid in self.findings_tree.get_children():
                self.findings_tree.delete(iid)
            self.detail_text.configure(state="normal")
            self.detail_text.delete("1.0", "end")
            self.detail_text.configure(state="disabled")
            self._set_busy(True)
            self.status_var.set(f"Scanning {target} …")
            self._log(f"--- scan {target}  (action={action}, "
                      f"threads={self.scanner.threads}, "
                      f"behaviour={'off' if not self.config.behavior_enabled else 'on'})")
            self._worker = threading.Thread(target=self._scan_worker,
                                            args=(target, action), daemon=True)
            self._worker.start()

        def _stop_scan(self) -> None:
            self._stop.set()
            self._log("Stop requested – finishing current file(s) …")

        def _scan_worker(self, target: Path, action: str) -> None:
            """Collect the tree (same walk as the CLI) and scan files in parallel."""
            result = ScanResult(target=str(target), started_at=time.time())
            notes: Dict[str, str] = {}
            wlog = lambda line: self._queue.put(("log", line))  # noqa: E731
            try:
                if target.is_file():
                    files: List[Tuple[Path, os.stat_result]] = \
                        [(target, target.lstat())]
                else:
                    files = []
                    protected = (self.config.quarantine_dir.resolve(),
                                 self.config.report_dir.resolve())

                    def _skipped(_p: Path, _reason: str) -> None:
                        result.files_skipped += 1

                    def _record(p: Path, st: os.stat_result) -> None:
                        files.append((p, st))

                    for _ in walk_files(target, self.config.exclude_dirs,
                                        protected, on_skip=_skipped,
                                        on_file=_record):
                        pass
                    if self._stop.is_set():
                        raise _ScanStopped()

                workers = self.scanner._workers()
                if len(files) > 1 and workers > 1:
                    self._scan_files_progress(files, result, workers)
                else:
                    for p, _st in files:
                        if self._stop.is_set():
                            raise _ScanStopped()
                        local = self._scan_one(p)
                        if local is not None:
                            self._merge(local, result, p)
                        self._queue.put(("progress",
                                         result.files_scanned, len(files), str(p)))
            except _ScanStopped:
                result.errors.append("scan stopped by user")
                wlog("Scan stopped by user.")
            except OSError as exc:
                result.errors.append(f"{target}: {exc}")
                wlog(f"error: {exc}")

            result.finished_at = time.time()
            self._apply_actions(result, notes, action, wlog)
            self._queue.put(("done", result, notes))

        def _scan_files_progress(self, files, result: ScanResult,
                                 workers: int) -> None:
            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=workers,
                                    thread_name_prefix="av-gui") as pool:
                jobs: List[Tuple[Path, object]] = []
                for p, _st in files:
                    if self._stop.is_set():
                        raise _ScanStopped()
                    jobs.append((p, pool.submit(self._scan_one, p)))
                for p, fut in jobs:
                    local = fut.result()
                    if local is not None:
                        self._merge(local, result, p)
                    self._queue.put(("progress",
                                     result.files_scanned, len(files), ""))

        def _scan_one(self, path: Path) -> Optional[ScanResult]:
            """Scan one file with the shared single-pass engine (in a worker)."""
            if self._stop.is_set():
                return None
            local = ScanResult(target=str(path), started_at=0.0)
            self.scanner._scan_file(path, local)
            return local

        def _merge(self, local: ScanResult, result: ScanResult,
                   path: Path) -> None:
            """Fold one file's result into the tree result (worker thread only)."""
            result.files_scanned += local.files_scanned
            result.files_skipped += local.files_skipped
            result.bytes_scanned += local.bytes_scanned
            if local.errors:
                result.errors.extend(local.errors)
            if local.findings:
                result.findings.extend(local.findings)
                self._queue.put(("finding", path, local.findings))

        def _apply_actions(self, result: ScanResult, notes: Dict[str, str],
                           action: str, wlog) -> None:
            if action == "detect":
                self._queue.put(("report", self.report_writer.save(
                    result, action=action, actions_taken=notes), notes))
                return
            handled = set()
            for finding in result.findings:
                if finding.path in handled:
                    continue
                handled.add(finding.path)
                path = Path(finding.path)
                if not path.exists():
                    notes[finding.path] = "already gone"
                elif action == "quarantine":
                    try:
                        item = self.quarantine.put(path, finding)
                        notes[finding.path] = f"quarantined as {item.id}"
                        wlog(f"quarantined {path.name} as {item.id}")
                    except OSError as exc:
                        notes[finding.path] = f"quarantine failed: {exc}"
                        wlog(f"quarantine failed for {path}: {exc}")
                else:  # delete
                    try:
                        path.unlink()
                        notes[finding.path] = "deleted"
                        wlog(f"deleted {path}")
                    except OSError as exc:
                        notes[finding.path] = f"delete failed: {exc}"
                        wlog(f"delete failed for {path}: {exc}")
            self._queue.put(("report", self.report_writer.save(
                result, action=action, actions_taken=notes), notes))

        # -------------------------------------------------------------- polling
        def _poll_queue(self) -> None:
            try:
                while True:
                    msg = self._queue.get_nowait()
                    kind = msg[0]
                    if kind == "progress":
                        _, done, total, current = msg
                        self.status_var.set(
                            f"Scanning {done}/{total}"
                            + (f" – {Path(current).name}" if current else " …"))
                    elif kind == "finding":
                        _, path, findings = msg
                        for f in findings:
                            self._add_finding(f)
                        self._log(f"{path}: {len(findings)} finding(s)")
                    elif kind == "report":
                        _, report_path, notes = msg
                        self._log(f"report saved: {report_path}")
                        if notes:
                            for p, note in notes.items():
                                self._log(f"  {p}: {note}")
                    elif kind == "selftest":
                        _, rc, text = msg
                        self._log(text.rstrip())
                        self._log(f"self test finished (exit {rc})")
                    elif kind == "log":
                        self._log(msg[1])
                    elif kind == "done":
                        self._on_scan_done(msg[1], msg[2])
            except queue.Empty:
                pass
            self.after(100, self._poll_queue)

        def _add_finding(self, f: Finding) -> None:
            row = finding_row(f)
            self.findings_tree.insert(
                "", "end", values=row,
                tags=(f.severity, Path(f.path).name),
                iid=f"{f.path}\x1f{f.name}\x1f{len(self._scanned_paths.get(f.path, []))}")
            self._scanned_paths.setdefault(f.path, []).append(f)

        def _on_finding_select(self, _event=None) -> None:
            sel = self.findings_tree.selection()
            self.detail_text.configure(state="normal")
            self.detail_text.delete("1.0", "end")
            if sel:
                f = self._scanned_paths.get(sel[0].split("\x1f")[0], [])
                for finding in f:
                    self.detail_text.insert(
                        "end",
                        f"{finding.severity.upper()}  {finding.name}\n"
                        f"file:   {finding.path}\n"
                        f"kind:   {finding.kind}\n"
                        f"detail: {finding.message}\n"
                        + (f"sha256: {finding.sha256}\n" if finding.sha256 else "")
                        + (f"size:   {finding.size} bytes\n" if finding.size else "")
                        + "\n")
            self.detail_text.configure(state="disabled")

        def _on_scan_done(self, result: ScanResult, notes: Dict[str, str]) -> None:
            self._last_result = result
            self._last_notes = notes
            self._set_busy(False)
            for err in result.errors:
                self._log(f"note: {err}")
            summary = summarize(result, notes)
            self.status_var.set(summary)
            self._log(summary)
            if not result.clean:
                order = sorted(result.findings,
                               key=lambda f: (_SEVERITY_RANK.get(f.severity, 9),
                                              f.path, f.name))
                self._log("Findings by severity:")
                for f in order:
                    self._log(f"  [{f.severity:<8}] {f.name}  –  {f.path}")
            else:
                self._log("No threats found.")
            self._refresh_quarantine()
            if not result.clean:
                verdict = result.worst_severity
                if verdict in ("critical", "high"):
                    messagebox.showwarning(
                        "AntiVirus",
                        f"Scan finished – {verdict.upper()} severity threats found.\n"
                        f"See the Findings tab.")

        # ------------------------------------------------------------ quarantine
        def _refresh_quarantine(self) -> None:
            for iid in self.quarantine_tree.get_children():
                self.quarantine_tree.delete(iid)
            try:
                items = self.quarantine.items()
            except OSError:
                items = []
            for item in items:
                self.quarantine_tree.insert(
                    "", "end",
                    values=(item.id, item.quarantined_at, item.size,
                            item.original_path, item.reason),
                    tags=(item.reason.split(":")[0],))

        def _selected_quarantine_id(self) -> Optional[str]:
            sel = self.quarantine_tree.selection()
            if not sel:
                messagebox.showinfo("AntiVirus", "Select a quarantined item first.")
                return None
            return self.quarantine_tree.item(sel[0], "values")[0]

        def _restore_selected(self) -> None:
            item_id = self._selected_quarantine_id()
            if item_id is None:
                return
            if not messagebox.askyesno(
                    "AntiVirus",
                    f"Restore {item_id} to its original location?\n"
                    "The file has previously been flagged – restore only if you "
                    "know it is safe."):
                return
            try:
                item, target = self.quarantine.restore(item_id)
            except (KeyError, ValueError, FileNotFoundError, OSError) as exc:
                messagebox.showerror("AntiVirus", f"Restore failed: {exc}")
                return
            self._log(f"restored {item_id} -> {target}")
            self._refresh_quarantine()

        def _purge_selected(self) -> None:
            item_id = self._selected_quarantine_id()
            if item_id is None:
                return
            if not messagebox.askyesno(
                    "AntiVirus",
                    f"Permanently destroy {item_id}?\nThis cannot be undone."):
                return
            try:
                self.quarantine.purge(item_id)
            except (KeyError, ValueError, FileNotFoundError, OSError) as exc:
                messagebox.showerror("AntiVirus", f"Purge failed: {exc}")
                return
            self._log(f"purged {item_id}")
            self._refresh_quarantine()

        # --------------------------------------------------------------- selftest
        def _run_selftest(self) -> None:
            if self._worker is not None and self._worker.is_alive():
                messagebox.showinfo("AntiVirus", "Wait for the scan to finish first.")
                return
            self._log("--- running built-in self test …")
            buf = io.StringIO()

            def run() -> None:
                try:
                    with contextlib.redirect_stdout(buf):
                        rc = run_selftest()
                except Exception:
                    buf.write(traceback.format_exc())
                    rc = 1
                self._queue.put(("selftest", rc, buf.getvalue()))

            threading.Thread(target=run, daemon=True).start()

        def _on_close(self) -> None:
            self._stop.set()
            self.destroy()


class _ScanStopped(Exception):
    """Internal: user pressed Stop."""


def run_gui() -> int:
    """Entry point for ``antivirus gui``. Returns a process exit code."""
    if not _TK_AVAILABLE:
        print("error: Tkinter is not available on this system.\n"
              "  Debian/Ubuntu:  sudo apt install python3-tk\n"
              "  Fedora:         sudo dnf install python3-tkinter\n"
              "  macOS (brew):   usually included with Python\n"
              "  Windows:        included in the standard installer\n"
              "The command-line interface works without it:\n"
              "  python3 -m antivirus scan .",
              file=sys.stderr)
        return 2
    try:
        app = AntiVirusApp()
    except tk.TclError as exc:  # no display (headless / SSH without X)
        print(f"error: cannot open a display ({exc}).\n"
              "Run the GUI on a machine with a graphical session, or use\n"
              "  python3 -m antivirus scan .\n"
              "on the command line instead.", file=sys.stderr)
        return 2
    try:
        app.mainloop()
    except tk.TclError:  # display lost / window closed abruptly
        pass
    return 0
