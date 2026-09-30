"""Curses terminal UI (standard library only, Unix-like systems).

    python3 -m antivirus tui

Windows note: CPython does not ship ``curses`` on Windows, so the TUI is
not available there — the CLI, GUI and web console all work.

Design: :class:`TuiModel` holds *all* state and logic (no curses import,
fully unit-testable headless); :func:`run_tui` is a thin curses renderer
that draws the model and forwards key presses.

Keys::

    s        start scan of the current target
    e        edit the target (type a path, Enter to confirm)
    j / k    or Down / Up        move selection through findings
    g / G    top / bottom of the findings list
    t        toggle fast mode
    a        cycle action (detect -> quarantine -> delete)
    f        enter an incremental-scan duration (e.g. 2h), empty clears
    ?        toggle help
    q        quit
"""
from __future__ import annotations

try:  # curses is part of the standard library on Unix-like systems only
    import curses
except ImportError:  # Windows
    curses = None  # type: ignore[assignment]

import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from . import __version__
from .web import WebApp

ACTIONS = ("detect", "quarantine", "kill", "delete")


class TuiModel:
    """State machine behind the TUI – curses-free and testable."""

    def __init__(self, app: WebApp, target: str = ".") -> None:
        self.app = app
        self.target = target
        self.action = "detect"
        self.fast = False
        self.since = ""
        self.job_id: Optional[str] = None
        self.selection = 0
        self.detail = False
        self.message = ""
        self.error = ""
        self.findings: List[Dict] = []
        self.log: List[str] = []
        self.help_open = False
        self.started_at: Optional[float] = None

    # ------------------------------------------------------------ properties
    @property
    def job(self) -> Optional[object]:
        return self.app.job(self.job_id) if self.job_id else None

    @property
    def running(self) -> bool:
        job = self.job
        return bool(job and job.status == "running")

    @property
    def done(self) -> bool:
        job = self.job
        return bool(job and job.status == "done")

    # -------------------------------------------------------------- commands
    def _log_line(self, line: str) -> None:
        self.log.append(f"{time.strftime('%H:%M:%S')}  {line}")
        del self.log[: len(self.log) - 200]

    def start_scan(self) -> None:
        if self.running:
            self.error = "a scan is already running"
            return
        target = Path(self.target)
        if not target.exists():
            self.error = f"no such file or directory: {target}"
            return
        try:
            job = self.app.start_scan(
                target, self.action,
                {"fast": self.fast, "since": self.since,
                 "no_archives": False, "no_behavior": False})
        except ValueError as exc:
            self.error = str(exc)
            return
        self.job_id = job.id
        self.findings = []
        self.selection = 0
        self.started_at = time.time()
        self.message = f"scanning {target} (action={self.action}) …"
        self._log_line(self.message)

    def tick(self) -> None:
        """Poll the current job (call once per UI frame)."""
        if not self.job_id:
            return
        detail = self.app.job_detail(self.job_id)
        if detail is None:
            return
        job = detail["job"]
        if job["status"] == "running":
            self.message = (
                f"scanning {job['files_scanned']} files, "
                f"{job['bytes_scanned'] / 1048576:.1f} MiB, "
                f"{job['findings']} finding(s) so far …")
            preview = detail.get("findings_preview", [])
            if len(preview) != len(self.findings):
                self.findings = preview
        elif job["status"] == "done":
            result = detail.get("result") or {}
            findings = result.get("findings", [])
            if findings != self.findings:
                self.findings = findings
                self.selection = min(self.selection, max(0, len(findings) - 1))
            elapsed = job["elapsed_seconds"]
            verdict = "CLEAN" if result.get("clean") else \
                f"INFECTED ({len(findings)} findings)"
            self.message = (f"done in {elapsed:.1f}s – {verdict}, "
                            f"{job['files_scanned']} files")
            self._log_line(self.message)
        else:  # error
            self.message = f"scan error: {job.get('error')}"
            self.error = self.message

    def move(self, delta: int) -> None:
        if not self.findings:
            return
        self.selection = (self.selection + delta) % len(self.findings)

    def top(self) -> None:
        self.selection = 0

    def bottom(self) -> None:
        if self.findings:
            self.selection = len(self.findings) - 1

    def page(self, delta: int) -> None:
        self.move(delta * 10)

    def toggle_detail(self) -> None:
        self.detail = not self.detail

    def toggle_help(self) -> None:
        self.help_open = not self.help_open

    def toggle_fast(self) -> None:
        self.fast = not self.fast
        self.message = f"fast mode {'on' if self.fast else 'off'}"

    def cycle_action(self) -> None:
        self.action = ACTIONS[(ACTIONS.index(self.action) + 1) % len(ACTIONS)]
        self.message = f"action: {self.action}"

    def set_since(self, value: str) -> None:
        from .utils import parse_since

        value = value.strip()
        if not value:
            self.since = ""
            self.message = "incremental scan: off"
            return
        try:
            parse_since(value)
        except ValueError as exc:
            self.error = str(exc)
            return
        self.since = value
        self.message = f"incremental scan: last {value}"

    # -------------------------------------------------------------- helpers
    @property
    def selected_finding(self) -> Optional[Dict]:
        if self.findings and 0 <= self.selection < len(self.findings):
            return self.findings[self.selection]
        return None

    @property
    def detail_text(self) -> str:
        f = self.selected_finding
        if not f:
            return ""
        return (f"{f.get('severity', '?').upper()}  {f.get('name', '?')}  "
                f"({f.get('kind', '?')})\n"
                f"file:   {f.get('path', '?')}\n"
                f"detail: {f.get('message', '')}")


_HELP = [
    "s  start scan            e  edit target",
    "j/k  move selection      g/G  top / bottom",
    "t  toggle fast mode      a  cycle action (detect/quarantine/delete)",
    "f  incremental window    ?  this help",
    "enter  finding detail    q  quit",
    "",
    "Findings are collected live while the scan runs.",
]


def run_tui(app: WebApp, target: str = ".") -> int:
    """Run the curses UI until the user quits. Returns the exit code."""
    if curses is None:  # pragma: no cover - Windows only
        print("error: the TUI needs curses, which Windows Python does not "
              "ship.\nUse the web console instead:  python3 -m antivirus web",
              file=sys.stderr)
        return 2
    model = TuiModel(app, target=target)

    def main(stdscr) -> int:
        curses.curs_set(0)
        stdscr.keypad(True)
        # Redraw at most every 500 ms even without key input, so live scan
        # progress (files / MiB / findings) updates on its own.
        stdscr.timeout(500)
        try:
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_RED, -1)
            curses.init_pair(2, curses.COLOR_CYAN, -1)
            curses.init_pair(3, curses.COLOR_YELLOW, -1)
            curses.init_pair(4, curses.COLOR_GREEN, -1)
            curses.init_pair(5, curses.COLOR_MAGENTA, -1)
            have_color = True
        except curses.error:
            have_color = False

        sev_colors = {
            "critical": 1, "high": 1, "medium": 3, "low": 4, "info": 5,
        }

        def color(sev: str) -> int:
            if not have_color:
                return -1
            return curses.color_pair(sev_colors.get(sev, 2))

        def put_line(scr, row: int, text: str, attr: int = -1) -> None:
            if row < 0:
                return
            scr.addnstr(row, 0, text, scr.getmaxyx()[1] - 1,
                        attr if attr != -1 else curses.A_NORMAL)

        while True:
            model.tick()
            height, width = stdscr.getmaxyx()
            stdscr.erase()

            # header
            opts = f"action={model.action}  fast={'on' if model.fast else 'off'}"
            if model.since:
                opts += f"  since={model.since}"
            put_line(stdscr, 0,
                     f" AntiVirus TUI v{__version__}   |   {opts}",
                     curses.A_BOLD)
            put_line(stdscr, 1,
                     f" target: {model.target}"
                     + ("   (scanning…)" if model.running else ""))
            put_line(stdscr, 2, model.message or "ready – press s to scan",
                     curses.A_DIM)

            top = 4
            if model.help_open:
                for i, line in enumerate(_HELP):
                    put_line(stdscr, top + i, line, curses.A_REVERSE)
                top += len(_HELP) + 2

            # findings list
            put_line(stdscr, top - 1,
                     f" findings ({len(model.findings)})", curses.A_BOLD)
            visible = max(0, height - top - 3)
            for i in range(visible):
                idx = model.selection + i
                if not model.findings or idx >= len(model.findings):
                    break
                f = model.findings[idx]
                mark = ">" if i == 0 else " "
                line = (f" {mark} [{f.get('severity', '?')[:8]:<8}] "
                        f"{f.get('name', '?')[:40]}  {f.get('path', '')}")
                put_line(stdscr, top + i, line, color(f.get("severity", "")))

            # detail / error / log strip
            put_line(stdscr, height - 3, "-" * max(0, width - 1), curses.A_DIM)
            if model.error:
                put_line(stdscr, height - 2, " " + model.error, curses.A_BOLD)
            elif model.detail:
                first = (model.detail_text or "(nothing selected)").splitlines(
                    )[:1]
                put_line(stdscr, height - 2, " " + (first[0] if first else ""))
            else:
                last_log = model.log[-1] if model.log else ""
                put_line(stdscr, height - 2,
                         f" {last_log}  ·  last 20 log lines kept"
                         if last_log else " ready")
            put_line(stdscr, height - 1,
                     " s scan   e target   j/k move   t fast   a action   "
                     "f since   ? help   q quit", curses.A_DIM)

            stdscr.refresh()

            try:
                ch = stdscr.getch()
            except curses.error:
                continue
            if ch == -1 or ch == getattr(curses, "KEY_ERR", -1):
                continue  # no input yet – loop back to redraw
            if ch in (ord("q"), 27):
                return 0
            elif ch in (ord("s"),):
                model.start_scan()
                model.error = ""
            elif ch in (ord("e"),):
                try:
                    stdscr.addstr(2, 0, f" target: {model.target} (Enter)   ")
                    stdscr.refresh()
                    raw = stdscr.getstr(3, 0, max(0, width - 1)).decode(
                        "utf-8", "replace")
                    if raw.strip():
                        model.target = raw.strip()
                        model.message = f"target: {model.target}"
                except curses.error:
                    pass
            elif ch in (ord("j"), curses.KEY_DOWN):
                model.move(1)
            elif ch in (ord("k"), curses.KEY_UP):
                model.move(-1)
            elif ch in (ord("g"),):
                model.top()
            elif ch in (ord("G"),):
                model.bottom()
            elif ch == curses.KEY_NPAGE:
                model.page(1)
            elif ch == curses.KEY_PPAGE:
                model.page(-1)
            elif ch in (ord("t"),):
                model.toggle_fast()
            elif ch in (ord("a"),):
                model.cycle_action()
            elif ch in (ord("f"),):
                try:
                    stdscr.addstr(2, 0, " since (e.g. 2h, Enter)          ")
                    stdscr.refresh()
                    raw = stdscr.getstr(3, 0, max(0, width - 1)).decode(
                        "utf-8", "replace")
                    model.set_since(raw)
                except curses.error:
                    pass
            elif ch in (ord("?"), ord("h")):
                model.toggle_help()
            elif ch in (10, 13, curses.KEY_ENTER):
                model.toggle_detail()

    try:
        return curses.wrapper(main)
    except (curses.error, OSError):
        print("error: the curses UI needs a real terminal "
              "(TTY). Use the CLI instead:\n"
              "  python3 -m antivirus scan .", flush=True)
        return 2


def tui_available() -> bool:
    """True when the curses UI can run on this platform (not on
    Windows: CPython does not bundle curses there)."""
    return curses is not None
