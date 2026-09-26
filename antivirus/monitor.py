"""A polling directory monitor: scans new and modified files as they appear.

A deliberate, dependency-free stand-in for inotify / watchdog based monitors:
every *interval* seconds a snapshot of the watched tree is compared with the
previous one and each new/changed file is scanned (and acted upon).

Efficiency: the snapshot walk is a single ``os.scandir`` pass where every
entry is ``lstat``-ed exactly once (results are cached by ``DirEntry``), and
bursts of changed files are scanned in parallel.
"""
from __future__ import annotations

import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from .config import Config
from .quarantine import Quarantine
from .scanner import Scanner, walk_files

LogFn = Callable[[str, str], None]

_LEVEL_COLOR = {"ok": "32", "alert": "31", "error": "31", "warn": "33", "info": "36"}

#: Changed files above this number are scanned in parallel.
_PARALLEL_MIN = 4


class DirectoryWatcher:
    def __init__(
        self,
        scanner: Scanner,
        quarantine: Quarantine,
        action: str = "detect",
        interval: float = 2.0,
        log: Optional[LogFn] = None,
    ) -> None:
        self.scanner = scanner
        self.quarantine = quarantine
        self.action = action
        self.interval = max(float(interval), 0.1)
        self.log: LogFn = log or self._default_log
        self._state: Dict[str, Tuple[float, int]] = {}

    @staticmethod
    def _default_log(level: str, message: str) -> None:
        line = f"[{time.strftime('%H:%M:%S')}] {message}"
        if sys.stdout.isatty():
            color = _LEVEL_COLOR.get(level, "0")
            print(f"\033[{color}m{line}\033[0m", flush=True)
        else:
            print(line, flush=True)

    # ------------------------------------------------------------- public API
    def poll(self, root: Path) -> Tuple[List[Path], List[Path]]:
        """Return ``(new_or_changed, removed)`` since the previous poll."""
        previous = self._state
        current = self._snapshot(root)
        self._state = current
        changed = [
            Path(p) for p, meta in current.items()
            if p not in previous or previous[p] != meta
        ]
        removed = [Path(p) for p in previous if p not in current]
        return changed, removed

    def run(self, root: Path) -> None:
        """Block forever (until Ctrl+C), scanning new/changed files."""
        root = Path(root)
        self._state = self._snapshot(root)
        self.log(
            "info",
            f"watching {root} every {self.interval:g}s (action={self.action}); "
            f"press Ctrl+C to stop",
        )
        while True:
            time.sleep(self.interval)
            changed, removed = self.poll(root)
            for path in removed:
                self.log("info", f"removed : {path}")
            if changed:
                self._handle(changed)

    # ------------------------------------------------------------ internals
    def _snapshot(self, root: Path) -> Dict[str, Tuple[float, int]]:
        config: Config = self.scanner.config
        protected = (config.quarantine_dir.resolve(), config.report_dir.resolve())
        state: Dict[str, Tuple[float, int]] = {}

        def _record(p: Path, st) -> None:
            state[str(p)] = (st.st_mtime, st.st_size)

        for _ in walk_files(root, config.exclude_dirs, protected,
                            on_file=_record, min_mtime=config.since_ts):
            pass
        return state

    def _handle(self, paths: List[Path]) -> None:
        """Scan the changed files (in parallel for bursts), then act on them."""
        if len(paths) >= _PARALLEL_MIN:
            with ThreadPoolExecutor(max_workers=min(8, len(paths)),
                                    thread_name_prefix="av-watch") as pool:
                results = list(pool.map(self.scanner.scan_file, paths, chunksize=1))
        else:
            results = [self.scanner.scan_file(p) for p in paths]
        for path, findings in zip(paths, results):
            self._act(path, findings)

    def _act(self, path: Path, findings: List) -> None:
        if not findings:
            self.log("ok", f"clean   : {path}")
            return
        worst = findings[0]
        self.log(
            "alert",
            f"THREAT [{worst.severity.upper()}] {worst.name}: {path} "
            f"({len(findings)} finding(s))",
        )
        if self.action == "quarantine":
            try:
                item = self.quarantine.put(path, worst)
                self.log("ok", f"quarantined as {item.id}")
            except OSError as exc:
                self.log("error", f"quarantine failed: {exc}")
        elif self.action == "delete":
            try:
                path.unlink()
                self.log("ok", "deleted")
            except OSError as exc:
                self.log("error", f"delete failed: {exc}")
