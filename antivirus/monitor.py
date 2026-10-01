"""A polling directory monitor: scans new and modified files as they appear.

A deliberate, dependency-free stand-in for inotify / watchdog based monitors:
every *interval* seconds a snapshot of the watched tree is compared with the
previous one and each new/changed file is scanned (and acted upon).

Efficiency: the snapshot walk is a single ``os.scandir`` pass where every
entry is ``lstat``-ed exactly once (results are cached by ``DirEntry``), and
bursts of changed files are scanned in parallel.  With ``cached_walk=True``
(used by the background guard) the walk is incremental: directories whose
``(mtime, size)`` are unchanged are not re-``scandir``-ed — their known
children are stat'ed directly, which keeps polling large trees cheap.
"""
from __future__ import annotations

import os
import stat
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from .config import Config
from .kill import KillRegistry
from .quarantine import Quarantine
from .scanner import Scanner, walk_files

LogFn = Callable[[str, str], None]
EventFn = Callable[[Dict], None]

_LEVEL_COLOR = {"ok": "32", "alert": "31", "error": "31", "warn": "33", "info": "36"}

#: Changed files above this number are scanned in parallel.
_PARALLEL_MIN = 4

#: A directory that *looks* unchanged (same mtime + size) is re-listed at
#: least this often (seconds).  Some filesystems quantise directory
#: timestamps (FAT uses 2 s; some virtual/overlay filesystems even finer
#: bursts collapse onto one value), so "directory mtime unchanged" alone is
#: not a bullet-proof proof that no entries appeared.  Re-listing keeps the
#: worst-case detection delay for such races bounded.
_REVALIDATE_SECONDS = 10.0


class DirectoryWatcher:
    def __init__(
        self,
        scanner: Scanner,
        quarantine: Quarantine,
        action: str = "detect",
        interval: float = 2.0,
        log: Optional[LogFn] = None,
        on_event: Optional[EventFn] = None,
        kill_registry: Optional["KillRegistry"] = None,
        cached_walk: bool = False,
        revalidate_after: float = _REVALIDATE_SECONDS,
    ) -> None:
        self.scanner = scanner
        self.quarantine = quarantine
        self.kill_registry = kill_registry
        self.action = action
        self.interval = max(float(interval), 0.1)
        self.log: LogFn = log or self._default_log
        #: Optional structured-event hook (JSON-friendly dicts) – used by
        #: ``monitor --json``. Events: ``removed``, ``clean``, ``threat``,
        #: ``quarantined``, ``deleted``, ``error``.
        self.on_event: Optional[EventFn] = on_event
        self._state: Dict[str, Tuple[float, int]] = {}
        #: Incremental (lightweight) walk: reuse per-directory listings when
        #: the directory itself is unchanged. Used by the background guard.
        self.cached_walk = cached_walk
        #: With ``cached_walk``, re-list a directory that *looks* unchanged
        #: at least this often (seconds) – guards against filesystems with
        #: coarse or lazily-updated directory timestamps. 0 = always re-list.
        self.revalidate_after = max(float(revalidate_after), 0.0)
        # dir path -> (mtime, size, {file: (mtime, size)}, [subdir, ...],
        #              monotonic time of the last full listing)
        self._dir_cache: Dict[
            str, Tuple[float, int, Dict[str, Tuple[float, int]], List[str],
                       float]] = {}

    def _emit(self, event: str, **fields) -> None:
        if self.on_event is None:
            return
        payload = {"event": event,
                   "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        payload.update(fields)
        try:
            self.on_event(payload)
        except Exception:
            pass  # a broken event hook must not stop the monitor

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
        current = (self._snapshot_cached(root) if self.cached_walk
                   else self._snapshot(root))
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
            self.process(self.poll(root))

    def process(self, poll_result: Tuple[List[Path], List[Path]]) -> None:
        """React to one poll: log removed files, scan changed ones.

        Exposed separately from :meth:`run` so tests (and embedders) can
        drive the watcher by hand.
        """
        changed, removed = poll_result
        for path in removed:
            self.log("info", f"removed : {path}")
            self._emit("removed", path=str(path))
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

    def _snapshot_cached(self, root: Path) -> Dict[str, Tuple[float, int]]:
        """Lightweight snapshot for long-running watches (the guard).

        A directory whose ``(mtime, size)`` matches the previous snapshot is
        assumed to have the same entries, so it is *not* re-``scandir``-ed –
        only its known children are stat'ed (to catch content changes).
        Directories that changed (or were first seen) are scanned normally.

        Because some filesystems update directory timestamps lazily or with
        coarse granularity, a directory can look unchanged right after an
        entry was added.  To keep the worst-case detection delay bounded, a
        directory that looks unchanged is still re-listed whenever its last
        full listing is older than ``revalidate_after`` seconds.  Returns the
        same ``{path: (mtime, size)}`` mapping as :meth:`_snapshot`.
        """
        config: Config = self.scanner.config
        protected = (config.quarantine_dir.resolve(), config.report_dir.resolve())
        state: Dict[str, Tuple[float, int]] = {}
        cache = self._dir_cache

        def _under(p: Path) -> bool:
            try:
                r = p.resolve()
            except OSError:
                return False
            return any(r == d or d in r.parents for d in protected)

        def visit(d: Path) -> None:
            try:
                st = d.lstat()
            except OSError:
                cache.pop(str(d), None)
                return
            if not stat.S_ISDIR(st.st_mode):
                return
            key = str(d)
            prev = cache.get(key)
            unchanged = (prev is not None and prev[0] == st.st_mtime
                         and prev[1] == st.st_size)
            if (unchanged and self.revalidate_after > 0.0
                    and time.monotonic() - prev[4] < self.revalidate_after):
                # Unchanged directory, still fresh: entries are known; stat
                # the children only (this is the lightweight fast path).
                files, subdirs = prev[2], prev[3]
                for name, _meta in files.items():
                    p = d / name
                    try:
                        fst = p.lstat()
                    except OSError:
                        continue  # vanished; will show up as "removed"
                    if stat.S_ISREG(fst.st_mode):
                        state[str(p)] = (fst.st_mtime, fst.st_size)
                for name in subdirs:
                    visit(d / name)
                return
            # New, changed, or due for revalidation: full scandir of this
            # level only.
            files: Dict[str, Tuple[float, int]] = {}
            subdirs: List[str] = []
            try:
                entries = list(os.scandir(d))
            except OSError:
                cache.pop(key, None)
                return
            for entry in entries:
                if entry.name in config.exclude_dir_set:
                    continue
                p = d / entry.name
                try:
                    est = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                mode = est.st_mode
                if stat.S_ISDIR(mode):
                    if not _under(p):
                        subdirs.append(entry.name)
                elif stat.S_ISREG(mode) and not stat.S_ISLNK(mode):
                    if not _under(p):
                        files[entry.name] = (est.st_mtime, est.st_size)
            cache[key] = (st.st_mtime, st.st_size, files, subdirs,
                          time.monotonic())
            for name, meta in files.items():
                state[str(d / name)] = meta
            for name in subdirs:
                visit(d / name)

        visit(Path(root))
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
            self._emit("clean", path=str(path))
            return
        worst = findings[0]
        self.log(
            "alert",
            f"THREAT [{worst.severity.upper()}] {worst.name}: {path} "
            f"({len(findings)} finding(s))",
        )
        self._emit("threat", path=str(path), severity=worst.severity,
                   name=worst.name, findings=len(findings))
        if self.action == "quarantine":
            try:
                item = self.quarantine.put(path, worst)
                self.log("ok", f"quarantined as {item.id}")
                self._emit("quarantined", path=str(path), id=item.id)
            except OSError as exc:
                self.log("error", f"quarantine failed: {exc}")
                self._emit("error", path=str(path), detail=str(exc))
        elif self.action == "kill":
            if self.kill_registry is None:
                self.log("error", "kill needs a registry (not configured)")
                self._emit("error", path=str(path), detail="no registry")
            else:
                try:
                    item = self.kill_registry.kill(path, worst)
                    self.log("ok", f"killed in place (registry: {item.id})")
                    self._emit("killed", path=str(path), id=item.id)
                except OSError as exc:
                    self.log("error", f"kill failed: {exc}")
                    self._emit("error", path=str(path), detail=str(exc))
        elif self.action == "delete":
            try:
                path.unlink()
                self.log("ok", "deleted")
                self._emit("deleted", path=str(path))
            except OSError as exc:
                self.log("error", f"delete failed: {exc}")
                self._emit("error", path=str(path), detail=str(exc))
