"""Scan cache – the engine's memory of previous scans.

Real antivirus products separate a *full scan* from a *fast rescan*: files
that have not changed do not need to be re-read. This module implements the
rescan side with a small JSON cache (no third-party dependencies):

* Key:   absolute file path.
* Entry: ``[size, mtime_ns, [[kind, name, severity, message], ...]]``.
* A cached verdict is reused **without reading the file at all** when the
  size *and* mtime match and the engine profile (signature-database version,
  behaviour/entropy/archive settings, max size) is unchanged.

The cache is an optimisation, not a security boundary: it lives inside the
scanned tree's working directory, is written atomically, and is ignored for
files whose metadata changed. Use ``--no-cache`` to bypass it.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .models import Finding

_CACHE_VERSION = 1


class ScanCache:
    """In-memory cache with a JSON on-disk backing file."""

    def __init__(self, path: Path, profile: dict) -> None:
        self.path = Path(path)
        self.profile = profile
        self.entries: Dict[str, Tuple[int, int, List[List[str]]]] = {}

    # ------------------------------------------------------------------ load
    @classmethod
    def load(cls, path: Path, profile: dict) -> "ScanCache":
        """Load *path*; a missing or incompatible cache yields a fresh one.

        A fresh cache is still used for *recording* this run's verdicts, so
        the first scan is what builds the cache for later fast rescans.
        """
        cache = cls(path, profile)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cache
        if data.get("version") != _CACHE_VERSION or data.get("profile") != profile:
            return cache  # engine settings or signature DB changed – restart
        for key, value in (data.get("entries") or {}).items():
            try:
                size, mtime_ns, findings = value
                norm = [list(item) for item in findings]
            except (TypeError, ValueError):
                continue
            cache.entries[str(key)] = (int(size), int(mtime_ns), norm)
        return cache

    # ------------------------------------------------------------------ query
    def get(self, path: str, size: int, mtime_ns: int) -> Optional[List[Finding]]:
        """Cached findings for *path*, or ``None`` when stale/absent."""
        entry = self.entries.get(path)
        if entry is None:
            return None
        c_size, c_mtime, findings = entry
        if c_size != size or c_mtime != mtime_ns:
            return None
        return [Finding(path=path, kind=k, name=n, severity=s, message=m)
                for k, n, s, m in findings]

    def put(self, path: str, size: int, mtime_ns: int,
            findings: List[Finding]) -> None:
        self.entries[path] = (int(size), int(mtime_ns),
                              [[f.kind, f.name, f.severity, f.message]
                               for f in findings])

    # ------------------------------------------------------------------- save
    def save(self) -> bool:
        """Atomically persist the cache; returns True on success."""
        payload = {
            "version": _CACHE_VERSION,
            "profile": self.profile,
            "entries": {
                p: [size, mtime, findings]
                for p, (size, mtime, findings) in self.entries.items()
            },
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=self.path.name + ".",
                                       dir=str(self.path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, ensure_ascii=False, separators=(",", ":"))
                os.replace(tmp, self.path)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            return True
        except OSError:
            return False
