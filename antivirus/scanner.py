"""The scanning engine.

Detection layers
----------------
1. **Hash** – SHA-256 (plus MD5) of the whole file is compared against the
   signature database. A hit is treated as a definite match.
2. **Pattern** – regular expressions matched against the raw file bytes catch
   threats that are renamed, wrapped or only partially known.
3. **Heuristic** – a Shannon-entropy check flags large, high-entropy files
   that look packed or encrypted.

Efficiency notes
----------------
* A file is read from disk **once**: hashing, pattern matching and the
  entropy sample are all computed in a single streaming pass.
* All pattern signatures are merged into **one** compiled alternation, so
  each 1 MiB buffer is scanned once instead of once per signature.
* Every directory entry is ``lstat``-ed exactly once (``os.scandir``).
* Directory scans run in parallel threads (``hashlib`` releases the GIL
  while hashing) – see ``Scanner(..., threads=...)`` / ``scan --threads``.
* Compiled regexes and the signature indexes are cached and only rebuilt
  when the database version changes.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Tuple

from .behavior import analyze_file as behavior_analyze_file
from .behavior import looks_executable as behavior_looks_executable
from .config import Config
from .models import (  # noqa: F401  (re-exported for backwards compatibility)
    Finding,
    shannon_entropy,
    shannon_entropy_counts,
)
from .signatures import Signature, SignatureDB
from .utils import md5_new

LogFn = Callable[[Path, str], None]

#: A heuristic entropy verdict is only made from samples of at least this size.
_MIN_ENTROPY_SAMPLE = 16 * 1024


@dataclass
class ScanResult:
    """Aggregated outcome of scanning one file or directory tree."""

    target: str
    started_at: float
    finished_at: float = 0.0
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    errors: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    @property
    def elapsed(self) -> float:
        return max(self.finished_at - self.started_at, 0.0)

    @property
    def clean(self) -> bool:
        return not self.findings

    @property
    def worst_severity(self) -> str:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        if not self.findings:
            return "info"
        return min(self.findings, key=lambda f: order.get(f.severity, 9)).severity

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_seconds": round(self.elapsed, 3),
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "bytes_scanned": self.bytes_scanned,
            "errors": list(self.errors),
            "findings": [f.to_dict() for f in self.findings],
            "clean": self.clean,
        }


def _is_under(path: Path, dirs: Tuple[Path, ...]) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        return False
    return any(resolved == d or d in resolved.parents for d in dirs)


def walk_files(
    root: Path,
    exclude_dirs,
    protected: Tuple[Path, ...] = (),
    on_skip: Optional[LogFn] = None,
    on_file: Optional[Callable[[Path, os.stat_result], None]] = None,
) -> Iterator[Path]:
    """Walk *root* with ``os.scandir``, yielding regular files deterministically.

    Each entry is ``lstat``-ed exactly once (the result is cached by
    ``DirEntry``). ``on_skip(path, reason)`` reports symlinks / special
    files; ``on_file(path, lstat_result)`` hands the caller the already
    fetched stat so it never has to stat the file again.
    """
    exclude = set(exclude_dirs)
    resolve_cache: Dict[str, Path] = {}

    def _under(p: Path) -> bool:
        key = str(p)
        r = resolve_cache.get(key)
        if r is None:
            try:
                r = p.resolve()
            except OSError:
                r = p
            resolve_cache[key] = r
        return any(r == d or d in r.parents for d in protected)

    def _skip(p: Path, reason: str) -> None:
        if on_skip is not None:
            on_skip(p, reason)

    stack: List[Path] = [Path(root)]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        dirs: List[Path] = []
        files: List[Tuple[Path, os.stat_result]] = []
        for entry in entries:
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                _skip(Path(entry.path), str(exc))
                continue
            mode = st.st_mode
            if stat.S_ISLNK(mode):
                _skip(Path(entry.path), "symlink")
            elif stat.S_ISDIR(mode):
                if entry.name not in exclude and not _under(Path(entry.path)):
                    dirs.append(Path(entry.path))
            elif stat.S_ISREG(mode):
                files.append((Path(entry.path), st))
            else:
                _skip(Path(entry.path), "not a regular file")
        files.sort(key=lambda item: item[0].name)
        for p, st in files:
            if on_file is not None:
                on_file(p, st)
            yield p
        stack.extend(reversed(sorted(dirs)))


class Scanner:
    """Runs the three detection layers over files and directory trees."""

    def __init__(self, config: Config, db: SignatureDB, threads: "str | int" = "auto") -> None:
        self.config = config
        self.db = db
        self.threads = threads
        self._patterns: List[Tuple[Signature, "re.Pattern[bytes]"]] = []
        self._combined: Optional["re.Pattern[bytes]"] = None
        self._name_to_sig: Dict[str, Signature] = {}
        self._overlap = 64
        self._cached_version: Optional[int] = None

    # ------------------------------------------------------------- public API
    def scan_path(self, path: Path) -> ScanResult:
        """Scan a single file or an entire directory tree."""
        path = Path(path)
        result = ScanResult(target=str(path), started_at=time.time())
        self._sync_patterns()
        if path.is_file():
            try:
                st: Optional[os.stat_result] = path.lstat()
            except OSError as exc:
                result.errors.append(f"{path}: {exc}")
                result.finished_at = time.time()
                return result
            files: List[Tuple[Path, Optional[os.stat_result]]] = [(path, st)]
        elif path.is_dir():
            files = []
            protected = (self.config.quarantine_dir.resolve(),
                         self.config.report_dir.resolve())

            def _skipped(child: Path, reason: str) -> None:
                result.files_skipped += 1

            def _record(p: Path, st: os.stat_result) -> None:
                files.append((p, st))

            for _ in walk_files(path, self.config.exclude_dirs, protected,
                                on_skip=_skipped, on_file=_record):
                pass
        else:
            result.errors.append(f"{path}: not a regular file or directory")
            result.finished_at = time.time()
            return result

        workers = self._workers()
        if len(files) > 1 and workers > 1:
            self._scan_files_parallel(files, result, workers)
        else:
            for p, st in files:
                self._scan_file(p, result, st=st)

        if len(result.findings) > 1:
            result.findings.sort(key=lambda f: (f.path, f.kind))
        result.finished_at = time.time()
        return result

    def scan_file(self, path: Path) -> List[Finding]:
        """Scan one file and return its findings (used by the monitor)."""
        result = ScanResult(target=str(path), started_at=time.time())
        self._sync_patterns()
        self._scan_file(Path(path), result)
        result.finished_at = time.time()
        return result.findings

    # ------------------------------------------------------------ threading
    def _workers(self) -> int:
        """Resolve the configured worker count (1 = fully sequential)."""
        t = self.threads
        if t in (0, 1, "off", "0", "1", False, None):
            return 1
        if t == "auto":
            return min(8, max(1, (os.cpu_count() or 1) * 2))
        try:
            return max(1, int(t))
        except (TypeError, ValueError):
            return 1

    def _scan_files_parallel(self, files: List[Tuple[Path, Optional[os.stat_result]]],
                             result: ScanResult, workers: int) -> None:
        def work(item: Tuple[Path, Optional[os.stat_result]]) -> ScanResult:
            p, st = item
            local = ScanResult(target=str(p), started_at=0.0)
            self._scan_file(p, local, st=st)
            return local

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="av-scan") as pool:
            for local in pool.map(work, files, chunksize=16):
                result.files_scanned += local.files_scanned
                result.files_skipped += local.files_skipped
                result.bytes_scanned += local.bytes_scanned
                if local.errors:
                    result.errors.extend(local.errors)
                if local.findings:
                    result.findings.extend(local.findings)

    # ------------------------------------------------------------ internals
    def _sync_patterns(self) -> None:
        """Rebuild the merged pattern regex when the signature DB changed."""
        if self._cached_version == self.db.version:
            return
        self._patterns = []
        self._name_to_sig = {}
        self._combined = None
        for sig in self.db.list():
            compiled = sig.compiled
            if compiled is not None:
                self._patterns.append((sig, compiled))
        if self._patterns:
            parts = []
            for i, (sig, _rx) in enumerate(self._patterns):
                name = f"av_sig_{i}"
                self._name_to_sig[name] = sig
                parts.append(f"(?P<{name}>{sig.pattern})")
            try:
                self._combined = re.compile("|".join(parts).encode("utf-8"))
            except re.error:
                self._combined = None  # fall back to per-pattern searches
        self._overlap = max((len(s.pattern) for s, _ in self._patterns), default=0) * 3 + 64
        self._cached_version = self.db.version

    def _match_patterns(self, buf: bytes) -> List[Signature]:
        """Which signatures match *buf* – one combined pass per chunk."""
        hits: List[Signature] = []
        if self._combined is not None:
            for m in self._combined.finditer(buf):
                name = m.lastgroup
                sig = None
                if name is not None and name in self._name_to_sig and m.group(name) is not None:
                    sig = self._name_to_sig[name]
                else:  # lastgroup may be an internal group of the user pattern
                    for n, s in self._name_to_sig.items():
                        if m.group(n) is not None:
                            sig = s
                            break
                if sig is not None and sig not in hits:
                    hits.append(sig)
        else:
            for sig, rx in self._patterns:
                if rx.search(buf) and sig not in hits:
                    hits.append(sig)
        return hits

    def _scan_file(self, path: Path, result: ScanResult,
                   st: Optional[os.stat_result] = None) -> None:
        if st is None:
            try:
                st = path.lstat()
            except OSError as exc:
                result.errors.append(f"{path}: {exc}")
                return
        size = st.st_size

        if size > self.config.max_file_size:
            result.files_skipped += 1
            result.errors.append(f"{path}: skipped ({size} bytes > max_file_size)")
            return

        try:
            sha256, md5, partial, pattern_hits, entropy, content = \
                self._stream_file(path, size)
        except OSError as exc:
            result.errors.append(f"{path}: {exc}")
            return

        result.files_scanned += 1
        result.bytes_scanned += size

        # NOTE: verdicts are collected in a *per-file* list.  The heuristic
        # guard must never look at ``result.findings`` – that list is shared
        # by the whole tree scan, so findings from earlier files would
        # silently suppress heuristics for every later file.
        local: List[Finding] = []

        # Layer 1 – exact hash match (definite).
        if not partial:
            signature = self.db.by_sha256(sha256)
            if signature is None:
                signature = self.db.by_md5(md5)
            if signature is not None:
                message = f"Matches signature '{signature.id}'"
                if signature.description:
                    message += f" ({signature.description})"
                local.append(Finding(
                    path=str(path),
                    kind="signature-hash",
                    name=signature.name,
                    severity=signature.severity,
                    message=message,
                    sha256=sha256,
                    size=size,
                ))
                result.findings.extend(local)  # definite match – stop here
                return

        # Layer 2 – pattern matches found in the same pass.
        for sig in pattern_hits:
            local.append(Finding(
                path=str(path),
                kind="signature-pattern",
                name=sig.name,
                severity=sig.severity,
                message=f"Pattern of signature '{sig.id}' found in file body",
                sha256=sha256,
                size=size,
            ))

        # Layer 2.5 – behavioural analysis (what the file appears to do).
        # Only files that look executable are examined; the content was
        # already buffered during the single read pass above.
        if (
            self.config.behavior_enabled
            and content is not None
            and behavior_looks_executable(path, content)
        ):
            local.extend(behavior_analyze_file(path, st, content))

        # Layer 3 – heuristics (only if this file has no definite hit yet).
        if not local and entropy is not None and entropy >= self.config.entropy_threshold:
            local.append(Finding(
                path=str(path),
                kind="heuristic",
                name="High-Entropy",
                severity="medium",
                message=(
                    f"Shannon entropy {entropy:.2f} bits/byte "
                    f"(threshold {self.config.entropy_threshold}); file may be packed or encrypted"
                ),
                sha256=sha256,
                size=size,
            ))

        result.findings.extend(local)

    def _stream_file(self, path: Path, size: int):
        """Read the file **once**, computing everything in one pass.

        Returns ``(sha256, md5, partial, pattern_hits, entropy_or_None,
        content_or_None)`` – *content* is kept in memory only for files up
        to ``behavior_max_size`` so the behavioural layer needs no extra
        disk reads.
        """
        cfg = self.config
        sha = hashlib.sha256()
        md5 = md5_new()
        need_entropy = size >= cfg.entropy_min_size
        buffer_content = size <= cfg.behavior_max_size
        counts: Optional["Counter"] = Counter() if need_entropy else None
        sampled = 0
        hits: List[Signature] = []
        remaining = list(self._patterns)
        tail = b""
        overlap = self._overlap
        content = b""
        read = 0
        with open(path, "rb") as fh:
            while read < size:
                chunk = fh.read(cfg.hash_chunk_size)
                if not chunk:
                    break
                read += len(chunk)
                sha.update(chunk)
                md5.update(chunk)
                if buffer_content:
                    content += chunk
                if remaining:
                    buf = tail + chunk
                    matched = self._match_patterns(buf)
                    if matched:
                        for sig in matched:
                            if sig not in hits:
                                hits.append(sig)
                        remaining = [pr for pr in remaining if pr[0] not in hits]
                    tail = buf[-overlap:] if remaining else b""
                if counts is not None and sampled < cfg.entropy_sample_size:
                    take = chunk[: cfg.entropy_sample_size - sampled]
                    counts.update(take)
                    sampled += len(take)
        entropy = None
        if counts is not None and sampled >= _MIN_ENTROPY_SAMPLE:
            entropy = shannon_entropy_counts(counts, sampled)
        return (
            sha.hexdigest(),
            md5.hexdigest(),
            read < size,
            hits,
            entropy,
            content if buffer_content else None,
        )
