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

import fnmatch
import hashlib
import os
import re
import stat
import time
import zipfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Tuple

from .behavior import analyze_file as behavior_analyze_file
from .behavior import looks_executable as behavior_looks_executable
from .cache import ScanCache
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
    files_cached: int = 0
    bytes_scanned: int = 0
    errors: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    #: Per-file verdicts actually produced by this run (internal – used to
    #: feed the scan cache; not serialized by ``to_dict``).
    scanned_paths: Dict[str, List[Finding]] = field(default_factory=dict)

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
            "files_cached": self.files_cached,
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
    exclude_patterns: Tuple[str, ...] = (),
) -> Iterator[Path]:
    """Walk *root* with ``os.scandir``, yielding regular files deterministically.

    Each entry is ``lstat``-ed exactly once (the result is cached by
    ``DirEntry``). ``on_skip(path, reason)`` reports symlinks / special
    files; ``on_file(path, lstat_result)`` hands the caller the already
    fetched stat so it never has to stat the file again.
    ``exclude_patterns`` are fnmatch globs matched against the file name and
    the path relative to *root*.
    """
    exclude = set(exclude_dirs)
    patterns = [p for p in exclude_patterns if p]
    root_str = str(root)

    def _excluded(p: Path) -> bool:
        if not patterns:
            return False
        rel = str(p)[len(root_str) + 1:] if str(p).startswith(root_str + os.sep) else p.name
        for pat in patterns:
            if fnmatch.fnmatch(p.name, pat) or fnmatch.fnmatch(rel, pat):
                return True
        return False

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
                if _under(Path(entry.path)):
                    _skip(Path(entry.path), "protected")
                elif _excluded(Path(entry.path)):
                    _skip(Path(entry.path), "excluded by pattern")
                else:
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
        """Scan a single file or an entire directory tree.

        When the scan cache is enabled, files whose size *and* mtime are
        unchanged (and whose engine profile matches) reuse their previous
        verdict without being read from disk at all.
        """
        path = Path(path)
        result = ScanResult(target=str(path), started_at=time.time())
        self._sync_patterns()
        cache: Optional[ScanCache] = None
        if self.config.cache_enabled:
            cache = ScanCache.load(self.config.cache_dir, self._cache_profile())
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
            if self.config.cache_enabled:
                # never scan our own runtime artefacts
                protected = protected + (self.config.cache_dir.resolve(),)

            def _skipped(child: Path, reason: str) -> None:
                result.files_skipped += 1

            def _record(p: Path, st: os.stat_result) -> None:
                files.append((p, st))

            for _ in walk_files(path, self.config.exclude_dirs, protected,
                                on_skip=_skipped, on_file=_record,
                                exclude_patterns=self.config.exclude_patterns):
                pass
        else:
            result.errors.append(f"{path}: not a regular file or directory")
            result.finished_at = time.time()
            return result

        # Cache partition: unchanged files keep their previous verdict.
        to_scan: List[Tuple[Path, Optional[os.stat_result]]] = []
        if cache is not None:
            for p, st in files:
                if st is None:
                    to_scan.append((p, st))
                    continue
                cached = cache.get(str(p), st.st_size, st.st_mtime_ns)
                if cached is not None:
                    result.files_scanned += 1
                    result.files_cached += 1
                    result.bytes_scanned += st.st_size
                    if cached:
                        result.findings.extend(cached)
                    result.scanned_paths[str(p)] = cached
                else:
                    to_scan.append((p, st))
            files = to_scan

        workers = self._workers()
        if len(files) > 1 and workers > 1:
            self._scan_files_parallel(files, result, workers)
        else:
            for p, st in files:
                self._scan_file(p, result, st=st)

        # Record fresh verdicts for the next (fast) scan.
        if cache is not None and result.scanned_paths:
            self._record_cache(cache, result)

        if len(result.findings) > 1:
            result.findings.sort(key=lambda f: (f.path, f.kind))
        result.finished_at = time.time()
        return result

    def _cache_profile(self) -> dict:
        """Everything that influences a verdict – the cache's validity key."""
        cfg = self.config
        return {
            "db_version": self.db.version,
            "behavior": cfg.behavior_enabled,
            "fast": cfg.fast_mode,
            "archives": cfg.archives_enabled,
            "entropy_threshold": cfg.entropy_threshold,
            "max_file_size": cfg.max_file_size,
        }

    def _record_cache(self, cache: ScanCache, result: ScanResult) -> None:
        """Store this run's per-file verdicts and persist the cache."""
        cfg = self.config
        base = Path(result.target)
        for path_str, findings in result.scanned_paths.items():
            p = Path(path_str)
            try:
                st = p.lstat()
            except OSError:
                continue
            cache.put(path_str, st.st_size, st.st_mtime_ns, findings)
        cache.save()

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
                if local.scanned_paths:
                    result.scanned_paths.update(local.scanned_paths)

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
                result.scanned_paths[str(path)] = local
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
        # Fast mode skips this layer and the entropy heuristic.
        if (
            self.config.behavior_enabled
            and not self.config.fast_mode
            and content is not None
            and behavior_looks_executable(path, content)
        ):
            local.extend(behavior_analyze_file(path, st, content))

        # Layer 2.75 – archive contents (ZIP entries, analysed in memory).
        if (
            self.config.archives_enabled
            and size <= self.config.archive_max_size
        ):
            head = content[:4] if content is not None else self._peek_bytes(path, 4)
            if head == b"PK\x03\x04":
                local.extend(self._scan_zip(path, size))

        # Layer 3 – heuristics (only if this file has no definite hit yet).
        if (
            not local
            and not self.config.fast_mode
            and entropy is not None
            and entropy >= self.config.entropy_threshold
        ):
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
        result.scanned_paths[str(path)] = local

    # ----------------------------------------------------------- in-memory
    @staticmethod
    def _peek_bytes(path: Path, n: int) -> bytes:
        try:
            with open(path, "rb") as fh:
                return fh.read(n)
        except OSError:
            return b""

    def scan_buffer(self, name: str, data: bytes) -> List[Finding]:
        """Run all layers over in-memory *data* (used for archive entries).

        *name* is only used for the executable-looking gate and for
        reporting (e.g. ``archive.zip!entry.py``); *data* is analysed, never
        written to disk.
        """
        cfg = self.config
        if not data or len(data) > cfg.max_file_size:
            return []
        self._sync_patterns()
        p = Path(name)
        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        local: List[Finding] = []

        signature = self.db.by_sha256(sha256) or self.db.by_md5(md5)
        if signature is not None:
            message = f"Matches signature '{signature.id}'"
            if signature.description:
                message += f" ({signature.description})"
            local.append(Finding(
                path=name, kind="signature-hash", name=signature.name,
                severity=signature.severity, message=message,
                sha256=sha256, size=len(data),
            ))
            return local

        for sig in self._match_patterns(data):
            local.append(Finding(
                path=name, kind="signature-pattern", name=sig.name,
                severity=sig.severity,
                message=f"Pattern of signature '{sig.id}' found in file body",
                sha256=sha256, size=len(data),
            ))

        if (
            cfg.behavior_enabled
            and not cfg.fast_mode
            and len(data) <= cfg.behavior_max_size
            and behavior_looks_executable(p, data)
        ):
            local.extend(behavior_analyze_file(p, None, data))

        if (
            not local
            and not cfg.fast_mode
            and len(data) >= cfg.entropy_min_size
        ):
            entropy = shannon_entropy(data[: cfg.entropy_sample_size])
            if entropy >= cfg.entropy_threshold:
                local.append(Finding(
                    path=name, kind="heuristic", name="High-Entropy",
                    severity="medium",
                    message=(
                        f"Shannon entropy {entropy:.2f} bits/byte "
                        f"(threshold {cfg.entropy_threshold}); file may be packed or encrypted"
                    ),
                    sha256=sha256, size=len(data),
                ))
        return local

    # --------------------------------------------------------------- archives
    def _scan_zip(self, path: Path, size: int) -> List[Finding]:
        """Examine the entries of a ZIP archive (in memory, never extracted).

        Guards against the usual archive tricks: absolute/".." entry names
        (zip slip), password-protected entries, entry caps and an overall
        expansion budget (zip bombs).
        """
        cfg = self.config
        out: List[Finding] = []
        try:
            zf = zipfile.ZipFile(str(path))
        except (zipfile.BadZipFile, OSError, ValueError):
            return out
        with zf:
            entries_read = 0
            for i, info in enumerate(zf.infolist()):
                if i >= cfg.archive_entries_max:
                    out.append(Finding(
                        path=str(path), kind="archive",
                        name="Archive entry limit exceeded", severity="medium",
                        message=f"more than {cfg.archive_entries_max} entries",
                    ))
                    break
                if info.is_dir():
                    continue
                label = f"{path}!{info.filename}"
                if (
                    info.filename.startswith(("/", "\\"))
                    or ".." in Path(info.filename).parts
                ):
                    out.append(Finding(
                        path=str(path), kind="archive",
                        name="Archive path traversal (zip slip)", severity="medium",
                        message=f"entry {info.filename!r} escapes the archive root",
                    ))
                    continue
                if info.flag_bits & 0x1:
                    out.append(Finding(
                        path=str(path), kind="archive",
                        name="Encrypted archive entry", severity="low",
                        message=f"entry {info.filename!r} is password-protected",
                    ))
                    continue
                if entries_read > cfg.archive_expansion_max:
                    out.append(Finding(
                        path=str(path), kind="archive",
                        name="Archive expansion limit exceeded", severity="medium",
                        message="total entry size exceeds the analysis budget",
                    ))
                    break
                want = cfg.archive_entry_max
                if 0 <= info.file_size < want:
                    want = info.file_size
                try:
                    with zf.open(info, "r") as fh:
                        data = fh.read(want)
                except (zipfile.BadZipFile, RuntimeError, OSError, ValueError):
                    continue
                if not data:
                    continue
                entries_read += len(data)
                out.extend(self.scan_buffer(label, data))
        return out

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
