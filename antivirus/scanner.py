"""The scanning engine.

Detection layers
----------------
1. **Hash** – SHA-256 (plus MD5) of the whole file is compared against the
   signature database. A hit is treated as a definite match.
2. **Pattern** – regular expressions matched against the raw file bytes catch
   threats that are renamed, wrapped or only partially known.
3. **Heuristic** – a Shannon-entropy check flags large, high-entropy files
   that look packed or encrypted.

Layers 2 and 3 are skipped once layer 1 produced a definite match.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import stat
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterator, List, Optional, Tuple

from .config import Config
from .signatures import Signature, SignatureDB
from .utils import md5_new

LogFn = Callable[[Path, str], None]


@dataclass
class Finding:
    """One problem found in one file."""

    path: str
    kind: str          # "signature-hash" | "signature-pattern" | "heuristic"
    name: str
    severity: str
    message: str
    sha256: str = ""
    size: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


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


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of *data* in bits per byte (0 .. 8)."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


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
) -> Iterator[Path]:
    """Yield regular files under *root* in a deterministic order.

    Symlinks and non-regular files are skipped (and reported via *on_skip*),
    directory names in *exclude_dirs* are pruned, and nothing under
    *protected* (e.g. the quarantine itself) is ever visited.
    """
    exclude = set(exclude_dirs)

    def _skip(child: Path, reason: str) -> None:
        if on_skip is not None:
            on_skip(child, reason)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        keep = []
        for name in dirnames:
            child = Path(dirpath) / name
            if name in exclude:
                continue
            if _is_under(child, protected):
                continue
            keep.append(name)
        dirnames[:] = sorted(keep)
        for name in sorted(filenames):
            child = Path(dirpath) / name
            try:
                if child.is_symlink():
                    _skip(child, "symlink")
                    continue
                if not stat.S_ISREG(child.lstat().st_mode):
                    _skip(child, "not a regular file")
                    continue
            except OSError as exc:
                _skip(child, str(exc))
                continue
            yield child


class Scanner:
    """Runs the three detection layers over files and directory trees."""

    def __init__(self, config: Config, db: SignatureDB) -> None:
        self.config = config
        self.db = db
        self._patterns: List[Tuple[Signature, "re.Pattern[bytes]"]] = []
        self._overlap = 64
        self._cached_version: Optional[int] = None

    # ------------------------------------------------------------- public API
    def scan_path(self, path: Path) -> ScanResult:
        """Scan a single file or an entire directory tree."""
        path = Path(path)
        result = ScanResult(target=str(path), started_at=time.time())
        self._sync_patterns()
        if path.is_file():
            self._scan_file(path, result)
        elif path.is_dir():
            for file_path in self._iter_files(path, result):
                self._scan_file(file_path, result)
        else:
            result.errors.append(f"{path}: not a regular file or directory")
        result.finished_at = time.time()
        return result

    def scan_file(self, path: Path) -> List[Finding]:
        """Scan one file and return its findings (used by the monitor)."""
        result = ScanResult(target=str(path), started_at=time.time())
        self._sync_patterns()
        self._scan_file(Path(path), result)
        result.finished_at = time.time()
        return result.findings

    # ------------------------------------------------------------ internals
    def _sync_patterns(self) -> None:
        """Rebuild compiled patterns when the signature DB changed."""
        if self._cached_version == self.db.version:
            return
        self._patterns = []
        for sig in self.db.list():
            compiled = sig.compiled
            if compiled is not None:
                self._patterns.append((sig, compiled))
        self._overlap = max((len(s.pattern) for s, _ in self._patterns), default=0) * 3 + 64
        self._cached_version = self.db.version

    def _iter_files(self, root: Path, result: ScanResult) -> Iterator[Path]:
        config = self.config
        protected = (config.quarantine_dir.resolve(), config.report_dir.resolve())

        def _skipped(child: Path, reason: str) -> None:
            result.files_skipped += 1

        for file_path in walk_files(root, config.exclude_dirs, protected, on_skip=_skipped):
            yield file_path

    def _scan_file(self, path: Path, result: ScanResult) -> None:
        try:
            size = path.stat().st_size
        except OSError as exc:
            result.errors.append(f"{path}: {exc}")
            return

        if size > self.config.max_file_size:
            result.files_skipped += 1
            result.errors.append(f"{path}: skipped ({size} bytes > max_file_size)")
            return

        result.files_scanned += 1
        result.bytes_scanned += size

        try:
            sha256, md5, partial = self._hash_file(path, size)
        except OSError as exc:
            result.errors.append(f"{path}: {exc}")
            return

        # Layer 1 – exact hash match.
        if not partial:
            signature = self.db.by_sha256(sha256)
            if signature is None:
                signature = self.db.by_md5(md5)
            if signature is not None:
                message = f"Matches signature '{signature.id}'"
                if signature.description:
                    message += f" ({signature.description})"
                result.findings.append(Finding(
                    path=str(path),
                    kind="signature-hash",
                    name=signature.name,
                    severity=signature.severity,
                    message=message,
                    sha256=sha256,
                    size=size,
                ))
                return  # definite match – no noisier layers needed

        # Layer 2 – pattern match in the file body.
        result.findings.extend(self._pattern_findings(path, sha256, size))

        # Layer 3 – heuristics (only if nothing definite was found).
        if not result.findings:
            result.findings.extend(self._heuristic_findings(path, sha256, size))

    def _hash_file(self, path: Path, size: int) -> Tuple[str, str, bool]:
        """Stream the file through SHA-256 and MD5. Returns partial flag."""
        sha = hashlib.sha256()
        md5 = md5_new()
        limit = min(size, self.config.max_file_size)
        read = 0
        with open(path, "rb") as fh:
            while read < limit:
                chunk = fh.read(self.config.hash_chunk_size)
                if not chunk:
                    break
                sha.update(chunk)
                md5.update(chunk)
                read += len(chunk)
        return sha.hexdigest(), md5.hexdigest(), read < size

    def _pattern_findings(self, path: Path, sha256: str, size: int) -> List[Finding]:
        findings: List[Finding] = []
        pending = list(self._patterns)
        if not pending or size == 0:
            return findings
        tail = b""
        try:
            with open(path, "rb") as fh:
                while pending:
                    chunk = fh.read(self.config.pattern_chunk_size)
                    if not chunk:
                        break
                    buf = tail + chunk
                    still = []
                    for sig, regex in pending:
                        if regex.search(buf):
                            findings.append(Finding(
                                path=str(path),
                                kind="signature-pattern",
                                name=sig.name,
                                severity=sig.severity,
                                message=f"Pattern of signature '{sig.id}' found in file body",
                                sha256=sha256,
                                size=size,
                            ))
                        else:
                            still.append((sig, regex))
                    pending = still
                    tail = buf[-self._overlap:]
        except OSError:
            pass
        return findings

    def _heuristic_findings(self, path: Path, sha256: str, size: int) -> List[Finding]:
        cfg = self.config
        if size < cfg.entropy_min_size:
            return []
        sample = self._read_sample(path, cfg.entropy_sample_size)
        if len(sample) < 16 * 1024:
            return []
        entropy = shannon_entropy(sample)
        if entropy >= cfg.entropy_threshold:
            return [Finding(
                path=str(path),
                kind="heuristic",
                name="High-Entropy",
                severity="medium",
                message=(
                    f"Shannon entropy {entropy:.2f} bits/byte "
                    f"(threshold {cfg.entropy_threshold}); file may be packed or encrypted"
                ),
                sha256=sha256,
                size=size,
            )]
        return []

    def _read_sample(self, path: Path, limit: int) -> bytes:
        parts: List[bytes] = []
        total = 0
        try:
            with open(path, "rb") as fh:
                while total < limit:
                    chunk = fh.read(self.config.hash_chunk_size)
                    if not chunk:
                        break
                    parts.append(chunk)
                    total += len(chunk)
        except OSError:
            pass
        return b"".join(parts)[:limit]
