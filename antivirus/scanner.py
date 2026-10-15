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
import gzip
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import time
import zipfile
import zlib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Tuple

from .behavior import analyze_file as behavior_analyze_file
from .behavior import looks_executable as behavior_looks_executable
from . import allowlist as allowlist_mod
from . import feeds as feeds_mod
from . import indicators as indicators_mod
from . import metrics as metrics_mod
from .cache import ScanCache
from .config import Config
from . import obfuscation as obfuscation_mod
from . import polyglot as polyglot_mod
from . import risk as risk_mod
from . import webshield as webshield_mod
# NOTE: .integrity is imported *inside* the methods that need it – it
# imports walk_files from this module, so a top-level import would be a
# cycle.
from .webshield import ThreatIntel
from .models import (  # noqa: F401  (re-exported for backwards compatibility)
    Finding,
    shannon_entropy,
    shannon_entropy_counts,
)
from .signatures import Signature, SignatureDB
from .prefilter import Prefilter, pattern_runs
from .utils import (marker_text_ok, md5_new, sanitize_text,
                    utf16_view)

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
    files_neutralized: int = 0
    #: files whose deep analysis hit the `scan_file_timeout` budget (v2.8)
    files_budget_skipped: int = 0
    #: findings dropped because the file/domain is allowlisted (v3.0)
    allowlist_suppressed: int = 0
    bytes_scanned: int = 0
    errors: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    #: Per-file verdicts actually produced by this run (internal – used to
    #: feed the scan cache; not serialized by ``to_dict``).
    scanned_paths: Dict[str, List[Finding]] = field(default_factory=dict)
    #: Per-file {path: {"sha256":…, "size":…}} for files hashed by this run
    #: (internal – feeds the integrity baseline check; not serialized).
    file_meta: Dict[str, Dict] = field(default_factory=dict)

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

    #: Report schema version (v2.8) – bumps when the JSON shape changes.
    REPORT_VERSION = 2

    def to_dict(self) -> dict:
        return {
            "report_version": self.REPORT_VERSION,
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_seconds": round(self.elapsed, 3),
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "files_cached": self.files_cached,
            "files_neutralized": self.files_neutralized,
            "files_budget_skipped": self.files_budget_skipped,
            "allowlist_suppressed": self.allowlist_suppressed,
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
    min_mtime: float = 0.0,
    max_depth: int = 0,
) -> Iterator[Path]:
    """Walk *root* with ``os.scandir``, yielding regular files deterministically.

    Each entry is ``lstat``-ed exactly once (the result is cached by
    ``DirEntry``). ``on_skip(path, reason)`` reports symlinks / special
    files; ``on_file(path, lstat_result)`` hands the caller the already
    fetched stat so it never has to stat the file again.
    ``exclude_patterns`` are fnmatch globs matched against the file name and
    the path relative to *root*. ``min_mtime`` (a *--since* cutoff, unix
    time) skips files not modified since then.  ``max_depth`` (0 = unlimited)
    stops descending after that many directory levels below *root*.
    """
    exclude = set(exclude_dirs)
    patterns = [p for p in exclude_patterns if p]
    root_str = str(root)

    def _excluded(p: Path) -> bool:
        if not patterns:
            return False
        # Normalise to "/" so glob patterns work the same on Windows.
        rel = str(p)[len(root_str) + 1:].replace(os.sep, "/") \
            if str(p).startswith(root_str + os.sep) else p.name
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

    stack: List[Tuple[Path, int]] = [(Path(root), 0)]
    while stack:
        current, depth = stack.pop()
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
                elif min_mtime and st.st_mtime < min_mtime:
                    _skip(Path(entry.path), "older than --since")
                else:
                    files.append((Path(entry.path), st))
            else:
                _skip(Path(entry.path), "not a regular file")
        files.sort(key=lambda item: item[0].name)
        for p, st in files:
            if on_file is not None:
                on_file(p, st)
            yield p
        if max_depth and depth >= max_depth:
            for d in dirs:
                _skip(d, "deeper than --max-depth")
            continue
        stack.extend((d, depth + 1) for d in reversed(sorted(dirs)))


class Scanner:
    """Runs the three detection layers over files and directory trees."""

    def __init__(self, config: Config, db: SignatureDB, threads: "str | int" = "auto") -> None:
        self.config = config
        self.db = db
        self.threads = threads
        #: Optional ``(done, total)`` callback, invoked after every file
        #: finishes (cached or freshly scanned). Used for progress bars.
        self.on_progress: Optional[Callable[[int, int], None]] = None
        #: Hashes of files already neutralized by the kill engine
        #: ``{ciphertext_sha256: registry entry id}`` — such files are
        #: counted as neutralized and produce no findings.
        self.neutralized: Optional[Dict[str, str]] = None
        self._patterns: List[Tuple[Signature, "re.Pattern[bytes]"]] = []
        #: sig id -> pattern is literal text (so a match must sit in text)
        self._texty: Dict[str, bool] = {}
        self._prefilter = Prefilter()
        self._combined: Optional["re.Pattern[bytes]"] = None
        self._name_to_sig: Dict[str, Signature] = {}
        self._overlap = 64
        #: (db.version, feed-pattern identity) the pattern set was built for.
        self._cached_version: Optional[Tuple] = None
        #: Threat-intel DB for the web shield (lazy-loaded).
        self._intel: Optional[ThreatIntel] = None
        #: The engine's own config files (signature DB, threat intel).
        #: They contain the very IOC text the patterns look for, so scanning
        #: them would be a self-match false positive – they are skipped.
        self._self_files: set = self._self_file_set(config)
        #: Standing trust baseline (mutation detection), lazy-loaded.
        self._trust_cache: Optional[Dict[str, Dict]] = None
        self._trust_version: int = 0
        #: User rules (v2.8) – lazy-loaded from config.user_rules_file.
        self._user_rules: Optional[List[Signature]] = None
        self._user_globs: Dict[str, str] = {}
        self._user_rules_version: int = -1
        self._glob_rules: List[Tuple[Signature, str]] = []
        #: Public feed indexes (v2.9) – read-only, lazily memory-mapped per
        #: bucket.  With no feeds built every lookup returns None and the
        #: scanner behaves exactly like it did before this layer existed.
        self._feeds: Optional[feeds_mod.FeedDB] = None
        self._feed_patterns: Optional[List[Signature]] = None
        self._feed_patterns_version: str = ""
        #: False-positive allowlist (v3.0) – lazy, mtime-aware.
        self._allow: Optional[allowlist_mod.AllowList] = None
        self._allow_version: int = -1
        #: Findings suppressed by the allowlist during this engine's life.
        self._allow_suppressed: int = 0

    # ----------------------------------------------------------------- feeds
    def feeds(self) -> feeds_mod.FeedDB:
        """The (lazily created) public-feed database."""
        if self._feeds is None:
            self._feeds = feeds_mod.FeedDB(
                Path(self.config.feeds_dir),
                enabled=bool(getattr(self.config, "feeds_enabled", True)))
        return self._feeds

    # ------------------------------------------------------------- allowlist
    def allowlist(self) -> allowlist_mod.AllowList:
        """The false-positive allowlist (lazy, reloaded when the file changes)."""
        if not getattr(self.config, "allowlist_enabled", True):
            if self._allow is None:
                self._allow = allowlist_mod.AllowList(None, entries=[])
            return self._allow
        path = Path(getattr(self.config, "allowlist_file",
                            allowlist_mod.DEFAULT_ALLOWLIST))
        try:
            mtime = path.stat().st_mtime_ns if path.exists() else 0
        except OSError:
            mtime = 0
        if self._allow is None or mtime != self._allow_version:
            self._allow = allowlist_mod.AllowList.load(path)
            self._allow_version = mtime
        return self._allow

    @property
    def allowlist_suppressed(self) -> int:
        """How many findings the allowlist has hidden for this engine."""
        return self._allow_suppressed

    def _apply_allowlist(self, path: Path, findings: List[Finding],
                         *, sha256: str = "", md5: str = "",
                         name: str = "") -> List[Finding]:
        """Drop findings for an allowlisted file/domain, counting them."""
        allow = self.allowlist()
        if not allow.entries:
            return findings
        hit = allow.check(str(path), sha256=sha256, md5=md5, name=name)
        if hit is not None:
            self._allow_suppressed += len(findings)
            return []
        kept, suppressed = allow.filter_findings(findings)
        if suppressed:
            self._allow_suppressed += len(suppressed)
        return kept

    def _load_feed_patterns(self) -> List[Signature]:
        """Feed-derived literal signatures (YARA strings, ClamAV .ndb)."""
        db = self.feeds()
        identity = db.identity()
        if self._feed_patterns is not None and \
                identity == self._feed_patterns_version:
            return self._feed_patterns
        signatures: List[Signature] = []
        for entry in db.patterns():
            try:
                signature = Signature(
                    id=str(entry["id"]), name=str(entry.get("name", "feed")),
                    category="feed",
                    pattern=str(entry["pattern"]),
                    severity=str(entry.get("severity", "high")),
                    description=str(entry.get("description", "")),
                    source=str(entry.get("source", "feed")),
                )
            except (KeyError, TypeError, ValueError):
                continue
            signatures.append(signature)
        self._feed_patterns = signatures
        self._feed_patterns_version = identity
        return signatures

    def _load_user_rules(self) -> List[Signature]:
        """User rules from ``config.user_rules_file`` (mtime-aware, cached).

        A missing file simply means "no user rules".  Rules carrying a
        file-name condition stay out of the merged alternation and are
        evaluated per file against the name.
        """
        from . import rules as rules_mod
        if not getattr(self.config, "user_rules_enabled", True):
            if self._user_rules:
                self._cached_version = None
            self._user_rules, self._glob_rules = [], []
            return self._user_rules
        path = Path(self.config.user_rules_file)
        try:
            mtime = path.stat().st_mtime_ns if path.exists() else 0
        except OSError:
            mtime = 0
        if self._user_rules is not None and mtime == self._user_rules_version:
            return self._user_rules
        if mtime:
            sigs, globs = rules_mod.rules_with_globs(path)
        else:
            sigs, globs = [], {}
        self._user_globs = globs
        self._user_rules = [s for s in sigs
                            if s.id not in globs and s.compiled is not None]
        self._glob_rules = [(s, globs[s.id]) for s in sigs
                            if s.id in globs and s.compiled is not None]
        self._user_rules_version = mtime
        self._cached_version = None  # merged patterns must be rebuilt
        return self._user_rules

    def _trust_baseline(self) -> Dict[str, Dict]:
        """The standing trust baseline ({} when none is configured).

        Reloaded when the baseline file's mtime changes, so a baseline
        created or updated between scans is picked up (one cheap stat).
        """
        from .integrity import _canon as _canon_key, load_manifest
        path = Path(self.config.trust_baseline_file)
        try:
            mtime = path.stat().st_mtime_ns if path.exists() else 0
        except OSError:
            mtime = 0
        if self._trust_cache is None or mtime != self._trust_version:
            files: Dict[str, Dict] = {}
            if mtime:
                try:
                    manifest = load_manifest(path)
                    files = {_canon_key(k): v
                             for k, v in manifest.get("files", {}).items()}
                except (ValueError, OSError, json.JSONDecodeError):
                    files = {}
            self._trust_cache = files
            self._trust_version = mtime
        return self._trust_cache

    def _integrity_finding(self, path_str: str, sha256: str) -> Optional[Finding]:
        """Mutation check of one file against the trust baseline."""
        from .integrity import check_trusted
        if not self.config.integrity_enabled:
            return None
        return check_trusted(self._trust_baseline(), path_str, sha256)

    @staticmethod
    def _self_file_set(config: Config) -> set:
        out = set()
        for p in (config.signatures_file, config.threat_intel_file,
                  config.intel_user_file, config.trust_baseline_file):
            pp = Path(p).expanduser()
            out.add(os.path.normpath(str(pp)))
            if not os.path.isabs(str(pp)):
                out.add(os.path.normpath(os.path.join(os.getcwd(), str(pp))))
            try:
                out.add(os.path.normpath(str(pp.resolve())))
            except (OSError, RuntimeError):
                pass
        return out

    def threat_intel(self) -> ThreatIntel:
        """The web shield's threat-intel DB (lazy, cached).

        Looks for the database in the configured location, next to the
        package (``data/``), and next to the package root (rescue-kit
        layout) before giving up.
        """
        if self._intel is None:
            cfg = self.config
            pkg_root = Path(webshield_mod.__file__).resolve().parent.parent
            candidates = [Path(cfg.threat_intel_file),
                          pkg_root / "data" / "threat_intel.json",
                          pkg_root / "threat_intel.json"]
            src = next((p for p in candidates if p.exists()), None)
            self._intel = ThreatIntel.load(src, Path(cfg.intel_user_file))
        return self._intel

    def _risk_finding(self, path_str: str, p: Path, st, data: bytes,
                      sha256: str, size: int, cfg: Config) -> Optional[Finding]:
        """Suspicion-engine layer: one finding when the risk score crosses
        the threshold (v2.4)."""
        report = risk_mod.assess_risk(p, st, data)
        if report.score < cfg.risk_threshold:
            return None
        return Finding(
            path=path_str, kind="suspicious", name="SuspiciousFile",
            severity=risk_mod.severity_for(report.score),
            message=(f"risk score {report.score}/100: "
                     + "; ".join(report.top_reasons(3))),
            sha256=sha256, size=size,
        )

    # ------------------------------------------------------------- public API
    def scan_path(self, path: Path,
                  result: Optional["ScanResult"] = None) -> ScanResult:
        """Scan a single file or an entire directory tree.

        When the scan cache is enabled, files whose size *and* mtime are
        unchanged (and whose engine profile matches) reuse their previous
        verdict without being read from disk at all.

        *result* may be a pre-built ScanResult (its counters are then
        updated in place – used by the web console for live progress).
        """
        path = Path(path)
        if result is None:
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
                                exclude_patterns=self.config.exclude_patterns,
                                min_mtime=self.config.since_ts,
                                max_depth=self.config.scan_max_depth):
                pass
        else:
            result.errors.append(f"{path}: not a regular file or directory")
            result.finished_at = time.time()
            return result

        # Cache partition: unchanged files keep their previous verdict.
        total = len(files)
        _done = [0]

        def _tick() -> None:
            _done[0] += 1
            if self.on_progress is not None:
                try:
                    self.on_progress(_done[0], total)
                except Exception:
                    pass  # a broken progress callback must not kill a scan

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
                    _tick()
                else:
                    to_scan.append((p, st))
            files = to_scan

        workers = self._workers()
        if len(files) > 1 and workers > 1:
            self._scan_files_parallel(files, result, workers, _tick)
        else:
            for p, st in files:
                self._scan_file(p, result, st=st)
                _tick()

        # Record fresh verdicts for the next (fast) scan.
        if cache is not None and result.scanned_paths:
            self._record_cache(cache, result)

        # Aggregate mutation alert (v2.7): many trusted files mutated in
        # one pass is the signature of ransomware-style bulk encryption.
        if self.config.integrity_enabled and self._trust_baseline():
            from .integrity import mass_mutation_finding
            mass = mass_mutation_finding(
                result.findings, str(path),
                self.config.mutation_ransomware_threshold)
            if mass is not None:
                result.findings.append(mass)

        if len(result.findings) > 1:
            result.findings.sort(key=lambda f: (f.path, f.kind))
        result.finished_at = time.time()
        # Cumulative metrics (v2.8): counters that survive across runs and
        # feed `antivirus metrics`.  A metrics failure must never break a scan.
        try:
            metrics_mod.record_scan(self.config.metrics_file, result)
        except Exception:
            pass
        return result

    def _allowlist_identity(self) -> int:
        """mtime of the allowlist file – part of the cache validity key."""
        try:
            path = Path(getattr(self.config, "allowlist_file",
                                allowlist_mod.DEFAULT_ALLOWLIST))
            return path.stat().st_mtime_ns if path.exists() else 0
        except OSError:
            return 0

    def _cache_profile(self) -> dict:
        """Everything that influences a verdict – the cache's validity key."""
        cfg = self.config
        self._trust_baseline()  # load + refresh _trust_version
        return {
            "db_version": self.db.version,
            "feeds": [self.feeds().identity(), cfg.feeds_enabled,
                      cfg.feeds_domains_enabled],
            "allowlist": [cfg.allowlist_enabled, self._allowlist_identity()],
            "indicators_enabled": self.config.indicators_enabled,
            "indicators_max_size": self.config.indicators_max_size,
            "wide_patterns_enabled": self.config.wide_patterns_enabled,
            "file_timeout": self.config.scan_file_timeout,
            "user_rules_mtime": self._user_rules_version,
            "behavior": cfg.behavior_enabled,
            "fast": cfg.fast_mode,
            "archives": cfg.archives_enabled,
            "entropy_threshold": cfg.entropy_threshold,
            "risk": [cfg.risk_enabled, cfg.risk_threshold],
            "webshield": cfg.webshield_enabled,
            "max_file_size": cfg.max_file_size,
            "integrity": [cfg.integrity_enabled,
                          self._trust_version],
            "polyglot": cfg.polyglot_enabled,
            "obfuscation": cfg.obfuscation_enabled,
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
                             result: "ScanResult", workers: int,
                             _tick: Optional[Callable[[], None]] = None) -> None:
        def work(item: Tuple[Path, Optional[os.stat_result]]) -> ScanResult:
            p, st = item
            local = ScanResult(target=str(p), started_at=0.0)
            self._scan_file(p, local, st=st)
            return local

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="av-scan") as pool:
            for local in pool.map(work, files, chunksize=16):
                if _tick is not None:
                    _tick()
                result.files_scanned += local.files_scanned
                result.files_skipped += local.files_skipped
                result.files_neutralized += local.files_neutralized
                result.bytes_scanned += local.bytes_scanned
                if local.errors:
                    result.errors.extend(local.errors)
                if local.findings:
                    result.findings.extend(local.findings)
                if local.scanned_paths:
                    result.scanned_paths.update(local.scanned_paths)
                if local.file_meta:
                    result.file_meta.update(local.file_meta)

    # ------------------------------------------------------------ internals
    def _sync_patterns(self) -> None:
        """Rebuild the pattern set + literal prefilter when the DB changed.

        v2.8: the old approach (one big alternation of every pattern) is
        O(patterns) per byte in CPython's ``re`` and measured ~7 s/MiB with
        100+ signatures.  Instead every pattern now carries a required
        literal token; a memchr-backed ``bytes.find`` gate decides which
        patterns are even worth testing on this buffer (see prefilter.py).
        """
        pattern_key = (self.db.version, self.feeds().identity())
        if self._cached_version == pattern_key:
            return
        self._patterns = []
        self._prefilter = Prefilter()
        seen = set()
        for sig in (self.db.list() + self._load_user_rules()
                    + self._load_feed_patterns()):
            compiled = sig.compiled
            if compiled is None or sig.id in seen:
                continue
            seen.add(sig.id)
            self._patterns.append((sig, compiled))
            self._prefilter.add_patterns(sig.id, [sig.pattern])
            # Signatures built from literal words (family names, note text,
            # commands) must match inside readable text; binary/code
            # signatures (hex escapes, byte windows) are exempt.
            self._texty[sig.id] = bool(pattern_runs(sig.pattern))
        self._overlap = max((len(s.pattern) for s, _ in self._patterns),
                            default=0) * 3 + 64
        self._cached_version = pattern_key

    def _match_patterns(self, buf: bytes) -> List[Signature]:
        """Which signatures match *buf* (prefilter gate, then regex).

        Text signatures additionally require the match to sit in readable
        text (v2.8): three random letters inside a compressed blob are not
        a family marker.  Binary signatures are exempt.
        """
        hits: List[Signature] = []
        candidates = set(self._prefilter.candidates(buf))
        for sig, rx in self._patterns:
            if sig.id not in candidates:
                continue
            m = rx.search(buf)
            if m is None:
                continue
            if (self._texty.get(sig.id, True)
                    and not marker_text_ok(buf, m.start(), m.end())):
                continue
            if sig not in hits:
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
        # The engine's own signature / threat-intel DBs contain the very IOC
        # text the patterns look for; scanning them is a self-match false
        # positive, so they are always skipped.
        if self._is_self_file(path):
            return
        # False-positive allowlist (v3.0): a name/path match skips the file
        # entirely, so an excluded file costs nothing to scan.
        allow = self.allowlist()
        if allow.entries and allow.check(str(path), name=path.name) is not None:
            self._allow_suppressed += 1
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

        if not partial and allow.entries and allow.check(
                str(path), sha256=sha256, md5=md5, name=path.name) is not None:
            self._allow_suppressed += 1
            return

        result.files_scanned += 1
        result.file_meta[str(path)] = {"sha256": sha256, "size": size}
        result.bytes_scanned += size

        # Soft per-file analysis budget (v2.8): when --file-timeout is set and
        # a file takes longer than that, the remaining *deep* layers are
        # skipped for this file (it is counted in files_budget_skipped).
        deadline = (time.monotonic() + self.config.scan_file_timeout
                    if self.config.scan_file_timeout else None)
        budget_hit = [False]

        def _budget_ok() -> bool:
            if deadline is None or time.monotonic() <= deadline:
                return True
            budget_hit[0] = True
            return False

        # Already neutralized by the kill engine (its registry maps the
        # ciphertext's hash to a registry entry): the file is inert, so it
        # is counted but not re-flagged by any layer.
        if self.neutralized and sha256 in self.neutralized:
            result.files_neutralized += 1
            result.scanned_paths[str(path)] = []
            return

        # NOTE: verdicts are collected in a *per-file* list.  The heuristic
        # guard must never look at ``result.findings`` – that list is shared
        # by the whole tree scan, so findings from earlier files would
        # silently suppress heuristics for every later file.
        local: List[Finding] = []

        # Layer 1 – mutation detection (v2.7): the content of a *trusted*
        # file changed since the trust baseline was taken.  Runs before the
        # hash short-circuit so a trusted file that turned into a known-bad
        # binary is reported as mutated *and* matched.
        if not partial:
            mutation = self._integrity_finding(str(path), sha256)
            if mutation is not None:
                local.append(mutation)

        # Layer 2 – exact hash match (definite).
        if not partial:
            signature = self.db.by_sha256(sha256)
            if signature is None:
                signature = self.db.by_md5(md5)
            if signature is None:
                for sig in self._load_user_rules():
                    if (sig.sha256 and sig.sha256.lower() == sha256) or \
                            (sig.md5 and sig.md5.lower() == md5):
                        signature = sig
                        break
            if signature is None:
                # Public feed hash sets (v2.9): millions of known-bad hashes,
                # matched by an 8-byte digest lookup - only when feeds exist.
                feed_hit = self.feeds().lookup_hash(sha256=sha256, md5=md5)
                if feed_hit is not None:
                    local.append(self.feeds().hash_finding(
                        str(path), feed_hit, size=size, sha256=sha256))
                    result.findings.extend(local)  # definite match – stop here
                    result.scanned_paths[str(path)] = local
                    return
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

        # Wide (UTF-16) pattern pass (v2.8): Windows scripts, registry
        # exports and PowerShell -enc blobs are stored UTF-16; decode a view
        # so the ASCII patterns can see them (no-op for other files).
        if (self.config.wide_patterns_enabled and not partial and content):
            wide = utf16_view(content)
            if wide:
                known = {s.id for s in pattern_hits}
                for sig in self._match_patterns(wide):
                    if sig.id not in known:
                        pattern_hits.append(sig)

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

        # User rules with a file-name condition (v2.8): evaluated per file,
        # because the merged alternation cannot know the file name.
        if self._glob_rules and content and _budget_ok():
            for sig, glob in self._glob_rules:
                if fnmatch.fnmatch(path.name, glob) and sig.compiled is not None \
                        and sig.compiled.search(content):
                    local.append(Finding(
                        path=str(path), kind="signature-pattern",
                        name=sig.name, severity=sig.severity,
                        message=(f"User rule '{sig.id}' matched "
                                 f"(file name {glob})"),
                        sha256=sha256, size=size))

        # Layer 2.5 – behavioural analysis (what the file appears to do).
        # Only files that look executable are examined; the content was
        # already buffered during the single read pass above.
        # Fast mode skips this layer and the entropy heuristic.
        if (
            self.config.behavior_enabled
            and not self.config.fast_mode
            and content is not None
            and _budget_ok()
            and behavior_looks_executable(path, content)
        ):
            local.extend(behavior_analyze_file(path, st, content))

        # Layer 2.55 – polyglot detection (v2.7): one file that is valid in
        # more than one format (PDF/PE, image/PE, text + binary blob, ...).
        # Any file type can be a polyglot, so no executable-looking gate.
        if self.config.polyglot_enabled and not self.config.fast_mode:
            head = content if content is not None else \
                self._peek_bytes(path, 4 * 1024 * 1024)
            if head:
                local.extend(polyglot_mod.analyze(str(path), head))

        # Layer 2.56 – obfuscation techniques (v2.7): encoded payload
        # blobs, double encoding, junk code, packed PEs without imports.
        if self.config.obfuscation_enabled and not self.config.fast_mode \
                and _budget_ok():
            head = content if content is not None else \
                self._peek_bytes(path, 4 * 1024 * 1024)
            if head:
                local.extend(obfuscation_mod.analyze(str(path), head))

        # Layer 2.57 – indicator checks (v2.8): technique markers - LOLBins,
        # persistence, evasion, credential access, C2, ransomware impact,
        # macro/DDE/LNK delivery.  See antivirus/indicators.py.
        if self.config.indicators_enabled and not self.config.fast_mode \
                and _budget_ok():
            limit = max(self.config.indicators_max_size, 1)
            head = content if content is not None else self._peek_bytes(path, limit)
            if head:
                local.extend(indicators_mod.analyze(
                    str(path), head[:limit], filename=path.name))

        # Layer 2.6 – web shield: URLs inside the file vs threat-intel (v2.4).
        if self.config.webshield_enabled and not self.config.fast_mode \
                and _budget_ok():
            head = content if content is not None else \
                self._peek_bytes(path, 262144)
            local.extend(webshield_mod.audit_bytes(
                str(path), head, self.threat_intel()))

        # Layer 2.62 – public feed IOCs (v2.9): domains/IPs inside the file
        # that appear in the built feed indexes, plus feed-listed file names.
        feeds = self.feeds()
        if feeds.built and not self.config.fast_mode and _budget_ok():
            local.extend(feeds.audit_name(str(path)))
            if self.config.feeds_domains_enabled:
                head = content if content is not None else \
                    self._peek_bytes(path, max(self.config.feeds_scan_bytes, 1))
                if head:
                    local.extend(feeds.audit_content(
                        str(path), head[:self.config.feeds_scan_bytes],
                        window=self.config.feeds_scan_bytes,
                        limit=self.config.feeds_max_tokens,
                        max_findings=self.config.feeds_max_findings))

        # Layer 2.65 – suspicion engine: how suspicious does the file *look*,
        # independent of any signature match (v2.4).  This is what makes the
        # background guard act on odd new files with no known signature.
        if (
            self.config.risk_enabled
            and not self.config.fast_mode
            and not local
            and _budget_ok()
        ):
            head = content if content is not None else \
                self._peek_bytes(path, 65536)
            local.append(self._risk_finding(str(path), path, st, head,
                                            sha256, size, self.config))
        local = [f for f in local if f is not None]

        # Layer 2.75 – archive contents (ZIP / TAR / GZIP, in memory only).
        if (
            self.config.archives_enabled
            and size <= self.config.archive_max_size
            and _budget_ok()
        ):
            head = content[:262] if content is not None else \
                self._peek_bytes(path, 262)
            local.extend(self._scan_archives(path, head))

        # Layer 3 – heuristics (only if this file has no definite hit yet).
        if (
            not local
            and not self.config.fast_mode
            and _budget_ok()
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

        if budget_hit[0]:
            result.files_budget_skipped += 1
            result.errors.append(
                f"{path}: deep analysis skipped (per-file budget "
                f"{self.config.scan_file_timeout:g}s)")

        # Backfill digests on findings produced by layers that don't set
        # them (behaviour / archives), so reports & exports carry the
        # file's hash and size for every finding.
        local = self._apply_allowlist(path, local, sha256=sha256,
                                      md5=md5, name=path.name)
        for f in local:
            if not f.sha256:
                f.sha256 = sha256
            if not f.size:
                f.size = size
        result.findings.extend(local)
        result.scanned_paths[str(path)] = local

    def _is_self_file(self, path: Path) -> bool:
        s = str(path)
        if os.path.normpath(s) in self._self_files:
            return True
        if not os.path.isabs(s):
            if os.path.normpath(os.path.join(os.getcwd(), s)) in self._self_files:
                return True
        # v2.9: everything under the feed database directory is generated
        # data that *quotes* the indicators it indexes - scanning it would
        # report the engine's own database as malicious.
        try:
            resolved = Path(s).resolve()
            root = Path(self.config.feeds_dir).resolve()
            if resolved == root or root in resolved.parents:
                return True
        except (OSError, RuntimeError):
            pass
        return False

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
        allow = self.allowlist()
        if allow.entries and allow.check(str(name), sha256=sha256, md5=md5,
                                         name=p.name) is not None:
            self._allow_suppressed += 1
            return []
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

        pattern_hits = self._match_patterns(data)
        if cfg.wide_patterns_enabled:
            wide = utf16_view(data)
            if wide:
                known = {s.id for s in pattern_hits}
                pattern_hits.extend(s for s in self._match_patterns(wide)
                                    if s.id not in known)
        for sig in pattern_hits:
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

        # Polyglot + obfuscation layers (v2.7) – same as on disk.
        if cfg.polyglot_enabled and not cfg.fast_mode:
            local.extend(polyglot_mod.analyze(name, data))
        if cfg.obfuscation_enabled and not cfg.fast_mode:
            local.extend(obfuscation_mod.analyze(name, data))
        # Indicator checks (v2.8) – same technique table as on disk.
        if cfg.indicators_enabled and not cfg.fast_mode:
            limit = max(cfg.indicators_max_size, 1)
            local.extend(indicators_mod.analyze(name, data[:limit],
                                                filename=p.name))

        # Web shield + suspicion engine (v2.4) – same layers as on disk.
        if cfg.webshield_enabled and not cfg.fast_mode:
            local.extend(webshield_mod.audit_bytes(name, data,
                                                   self.threat_intel()))

        # Public feed IOCs (v2.9) – archive members are analysed the same
        # way as files on disk, and never written anywhere.
        feeds = self.feeds()
        if feeds.built and not cfg.fast_mode:
            local.extend(feeds.audit_name(name))
            if cfg.feeds_domains_enabled:
                local.extend(feeds.audit_content(
                    name, data[:cfg.feeds_scan_bytes],
                    window=cfg.feeds_scan_bytes, limit=cfg.feeds_max_tokens,
                    max_findings=cfg.feeds_max_findings))
        if cfg.risk_enabled and not cfg.fast_mode and not local:
            f = self._risk_finding(name, p, None, data, sha256, len(data), cfg)
            if f is not None:
                local.append(f)

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
        local = self._apply_allowlist(name, local, sha256=sha256,
                                      name=p.name)
        for f in local:
            if not f.sha256:
                f.sha256 = sha256
            if not f.size:
                f.size = len(data)
        return local

    # --------------------------------------------------------------- archives
    def _scan_archives(self, path: Path, head: bytes) -> List[Finding]:
        """Format dispatch for the archive layer."""
        if head[:4] == b"PK\x03\x04":
            return self._scan_zip(path)
        if head[:2] == b"\x1f\x8b":
            return self._scan_gzip(path)
        if len(head) >= 262 and head[257:262] == b"ustar":
            return self._scan_tar(path)
        return []

    def _scan_zip(self, path: Path) -> List[Finding]:
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

    def _tar_member_flags(self, name: str) -> Optional[str]:
        if name.startswith(("/", "\\")) or ".." in Path(name).parts:
            return "Archive path traversal (tar slip)"
        return None

    def _scan_tar_members(self, tf: "tarfile.TarFile", base: str) -> List[Finding]:
        """Shared member loop for file- and byte-backed tar archives."""
        cfg = self.config
        out: List[Finding] = []
        entries_read = 0
        for i, member in enumerate(tf.getmembers()):
            if i >= cfg.archive_entries_max:
                out.append(Finding(
                    path=base, kind="archive",
                    name="Archive entry limit exceeded", severity="medium",
                    message=f"more than {cfg.archive_entries_max} entries",
                ))
                break
            if not member.isfile():
                continue
            slip = self._tar_member_flags(member.name)
            if slip is not None:
                out.append(Finding(
                    path=base, kind="archive", name=slip, severity="medium",
                    message=f"entry {member.name!r} escapes the archive root",
                ))
                continue
            if entries_read > cfg.archive_expansion_max:
                out.append(Finding(
                    path=base, kind="archive",
                    name="Archive expansion limit exceeded", severity="medium",
                    message="total entry size exceeds the analysis budget",
                ))
                break
            try:
                fh = tf.extractfile(member)
                if fh is None:
                    continue
                want = cfg.archive_entry_max
                if 0 <= member.size < want:
                    want = member.size
                data = fh.read(want)
            except (tarfile.TarError, OSError, ValueError):
                continue
            if not data:
                continue
            entries_read += len(data)
            out.extend(self.scan_buffer(f"{base}!{member.name}", data))
        return out

    def _scan_tar(self, path: Path) -> List[Finding]:
        try:
            tf = tarfile.open(str(path))
        except (tarfile.TarError, OSError, ValueError):
            return []
        with tf:
            return self._scan_tar_members(tf, str(path))

    def _scan_tar_bytes(self, tar_bytes: bytes, base: str) -> List[Finding]:
        try:
            tf = tarfile.open(fileobj=io.BytesIO(tar_bytes))
        except (tarfile.TarError, OSError, ValueError):
            return []
        with tf:
            return self._scan_tar_members(tf, base)

    def _scan_gzip(self, path: Path) -> List[Finding]:
        """Scan a gzip stream: tar member(s), or the decompressed payload."""
        cfg = self.config
        out: List[Finding] = []
        try:
            with open(path, "rb") as fh:
                inner = gzip.decompress(fh.read(cfg.archive_max_size))
        except (OSError, EOFError, zlib.error):
            return out
        if len(inner) > cfg.archive_expansion_max:
            out.append(Finding(
                path=str(path), kind="archive",
                name="Archive expansion limit exceeded", severity="medium",
                message="decompressed content exceeds the analysis budget",
            ))
            return out
        if len(inner) >= 262 and inner[257:262] == b"ustar":
            return self._scan_tar_bytes(inner, str(path))
        out.extend(self.scan_buffer(f"{path}!member",
                                    inner[: cfg.archive_entry_max]))
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
