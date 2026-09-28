"""High-level, import-friendly API for the AntiVirus engine.

Everything is dependency-free (standard library only), so the package can
be dropped into another project as a plain module:

    # one-shot, throwaway engine (artefacts under ./)
    import antivirus
    result = antivirus.scan("/path/to/scan")
    if not result.clean:
        for f in result.findings:
            print(f"[{f.severity}] {f.name}  {f.path}")

    # long-lived engine with its own working area
    from antivirus import Antivirus
    av = Antivirus(base="~/.myapp")      # cache/reports/quarantine/signatures
                                          # live under ~/.myapp, never your CWD
    result = av.scan("some/dir", fast=True)
    result.worst_severity
    av.add_signature(id="AV-MINE-001", name="Mine",
                     pattern="UNIQUE-MARKER", severity="high")
    av.scan_file("suspicious.bin")
    av.file_info("suspicious.bin")["sha256"]
    av.manifest("some/dir")               # integrity baseline (dict)
    av.verify("some/dir", "baseline.json")  # fast hash-only diff (findings)
    av.quarantine.restore("275a021b-...")

The API is intentionally thin: it wires together the same
:mod:`scanner`, :mod:`quarantine` and :mod:`signatures` components the CLI,
GUI, TUI and web console use.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from .config import Config
from .fileinfo import file_info
from .integrity import build_manifest as _build_manifest
from .integrity import save_manifest as _save_manifest
from .models import Finding
from .quarantine import Quarantine
from .report import ReportWriter
from .scanner import ScanResult, Scanner
from .signatures import Signature, SignatureDB

#: Bundled signature database (same location the CLI falls back to).
BUNDLED_SIGNATURES = Path(__file__).resolve().parent.parent / "data" / \
    "signatures.json"


def engine_stats(config: Config, db: SignatureDB, quarantine: Quarantine,
                 include_reports: bool = True) -> Dict:
    """A cross-component snapshot of engine state.

    Shared by ``antivirus stats`` (CLI) and the web console's
    ``/api/stats`` endpoint. Pure read-only.
    """
    from . import __version__
    from .report import ReportWriter, summarize_reports

    sigs = db.list()
    by_sev: Dict[str, int] = {}
    by_kind = {"sha256": 0, "md5": 0, "pattern": 0}
    for s in sigs:
        by_sev[s.severity] = by_sev.get(s.severity, 0) + 1
        if s.sha256:
            by_kind["sha256"] += 1
        if s.md5:
            by_kind["md5"] += 1
        if s.pattern:
            by_kind["pattern"] += 1
    order = ("critical", "high", "medium", "low", "info")

    cache_path = Path(config.cache_dir)
    cache: Dict = {"path": str(cache_path), "entries": 0, "size_bytes": 0}
    if cache_path.exists():
        try:
            cache["size_bytes"] = cache_path.lstat().st_size
            cache["entries"] = len(json.loads(
                cache_path.read_text(encoding="utf-8")).get("entries", {}))
        except (json.JSONDecodeError, OSError, ValueError):
            pass

    stats: Dict = {
        "version": __version__,
        "signatures": {
            "total": len(sigs),
            "by_severity": {s: by_sev[s] for s in order if s in by_sev},
            "by_kind": by_kind,
            "path": str(config.signatures_file),
        },
        "cache": cache,
        "quarantine": {
            "items": len(quarantine.items()),
            "path": str(config.quarantine_dir),
        },
    }
    if include_reports:
        stats["reports"] = summarize_reports(
            ReportWriter(config.report_dir).all_reports())
    return stats


def apply_actions(result: ScanResult, quarantine: Quarantine,
                  action: str) -> Dict[str, str]:
    """Apply *action* (detect / quarantine / delete) to a scan result.

    Returns a ``{path: note}`` map describing what happened to each file.
    Shared by the module API, the web console and (conceptually) the CLI.
    """
    notes: Dict[str, str] = {}
    if action == "detect":
        return notes
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
                item = quarantine.put(path, finding)
                notes[finding.path] = f"quarantined as {item.id}"
            except OSError as exc:
                notes[finding.path] = f"quarantine failed: {exc}"
        else:  # delete
            try:
                path.unlink()
                notes[finding.path] = "deleted"
            except OSError as exc:
                notes[finding.path] = f"delete failed: {exc}"
    return notes


class Antivirus:
    """A configured, ready-to-use engine with its own working area.

    Parameters
    ----------
    base:
        Directory holding runtime artefacts (signature database, scan
        cache, reports, quarantine, baselines). Created on demand.
    config:
        Pre-built :class:`~antivirus.config.Config` (advanced use – the
        *base* artefact locations are ignored when this is given).
    threads:
        Worker threads for directory scans (``"auto"``, ``1`` … ``"off"``).
    """

    def __init__(self, base=".", config: Optional[Config] = None,
                 threads: "str | int" = "auto",
                 signatures: Optional[str] = None) -> None:
        base_path = Path(os.path.expanduser(str(base)))
        if config is None:
            config = Config()
            config.quarantine_dir = base_path / "quarantine"
            config.report_dir = base_path / "reports"
            config.signatures_file = base_path / "data" / "signatures.json"
            config.cache_dir = base_path / ".av-cache"
            config.baseline_dir = base_path / "baselines"
        if signatures is not None:
            config.signatures_file = Path(os.path.expanduser(str(signatures)))
        config.resolve_paths(base_path)

        sig = config.signatures_file
        if not sig.exists() and BUNDLED_SIGNATURES.exists():
            sig.parent.mkdir(parents=True, exist_ok=True)
            import shutil

            shutil.copyfile(BUNDLED_SIGNATURES, sig)

        self.base = base_path
        self.config = config
        self.db = SignatureDB(config.signatures_file)
        self.scanner = Scanner(config, self.db, threads=threads)
        self.quarantine = Quarantine(config.quarantine_dir)
        self.report_writer = ReportWriter(config.report_dir)

    # ------------------------------------------------------------- scanning
    def scan(
        self,
        target,
        action: str = "detect",
        fast: bool = False,
        since: Optional[str] = None,
        exclude: Sequence[str] = (),
        no_archives: bool = False,
        cache: Optional[bool] = None,
        baseline: Optional[str] = None,
        save_report: bool = False,
    ) -> ScanResult:
        """Scan a file or directory tree.

        The returned :class:`~antivirus.scanner.ScanResult` also carries a
        ``notes`` attribute ({path: note}) describing applied actions.
        *baseline* may be a manifest file path, or a baseline id previously
        stored with :meth:`save_manifest`.
        """
        if action not in ("detect", "quarantine", "delete"):
            raise ValueError(f"invalid action: {action}")
        from .utils import parse_since

        cfg = self.config
        previous = {
            "fast_mode": cfg.fast_mode,
            "since_ts": cfg.since_ts,
            "exclude_patterns": cfg.exclude_patterns,
            "archives_enabled": cfg.archives_enabled,
            "cache_enabled": cfg.cache_enabled,
        }
        cfg.fast_mode = fast
        cfg.since_ts = time.time() - parse_since(since) if since else 0.0
        if exclude:
            cfg.exclude_patterns = tuple(exclude)
        if no_archives:
            cfg.archives_enabled = False
        if cache is not None:
            cfg.cache_enabled = cache

        result: Optional[ScanResult] = None
        try:
            target_path = Path(os.path.expanduser(str(target)))
            if not target_path.exists():
                raise FileNotFoundError(str(target))
            result = self.scanner.scan_path(target_path)
            if baseline and result is not None and target_path.is_dir():
                from .integrity import (
                    compare_baseline,
                    current_from_result,
                    load_manifest,
                )

                bpath = Path(os.path.expanduser(str(baseline)))
                if not bpath.exists():
                    bpath = cfg.baseline_dir / f"{baseline}.json"
                manifest = load_manifest(bpath)
                extra = compare_baseline(
                    manifest, current_from_result(result, target_path))
                result.findings.extend(extra)
            if action != "detect" and result is not None:
                result.notes = apply_actions(result, self.quarantine, action)  # type: ignore[attr-defined]
            elif result is not None:
                result.notes = {}  # type: ignore[attr-defined]
            if save_report and result is not None:
                result.report_path = self.report_writer.save(  # type: ignore[attr-defined]
                    result, action=action,
                    actions_taken=getattr(result, "notes", {}))
        finally:
            for key, value in previous.items():
                setattr(cfg, key, value)
        if result is None:  # pragma: no cover - defensive
            raise RuntimeError("scan produced no result")
        return result

    def scan_file(self, path) -> List[Finding]:
        """Scan a single file; returns its findings (empty when clean)."""
        return self.scanner.scan_file(Path(path))

    def save_report(self, result: ScanResult, action: str = "detect") -> Path:
        return self.report_writer.save(result, action=action)

    # ----------------------------------------------------------- signatures
    def add_signature(self, id: str, name: str, *,
                      severity: str = "medium", category: str = "custom",
                      description: str = "", sha256: str = "",
                      md5: str = "", pattern: str = "") -> Signature:
        sig = Signature(id=id, name=name, category=category,
                        severity=severity, description=description,
                        sha256=sha256.lower(), md5=md5.lower(),
                        pattern=pattern)
        self.db.add(sig)
        return sig

    def remove_signature(self, id: str) -> Signature:
        return self.db.remove(id)

    def signatures(self) -> List[Signature]:
        return self.db.list()

    # -------------------------------------------------------- file utilities
    def file_info(self, path) -> Dict:
        return file_info(Path(path))

    def manifest(self, target) -> Dict:
        """Hash a file or tree; returns the integrity baseline (dict)."""
        return _build_manifest(Path(target), self.config)

    def save_manifest(self, manifest: Dict, path) -> Path:
        _save_manifest(manifest, Path(path))
        return Path(path)

    def verify(self, target, baseline) -> List[Finding]:
        """Fast integrity-only check: hash the tree, diff vs *baseline*.

        No signature/behaviour/entropy layers run, so this is much cheaper
        than ``scan(..., baseline=...)``. *baseline* is a manifest file
        path or a baseline id stored under *base*.
        """
        from .integrity import load_manifest, verify_tree

        bpath = Path(os.path.expanduser(str(baseline)))
        if not bpath.exists():
            bpath = self.config.baseline_dir / f"{baseline}.json"
        manifest = load_manifest(bpath)
        return verify_tree(Path(os.path.expanduser(str(target))),
                           manifest, self.config)

    def rescue_build(self, out_dir=None, iso_path=None) -> Dict:
        """Build the rescue kit + ISO, using this engine's signature DB.

        *out_dir* / *iso_path* default to ``rescue-kit`` / ``rescue.iso``
        inside the engine's base directory.
        """
        from .rescue import build_rescue_disk

        out = Path(out_dir) if out_dir else self.base / "rescue-kit"
        iso = Path(iso_path) if iso_path else self.base / "rescue.iso"
        return build_rescue_disk(out, iso, self.config.signatures_file)

    # ------------------------------------------------------------- properties
    @property
    def version(self) -> str:
        from . import __version__

        return __version__


# ------------------------------------------------------------------ one-shot
def scan(target, base=".", signatures: Optional[str] = None,
         **kwargs) -> ScanResult:
    """One-shot convenience scan (see :meth:`Antivirus.scan`).

    The engine's working area is *base* (default ``"."``): a throwaway use
    will create ``data/``, ``.av-cache``, ``reports/`` there. *signatures*
    may point at a specific signature database (its parent directory is
    used for the working artefacts).
    """
    return Antivirus(base=base, signatures=signatures).scan(target, **kwargs)


def scan_file(path, base=".") -> List[Finding]:
    """One-shot single-file scan; returns its findings."""
    return Antivirus(base=base).scan_file(path)


def rescue_build(out_dir="rescue-kit", iso_path="rescue.iso",
                 signatures: Optional[str] = None) -> Dict:
    """One-shot rescue kit + ISO image build (see :mod:`antivirus.rescue`).

    *signatures* may point at a specific signature database to snapshot
    (default: the bundled one).
    """
    from .rescue import build_rescue_disk

    return build_rescue_disk(Path(os.path.expanduser(str(out_dir))),
                             iso_path, signatures)


def run_rescue(target, **kwargs) -> Dict:
    """One-shot rescue scan of a mounted volume (see :mod:`antivirus.rescue`).

    Quarantine/reports go to ``rescue-quarantine`` / ``rescue-reports``
    under the CWD (the live side), never into the scanned tree.
    """
    from .rescue import run_rescue as _run_rescue

    return _run_rescue(target, **kwargs)
