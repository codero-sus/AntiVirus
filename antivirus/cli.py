"""Command line interface for AntiVirus."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path
from typing import Dict, Optional

from . import __version__
from .behavior import analyze_file as behavior_analyze_file
from .behavior import looks_executable as behavior_looks_executable
from .config import Config
from .gui import run_gui
from .monitor import DirectoryWatcher
from .pe import (
    SUBSYSTEM_NAMES,
    parse_pe,
    pe_indicators,
    render_pe_report,
)
from .output import BOLD, CYAN, GREEN, RED, SEVERITY_COLOR, YELLOW, paint
from .quarantine import Quarantine
from .report import ReportWriter, diff_reports, render_report
from .scanner import ScanResult, Scanner
from .selftest import run_selftest
from .signatures import Signature, SignatureDB, VALID_SEVERITIES
from .utils import human_size, parse_since

BUNDLED_SIGNATURES = Path(__file__).resolve().parent.parent / "data" / "signatures.json"


def _argparse_since(text: str) -> float:
    """argparse ``type=`` wrapper around :func:`parse_since`."""
    try:
        return parse_since(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _build(args):
    """Create config + collaborators from CLI arguments."""
    config = Config()
    config.quarantine_dir = Path(args.quarantine_dir)
    config.report_dir = Path(args.report_dir)
    sig_path = Path(args.signatures)
    # A missing DB is fine for `sig import` (a fresh target database) –
    # only the first-run fallback below may replace it.
    if (
        not sig_path.exists()
        and getattr(args, "saction", None) != "import"
        and BUNDLED_SIGNATURES.exists()
    ):
        # First run from a directory without a DB: start from the bundled one.
        sig_path = Path.cwd() / "data" / "signatures.json"
        if not sig_path.exists():
            sig_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(BUNDLED_SIGNATURES, sig_path)
    config.signatures_file = sig_path
    if getattr(args, "max_size", None):
        config.max_file_size = args.max_size
    if getattr(args, "no_behavior", False):
        config.behavior_enabled = False
    if getattr(args, "fast", False):
        config.fast_mode = True
    if getattr(args, "no_cache", False):
        config.cache_enabled = False
    if getattr(args, "no_archives", False):
        config.archives_enabled = False
    if getattr(args, "exclude", None):
        config.exclude_patterns = tuple(args.exclude)
    if getattr(args, "since", 0.0):
        config.since_ts = time.time() - args.since
    config.resolve_paths(Path.cwd())
    db = SignatureDB(config.signatures_file)
    scanner = Scanner(config, db, threads=getattr(args, "threads", "auto"))
    quarantine = Quarantine(config.quarantine_dir)
    return config, db, scanner, quarantine


def _common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--signatures", default="data/signatures.json",
                        help="signature database file (JSON)")
    parser.add_argument("--quarantine-dir", default="quarantine",
                        help="quarantine directory")
    parser.add_argument("--report-dir", default="reports",
                        help="report directory")
    parser.add_argument("--registry-dir", default="registry",
                        help="kill registry directory (key/IV store)")
    parser.add_argument("--max-size", type=int, default=0, metavar="BYTES",
                        help="skip files larger than BYTES")


class _ProgressBar:
    """A single-line scan progress bar written to *stderr* (so stdout
    stays pure for ``--json`` / pipes). Only ticks at most every 0.1 s.
    """

    def __init__(self, interval: float = 0.1) -> None:
        self._interval = interval
        self._last = 0.0
        self._total = 0
        self._width = 30

    def __call__(self, done: int, total: int) -> None:
        self._total = max(total, 1)
        now = time.monotonic()
        if now - self._last < self._interval and done < self._total:
            return
        self._last = now
        frac = min(done / self._total, 1.0)
        filled = int(self._width * frac)
        sys.stderr.write(
            f"\r  [{('#' * filled) + ('.' * (self._width - filled))}] "
            f"{done}/{self._total} files ({frac * 100:3.0f}%)   ")
        sys.stderr.flush()
        if done >= self._total:
            sys.stderr.write("\n")


# --------------------------------------------------------------------- scan
def cmd_scan(args) -> int:
    config, db, scanner, quarantine = _build(args)
    target = Path(args.target)
    if not target.exists():
        print(paint(f"error: no such file or directory: {target}", RED), file=sys.stderr)
        return 2

    # Kill registry: the scanner must know what was already neutralized
    # *before* it starts, so killed files are counted, not re-flagged.
    from .api import neutralized_map
    from .kill import KillRegistry

    kill_registry = KillRegistry(Path(args.registry_dir))
    scanner.neutralized = neutralized_map(kill_registry)

    if getattr(args, "baseline", None) and target.is_dir():
        if config.cache_enabled:
            # A baseline comparison needs the *current* hash of every file.
            config.cache_enabled = False
            if not args.json:
                print(paint(
                    " Baseline mode: scan cache disabled (all files hashed)",
                    YELLOW))

    # A live progress bar on stderr (stdout stays pure for --json/pipes).
    if not args.json and target.is_dir() and sys.stderr.isatty():
        scanner.on_progress = _ProgressBar()
    try:
        result = scanner.scan_path(target)
    except OSError as exc:
        print(paint(f"error: {exc}", RED), file=sys.stderr)
        return 2

    if getattr(args, "baseline", None) and target.is_dir():
        from .integrity import CHANGED, MISSING, NEW

        rc, extra = _apply_baseline(result, target, args.baseline)
        if rc != 0:
            return rc
        if extra and not args.json:
            changed = sum(1 for f in extra if f.name == CHANGED)
            missing = sum(1 for f in extra if f.name == MISSING)
            new = sum(1 for f in extra if f.name == NEW)
            print(paint(
                f" Integrity vs baseline: {changed} changed, "
                f"{missing} missing, {new} new", YELLOW))

    from .api import apply_actions

    notes = apply_actions(result, quarantine, args.action,
                          kill_registry=kill_registry)

    writer = ReportWriter(config.report_dir)
    report_path = writer.save(result, action=args.action, actions_taken=notes)
    workers = scanner._workers()

    if args.json:
        data = result.to_dict()
        data["action"] = args.action
        data["actions_taken"] = notes
        data["threads"] = workers
        data["report"] = str(report_path)
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        _print_scan_summary(result, args.action, notes, report_path, workers)

    return 0 if result.clean else 1


def _print_scan_summary(result: ScanResult, action: str, notes: dict,
                        report_path: Path, workers: int = 1) -> None:
    bar = "=" * 62
    print()
    print(paint(bar, BOLD))
    print(paint(f" AntiVirus {__version__}", BOLD)
          + f"  |  scan of {result.target}  |  action: {action}")
    print(paint(bar, BOLD))
    cached = f"  [{result.files_cached} from scan cache]" if result.files_cached else ""
    print(f" Files scanned:  {result.files_scanned}{cached}  ({human_size(result.bytes_scanned)})")
    print(f" Skipped:        {result.files_skipped}")
    if getattr(result, "files_neutralized", 0):
        print(f" Neutralized:    {result.files_neutralized}  "
              f"(already killed – inert, not re-flagged)")
    print(f" Errors:         {len(result.errors)}")
    print(f" Threads:        {workers} ({'parallel' if workers > 1 else 'sequential'})")
    print(f" Duration:       {result.elapsed:.2f} s")
    print()
    if result.findings:
        color = SEVERITY_COLOR.get(result.worst_severity, YELLOW)
        print(paint(f" Threats found: {len(result.findings)}", color))
        print(paint("-" * 62, BOLD))
        for finding in result.findings:
            fcolor = SEVERITY_COLOR.get(finding.severity, YELLOW)
            print(f"  {paint(f'[{finding.severity.upper()}]', fcolor)} "
                  f"{paint(finding.name, BOLD)}   ({finding.kind})")
            print(f"    file:   {finding.path}")
            print(f"    detail: {finding.message}")
            if finding.path in notes:
                print(f"    action: {notes[finding.path]}")
        print(paint("-" * 62, BOLD))
        _print_top_threats(result)
    else:
        print(paint(" No threats found.", GREEN))
    for err in result.errors[:5]:
        print(paint(f" warning: {err}", YELLOW))
    print(f" Result: {paint('CLEAN' if result.clean else 'INFECTED', GREEN if result.clean else RED)}")
    if action == "kill":
        killed = [n for n in notes.values() if n.startswith("killed")]
        if killed:
            print(f" {paint(str(len(killed)), BOLD)} file(s) killed in place – "
                  f"key/IV stored in the registry (see: antivirus kill list)")
    print(f" Report: {report_path}")
    print(paint(bar, BOLD))


def _print_top_threats(result: ScanResult) -> None:
    """One line per infected file, ranked by worst severity, then size."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    by_file: Dict[str, List[Finding]] = {}
    for f in result.findings:
        by_file.setdefault(f.path, []).append(f)

    def worst_key(path: str):
        sev = min(order.get(f.severity, 9) for f in by_file[path])
        return (sev, -len(by_file[path]))

    ranked = sorted(by_file, key=worst_key)
    print(paint(" Top threats by file:", BOLD))
    for i, path in enumerate(ranked, 1):
        sev = min((f.severity for f in by_file[path]),
                  key=lambda s: order.get(s, 9))
        color = SEVERITY_COLOR.get(sev, YELLOW)
        print(f"  {i}. {paint(f'[{sev.upper()}]', color)}  {path}  "
              f"({len(by_file[path])} finding(s))")


# ------------------------------------------------------------------ monitor
def cmd_monitor(args) -> int:
    config, db, scanner, quarantine = _build(args)
    target = Path(args.target)
    if not target.exists():
        print(paint(f"error: no such file or directory: {target}", RED), file=sys.stderr)
        return 2
    from .api import neutralized_map
    from .kill import KillRegistry

    kill_registry = KillRegistry(Path(args.registry_dir))
    scanner.neutralized = neutralized_map(kill_registry)
    if args.json:
        # Machine-readable mode: one JSON object per event on stdout,
        # human messages suppressed.
        def _emit(event: dict) -> None:
            print(json.dumps(event, ensure_ascii=False), flush=True)

        watcher = DirectoryWatcher(
            scanner, quarantine, action=args.action, interval=args.interval,
            log=lambda level, message: None, on_event=_emit,
            kill_registry=kill_registry)
    else:
        watcher = DirectoryWatcher(scanner, quarantine, action=args.action,
                                   interval=args.interval,
                                   kill_registry=kill_registry)
        print(paint(f"Monitoring {target} – press Ctrl+C to stop", CYAN))
    try:
        watcher.run(target)
    except KeyboardInterrupt:
        if not args.json:
            print(paint("Monitor stopped.", GREEN))
    return 0


# --------------------------------------------------------------- quarantine
def cmd_quarantine(args) -> int:
    config, db, scanner, quarantine = _build(args)
    if args.qaction == "list":
        items = quarantine.items()
        if not items:
            print("Quarantine is empty.")
            return 0
        for item in items:
            print(f"{item.id}")
            print(f"   when:    {item.quarantined_at}")
            print(f"   path:    {item.original_path}")
            print(f"   reason:  {item.reason}")
            print()
        return 0
    try:
        if args.qaction == "restore":
            item, target = quarantine.restore(args.id)
            print(paint(f"Restored {item.id} -> {target}", GREEN))
            return 0
        quarantine.purge(args.id)
        print(paint(f"Purged {args.id}", GREEN))
        return 0
    except (KeyError, ValueError, FileNotFoundError) as exc:
        print(paint(f"error: {exc}", RED), file=sys.stderr)
        return 2


# ---------------------------------------------------------------------- guard
def cmd_guard(args) -> int:
    from .guard import (
        guard_running,
        guard_status,
        run_daemon_cli,
        start_guard,
        stop_guard,
        tail_log,
    )

    if args.gaction == "_daemon":  # spawned by `guard start`; hidden
        return run_daemon_cli(args)

    if args.gaction == "start":
        try:
            info = start_guard(
                args.target, action=args.action, interval=args.interval,
                initial=args.initial, state_dir=args.state_dir,
                signatures=args.signatures)
        except (OSError, ValueError, RuntimeError, FileNotFoundError) as exc:
            print(paint(f"error: {exc}", RED), file=sys.stderr)
            return 2
        print(paint(f" Guard started in the background (pid {info['pid']})", GREEN))
        print(f"  target:   {info['target']}")
        print(f"  action:   {info['action']}   interval: {info['interval']:g}s")
        print(f"  state:    {info['state_dir']}")
        print("  antivirus guard status | antivirus guard log | antivirus guard stop")
        return 0

    status = guard_status(args.state_dir)
    if args.gaction == "stop":
        if guard_running(args.state_dir) is None:
            print("No guard is running.")
            stop_guard(args.state_dir)  # clean up any stale files
            return 0
        print("Stopping guard …", flush=True)
        ok = stop_guard(args.state_dir)
        print(paint(" Guard stopped." if ok else
                    " Guard could not be stopped.",
                    GREEN if ok else RED))
        return 0 if ok else 2

    if args.gaction == "status":
        if not status["running"]:
            last = status.get("last_event") or {}
            print("Guard is not running.")
            if status.get("stopped_at"):
                print(f" Last run: started {status.get('started_at')}, "
                      f"stopped {status['stopped_at']}, "
                      f"{status.get('files_scanned', 0)} file(s) scanned, "
                      f"{status.get('threats_found', 0)} threat(s).")
            return 0
        print(paint(" Guard running", GREEN) + f"  (pid {status['pid']})")
        print(f"  target:   {status['target']}")
        print(f"  action:   {status['action']}   interval: "
              f"{status['interval']:g}s")
        print(f"  started:  {status['started_at']}")
        print(f"  scanned:  {status['files_scanned']} new/changed file(s), "
              f"{status['threats_found']} threat(s)")
        le = status.get("last_event") or {}
        if le:
            print(f"  last:     [{le.get('event')}] {le.get('path', '')}")
        print(f"  state:    {status['state_dir']}")
        return 0

    # guard log
    lines = tail_log(args.state_dir, args.lines)
    if not lines:
        print("Guard log is empty.")
        return 0
    for line in lines:
        print(line)
    return 0


# ----------------------------------------------------------------------- kill
def cmd_kill(args) -> int:
    from .kill import KillRegistry

    registry = KillRegistry(Path(args.registry_dir))
    if args.kaction == "list":
        items = registry.entries()
        if not items:
            print("Kill registry is empty (nothing neutralized yet).")
            return 0
        for item in items:
            print(f"{item.id}")
            print(f"   when:    {item.killed_at}")
            print(f"   path:    {item.original_path}")
            print(f"   size:    {human_size(item.size)}")
            print(f"   reason:  {item.reason}")
            print(f"   key:     {item.key[:8]}…  iv: {item.iv[:8]}…  "
                  f"(stored in {registry.path})")
            print()
        return 0
    try:
        if args.kaction == "revive":
            item, target = registry.revive(args.id)
            print(paint(f"Revived {item.id} -> {target} "
                        f"({human_size(item.size)}, original bytes restored)",
                        GREEN))
            return 0
        registry.purge(args.id)
        print(paint(f"Purged {args.id} (file deleted, registry entry removed "
                    f"– irreversible)", GREEN))
        return 0
    except (KeyError, ValueError, FileNotFoundError) as exc:
        print(paint(f"error: {exc}", RED), file=sys.stderr)
        return 2


# ---------------------------------------------------------------------- sig
def cmd_sig(args) -> int:
    config, db, scanner, quarantine = _build(args)
    if args.saction == "show":
        print(f"Signature database: {config.signatures_file}")
        print(f"{'ID':<22} {'SEVERITY':<10} {'KIND':<14} NAME")
        for s in db.list():
            kind = "+".join(k for k, v in (("sha256", s.sha256),
                                           ("md5", s.md5),
                                           ("pattern", s.pattern)) if v) or "-"
            sev = paint(s.severity.ljust(10), SEVERITY_COLOR.get(s.severity))
            print(f" {s.id:<22} {sev} {kind:<14} {s.name}")
            if s.description:
                print(f" {'':<22} {s.description}")
        return 0
    if args.saction == "remove":
        try:
            removed = db.remove(args.id)
        except KeyError as exc:
            print(paint(f"error: {exc.args[0]}", RED), file=sys.stderr)
            return 2
        print(paint(f"Removed signature {removed.id!r} from {config.signatures_file}",
                    GREEN))
        return 0
    if args.saction == "export":
        out_path = Path(args.file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        sigs = db.list()
        out_path.write_text(json.dumps(
            {"version": 1,
             "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "signatures": [
                 {k: getattr(s, k) for k in
                  ("id", "name", "category", "severity", "description",
                   "sha256", "md5", "pattern")}
                 for s in sigs
             ]},
            indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")
        print(paint(f"Exported {len(sigs)} signature(s) to {out_path}", GREEN))
        return 0
    if args.saction == "import":
        in_path = Path(args.file)
        if not in_path.exists():
            print(paint(f"error: no such file: {in_path}", RED), file=sys.stderr)
            return 2
        text = in_path.read_text(encoding="utf-8")
        try:
            data = json.loads(text)
            items = data if isinstance(data, list) else data.get("signatures", [])
        except json.JSONDecodeError:
            # Not JSON -> treat as a plain-text IOC file (hash lines,
            # ``pattern:`` lines, or literal strings).
            from .signatures import parse_ioc_text

            source = args.source or in_path.stem
            ioc_sigs = parse_ioc_text(text, source=source,
                                      severity=args.severity)
            items = [vars(s) for s in ioc_sigs]
        known = {s.id.lower() for s in db.list()}
        added = skipped = failed = 0
        for item in items:
            try:
                sig = Signature(
                    id=item["id"],
                    name=item.get("name", item["id"]),
                    category=item.get("category", "custom"),
                    severity=item.get("severity", "medium"),
                    description=item.get("description", ""),
                    sha256=(item.get("sha256") or "").lower(),
                    md5=(item.get("md5") or "").lower(),
                    pattern=item.get("pattern", "") or "",
                )
            except (KeyError, TypeError):
                failed += 1
                continue
            if sig.id.lower() in known:
                skipped += 1
                continue
            try:
                db.add(sig, save=False)
                known.add(sig.id.lower())
                added += 1
            except ValueError as exc:
                failed += 1
                print(paint(f" skipped {sig.id!r}: {exc}", YELLOW))
        if added:
            db.save()
        print(paint(
            f"Imported {added} signature(s) from {in_path} "
            f"({skipped} already present, {failed} invalid)", GREEN))
        return 0
    # action: add
    sig = Signature(
        id=args.id,
        name=args.name,
        category=args.category,
        severity=args.severity,
        description=args.description,
        sha256=(args.sha256 or "").lower(),
        md5=(args.md5 or "").lower(),
        pattern=args.pattern or "",
    )
    try:
        db.add(sig)
    except ValueError as exc:
        print(paint(f"error: {exc}", RED), file=sys.stderr)
        return 2
    print(paint(f"Added signature {sig.id!r} to {config.signatures_file}", GREEN))
    return 0


# ----------------------------------------------------------------- manifest
def cmd_manifest(args) -> int:
    config, db, scanner, quarantine = _build(args)
    target = Path(args.target)
    if not target.exists():
        print(paint(f"error: no such file or directory: {target}", RED),
              file=sys.stderr)
        return 2
    try:
        from .integrity import build_manifest, save_manifest

        manifest = build_manifest(target, config)
    except OSError as exc:
        print(paint(f"error: {exc}", RED), file=sys.stderr)
        return 2
    if args.out:
        save_manifest(manifest, Path(args.out))
        print(paint(f"Manifest written: {len(manifest['files'])} file(s) "
                    f"-> {args.out}", GREEN))
        print("Re-check later with:  "
              f"python3 -m antivirus scan {target} --baseline {args.out}")
    else:
        print(json.dumps(manifest, indent=2, ensure_ascii=False))
    return 0


# ------------------------------------------------------------------ verify
def cmd_verify(args) -> int:
    """Fast integrity-only check (hash + diff, no signature scanning)."""
    from .integrity import CHANGED, MISSING, NEW, load_manifest, verify_tree

    config, db, scanner, quarantine = _build(args)
    target = Path(args.target)
    if not target.exists():
        print(paint(f"error: no such file or directory: {target}", RED),
              file=sys.stderr)
        return 2
    bpath = Path(args.baseline)
    if not bpath.exists():
        print(paint(f"error: no such baseline: {bpath}", RED), file=sys.stderr)
        return 2
    try:
        baseline = load_manifest(bpath)
        findings = verify_tree(target, baseline, config)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(paint(f"error: {exc}", RED), file=sys.stderr)
        return 2

    changed = sum(1 for f in findings if f.name == CHANGED)
    missing = sum(1 for f in findings if f.name == MISSING)
    new = sum(1 for f in findings if f.name == NEW)

    if args.json:
        print(json.dumps({
            "target": str(target),
            "baseline": str(bpath),
            "changed": changed, "missing": missing, "new": new,
            "clean": not findings,
            "findings": [f.to_dict() for f in findings],
        }, indent=2, ensure_ascii=False))
    else:
        bar = "=" * 62
        print()
        print(paint(bar, BOLD))
        print(paint(f" Integrity check of {target} vs {bpath.name}", BOLD))
        print(bar)
        if not findings:
            print(paint(" No changes since the baseline.", GREEN))
        else:
            for f in findings:
                color = SEVERITY_COLOR.get(f.severity, YELLOW)
                print(f"  {paint(f'[{f.severity.upper()}]', color)} "
                      f"{paint(f.name, BOLD)}")
                print(f"    file: {f.path}")
        print(paint(f" {changed} changed, {missing} missing, {new} new",
                    YELLOW if findings else GREEN))
        print(bar)
    return 0 if not findings else 1


# ------------------------------------------------------------------- export
def cmd_export(args) -> int:
    """Export findings from saved reports to CSV (default) or JSONL."""
    from .report import (
        EXPORT_COLUMNS,
        ReportWriter,
        iter_export_rows,
        write_export,
    )

    config, db, scanner, quarantine = _build(args)
    writer = ReportWriter(config.report_dir)
    if args.reports:
        paths = []
        for ref in args.reports:
            p = Path(ref)
            if not p.exists():
                p = config.report_dir / ref
            if not p.exists():
                print(paint(f"error: no such report: {ref}", RED),
                      file=sys.stderr)
                return 2
            paths.append(p)
    else:
        paths = writer.all_reports()
    if not paths:
        print(paint("error: no saved reports to export (run a scan first)",
                    RED), file=sys.stderr)
        return 2

    rows = iter_export_rows(paths)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8", newline="") as fh:
            count = write_export(rows, fh, fmt=args.format)
        print(paint(f"Exported {count} finding(s) from {len(paths)} "
                    f"report(s) -> {out_path}", GREEN))
    else:
        count = write_export(rows, sys.stdout, fmt=args.format)
        print(paint(f"({count} finding(s) from {len(paths)} report(s))",
                    YELLOW), file=sys.stderr)
    return 0


# --------------------------------------------------------------------- stats
def cmd_stats(args) -> int:
    """Show engine statistics (signatures, cache, quarantine, reports)."""
    from .api import engine_stats

    config, db, scanner, quarantine = _build(args)
    stats = engine_stats(config, db, quarantine, include_reports=not args.no_reports)
    if args.json:
        print(json.dumps(stats, indent=2, ensure_ascii=False))
        return 0

    bar = "=" * 62
    print()
    print(paint(bar, BOLD))
    print(paint(f" AntiVirus {stats['version']} – engine statistics", BOLD))
    print(bar)
    sig = stats["signatures"]
    sev = ", ".join(f"{k}: {v}" for k, v in sig["by_severity"].items())
    kind = ", ".join(f"{k}: {v}" for k, v in sig["by_kind"].items())
    print(f" Signatures:  {sig['total']}   ({sev})")
    print(f"              kinds -> {kind}")
    print(f"              db     -> {sig['path']}")
    cache = stats["cache"]
    cache_txt = f"{cache['entries']} entries, {human_size(cache['size_bytes'])}" \
        if cache["entries"] or cache["size_bytes"] else "empty / absent"
    print(f" Scan cache:  {cache_txt}   ({cache['path']})")
    q = stats["quarantine"]
    print(f" Quarantine:  {q['items']} item(s)   ({q['path']})")
    if "reports" in stats:
        r = stats["reports"]
        print(f" Reports:     {r['reports']} total "
              f"({r['infected']} infected / {r['clean']} clean), "
              f"{r['total_findings']} finding(s)")
        if r["by_severity"]:
            print("                " + ", ".join(
                f"{k}: {v}" for k, v in r["by_severity"].items()))
    print(bar)
    return 0


# -------------------------------------------------------------- scan baseline
def _apply_baseline(result: ScanResult, target: Path,
                    baseline_file: str) -> tuple:
    """Diff the scan against an integrity baseline.

    Returns ``(0, extra_findings)`` on success or ``(2, None)`` on error.
    """
    import json as _json

    from .integrity import compare_baseline, load_manifest

    bpath = Path(baseline_file)
    if not bpath.exists():
        print(paint(f"error: no such baseline: {bpath}", RED), file=sys.stderr)
        return 2, None
    try:
        baseline = load_manifest(bpath)
    except (ValueError, _json.JSONDecodeError) as exc:
        print(paint(f"error: {bpath}: {exc}", RED), file=sys.stderr)
        return 2, None
    target_resolved = target.resolve()
    current = {}
    for p, meta in result.file_meta.items():
        pp = Path(p)
        try:
            rel = pp.resolve().relative_to(target_resolved)
        except (ValueError, OSError):
            continue
        current[str(rel)] = meta
    extra = compare_baseline(baseline, current)
    if extra:
        result.findings.extend(extra)
    return 0, extra


# --------------------------------------------------------------------- hash
def cmd_hash(args) -> int:
    rows = []
    ok = True
    for name in args.files:
        path = Path(name)
        if not path.is_file():
            print(paint(f"error: no such file: {name}", RED), file=sys.stderr)
            ok = False
            continue
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        try:
            with open(path, "rb") as fh:
                while chunk := fh.read(1024 * 1024):
                    sha256.update(chunk)
                    md5.update(chunk)
                    sha1.update(chunk)
        except OSError as exc:
            print(paint(f"error: {path}: {exc}", RED), file=sys.stderr)
            ok = False
            continue
        rows.append({"file": name,
                     "sha256": sha256.hexdigest(),
                     "md5": md5.hexdigest(),
                     "sha1": sha1.hexdigest(),
                     "size": path.lstat().st_size})
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    else:
        for r in rows:
            print(f"file:   {r['file']}")
            print(f"sha256: {r['sha256']}")
            print(f"md5:    {r['md5']}")
            print(f"sha1:   {r['sha1']}")
            print(f"size:   {r['size']} bytes")
            print()
    return 0 if ok else 2


# ----------------------------------------------------------------- fileinfo
def cmd_fileinfo(args) -> int:
    from .fileinfo import file_info, render_file_info

    ok = True
    for name in args.files:
        p = Path(name)
        if not p.exists():
            print(paint(f"error: no such file: {name}", RED), file=sys.stderr)
            ok = False
            continue
        print(render_file_info(file_info(p)))
        print()
    return 0 if ok else 2


# ------------------------------------------------------------------------ tui
def cmd_tui(args) -> int:
    from .tui import run_tui, tui_available
    from .web import WebApp

    if not tui_available():
        # Windows: CPython does not bundle curses, so there is no TUI.
        print("error: the TUI needs curses, which is not available here "
              "(on Windows, CPython does not bundle it).",
              file=sys.stderr)
        print("Use the CLI (python3 -m antivirus scan .) or the web "
              "console (python3 -m antivirus web) instead.",
              file=sys.stderr)
        return 2
    config, db, scanner, quarantine = _build(args)
    app = WebApp(config, db, scanner, quarantine)
    try:
        return run_tui(app, target=args.target or ".")
    except KeyboardInterrupt:
        return 0


# --------------------------------------------------------------------- rescue
def _cmd_rescue(args) -> int:
    if args.rescue_action == "build":
        return cmd_rescue_build(args)
    if args.rescue_action == "run":
        return cmd_rescue_run(args)
    return cmd_rescue_verify(args)


def cmd_rescue_build(args) -> int:
    from .rescue import build_rescue_disk, build_rescue_kit
    from .utils import human_size

    sig = Path(args.signatures) if args.signatures and \
        Path(args.signatures).exists() else None
    try:
        if args.no_iso:
            manifest = build_rescue_kit(Path(args.out), sig)
        else:
            manifest = build_rescue_disk(Path(args.out),
                                         Path(args.iso), sig)
    except (OSError, ValueError) as exc:
        print(paint(f"error: {exc}", RED), file=sys.stderr)
        return 2

    bar = "=" * 62
    print()
    print(paint(bar, BOLD))
    print(paint(f" Rescue kit built: {manifest['kit']}", BOLD))
    print(bar)
    print(f" Version:        AntiVirus {manifest['antivirus']}")
    print(f" Signatures:     {manifest['signatures']['count']} "
          f"({manifest['signatures']['file']})")
    print(f" Files:          {len(manifest['files'])} (SHA-256 manifest)")
    if "iso" in manifest:
        print(f" ISO image:      {manifest['iso']} "
              f"({human_size(manifest['iso_size'])})")
    print(bar)
    print(" Next steps:")
    print("   1. Copy the kit (or the ISO) to a USB stick.")
    print("   2. Boot a live system (any Linux live USB / rescue VM),")
    print("      mount the infected volume:  sudo mount /dev/sda1 /mnt/disk")
    print(f"   3. Verify the media:    {args.out}/bootstrap.sh --selftest")
    print(f"      Rescue scan:         {args.out}/bootstrap.sh /mnt/disk "
          f"--action quarantine")
    print(f"   Verify the manifest:   antivirus rescue verify {args.out}")
    print(bar)
    return 0


def cmd_rescue_run(args) -> int:
    from .rescue import run_rescue

    target = Path(args.target)
    if not target.exists():
        print(paint(f"error: no such file or directory: {target}", RED),
              file=sys.stderr)
        return 2
    try:
        info = run_rescue(
            target, action=args.action, fast=args.fast,
            since=str(args.since) if args.since else "",
            exclude=tuple(args.exclude) if args.exclude else (),
            quarantine_dir=args.rescue_quarantine,
            report_dir=args.rescue_reports,
            registry_dir=args.rescue_registry)
    except (OSError, ValueError) as exc:
        print(paint(f"error: {exc}", RED), file=sys.stderr)
        return 2
    result = info["result"]

    if args.json:
        data = result.to_dict()
        data["action"] = args.action
        data["actions_taken"] = info["notes"]
        data["rescue"] = {
            "quarantine_dir": info["quarantine_dir"],
            "registry_dir": info["registry_dir"],
            "report": str(info["report"]) if info["report"] else None,
            "signatures": info["signatures_file"],
        }
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        _print_scan_summary(result, args.action, info["notes"],
                            info["report"])
        print(paint(
            f" Quarantine lives on the rescue side: {info['quarantine_dir']} "
            f"(outside the scanned tree)", YELLOW))
        if args.action == "kill":
            print(paint(
                f" Kill registry (key/IV) lives on the rescue side: "
                f"{info['registry_dir']}", YELLOW))
    return 0 if result.clean else 1


def cmd_rescue_verify(args) -> int:
    from .rescue import read_kit_manifest, verify_kit

    problems = verify_kit(Path(args.kit))
    manifest = read_kit_manifest(Path(args.kit))
    if manifest:
        print(f"Kit: {args.kit}  (AntiVirus {manifest['antivirus']}, "
              f"built {manifest['built']}, "
              f"{manifest['signatures']['count']} signature(s))")
    if problems:
        for p in problems:
            print(paint(f"  FAIL: {p}", RED))
        print(paint(f"Verification FAILED ({len(problems)} problem(s)).",
                    RED))
        return 1
    print(paint("Verification OK — every file matches the manifest.",
                GREEN))
    return 0


# ------------------------------------------------------------------ samples
def cmd_samples(args) -> int:
    from .samples import build_all_samples

    root = Path(args.dir)
    try:
        written = build_all_samples(root)
    except OSError as exc:
        print(paint(f"error: {exc}", RED), file=sys.stderr)
        return 2
    print(paint(f"Wrote {len(written)} inert demo sample file(s) to {root}",
                GREEN))
    print("Nothing here is real malware; scan it to test the engine:")
    print(f"  python3 -m antivirus scan {root}")
    return 0


# ------------------------------------------------------------------------ web
def cmd_web(args) -> int:
    from .web import run_web

    config, db, scanner, quarantine = _build(args)
    try:
        return run_web(config, db, scanner, quarantine,
                       host=args.host, port=args.port)
    except OSError as exc:
        print(paint(f"error: {exc}", RED), file=sys.stderr)
        return 2


# ----------------------------------------------------------------- behavior
def cmd_behavior(args) -> int:
    config, db, scanner, quarantine = _build(args)
    path = Path(args.file)
    if not path.is_file():
        print(paint(f"error: no such file: {path}", RED), file=sys.stderr)
        return 2
    try:
        st = path.lstat()
        with open(path, "rb") as fh:
            content = fh.read(config.behavior_max_size)
    except OSError as exc:
        print(paint(f"error: {exc}", RED), file=sys.stderr)
        return 2

    if not behavior_looks_executable(path, content):
        print(f"No behavioural analysis applicable: {path} does not look "
              "executable (no script extension, no shebang, not a PE/ELF).")
        return 0
    findings = behavior_analyze_file(path, st, content)
    if args.json:
        print(json.dumps({"file": str(path),
                          "findings": [f.to_dict() for f in findings]}, indent=2))
    else:
        bar = "=" * 62
        print()
        print(paint(bar, BOLD))
        print(paint(f" Behavioural analysis of {path}", BOLD))
        print(paint(bar, BOLD))
        if not findings:
            print(paint("  No behavioural indicators found.", GREEN))
        for f in findings:
            color = SEVERITY_COLOR.get(f.severity, YELLOW)
            print(f"  {paint(f'[{f.severity.upper()}]', color)} {f.name}")
            print(f"             {f.message}")
        print(paint(bar, BOLD))
    return 0 if not findings else 1


# ------------------------------------------------------------------------ pe
def cmd_pe(args) -> int:
    config, db, scanner, quarantine = _build(args)
    path = Path(args.file)
    if not path.is_file():
        print(paint(f"error: no such file: {path}", RED), file=sys.stderr)
        return 2
    try:
        data = path.read_bytes()
    except OSError as exc:
        print(paint(f"error: {exc}", RED), file=sys.stderr)
        return 2

    info = parse_pe(data)
    indicators = pe_indicators(info)
    if args.json:
        from .pe import _flag_names, _CHAR_FLAGS, _DLL_CHAR_FLAGS

        payload = {
            "file": str(path),
            "valid": info.valid,
            "error": info.error or None,
            "machine": info.machine_name,
            "is_64": info.is_64,
            "characteristics": _flag_names(info.characteristics, _CHAR_FLAGS),
            "dll_characteristics": _flag_names(info.dll_characteristics,
                                               _DLL_CHAR_FLAGS),
            "subsystem": SUBSYSTEM_NAMES.get(info.subsystem, info.subsystem),
            "entry_point_rva": info.entry_point_rva,
            "image_base": info.image_base,
            "sections": [
                {"name": s.name, "vrva": s.vrva, "vsize": s.vsize,
                 "rawsize": s.rawsize, "rawptr": s.rawptr, "flags": s.flags,
                 "entropy": s.entropy}
                for s in info.sections
            ],
            "imports": info.imports,
            "exports": info.exports,
            "resources": [
                {"type": r.type_name or r.type_id, "name_id": r.name_id,
                 "size": r.size, "markers": r.markers}
                for r in info.resources
            ],
            "relocations": {"blocks": info.reloc_blocks,
                            "entries": info.reloc_entries},
            "tls": info.has_tls,
            "debug_dirs": info.debug_dirs,
            "dotnet": info.is_dotnet,
            "indicators": [
                {"name": i.name, "severity": i.severity, "message": i.message}
                for i in indicators
            ],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(render_pe_report(info, indicators))
    return 0 if not indicators else 1


# ------------------------------------------------------------------ report
def cmd_report(args) -> int:
    config, db, scanner, quarantine = _build(args)
    writer = ReportWriter(config.report_dir)
    if args.raction == "list":
        files = sorted(config.report_dir.glob("scan-*.json"))
        if not files:
            print("No reports yet. Run a scan first.")
            return 0
        for f in files:
            data = json.loads(f.read_text(encoding="utf-8"))
            stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(f.stat().st_mtime))
            state = "CLEAN" if data.get("clean") else "INFECTED"
            print(f" {f.name}   {stamp}   {state:<8} "
                  f"{len(data.get('findings', []))} threat(s)   {data.get('target')}")
        return 0
    if args.raction == "diff":
        return _report_diff(config, args)
    if args.raction == "summary":
        return _report_summary(config, writer)
    # action: show
    if args.file:
        path = Path(args.file)
        if not path.exists():
            candidate = config.report_dir / args.file
            if candidate.exists():
                path = candidate
    else:
        path = writer.latest()
    if not path or not path.exists():
        print(paint("error: no such report", RED), file=sys.stderr)
        return 2
    data = json.loads(path.read_text(encoding="utf-8"))
    print(render_report(data))
    return 0


def _load_report_file(config: Config, ref: Optional[str],
                      default_index: int = -1) -> tuple:
    """Resolve a report reference (explicit path, name in the report dir,
    or None = Nth-newest saved report) to (path, data)."""
    writer = ReportWriter(config.report_dir)
    if ref:
        path = Path(ref)
        if not path.exists():
            path = config.report_dir / ref
        if not path.exists():
            raise FileNotFoundError(f"no such report: {ref}")
    else:
        files = writer.all_reports()
        if not files:
            raise FileNotFoundError("no saved reports yet")
        path = files[default_index]
    return path, json.loads(path.read_text(encoding="utf-8"))


def _report_summary(config: Config, writer: "ReportWriter") -> int:
    from .report import summarize_reports

    data = summarize_reports(writer.all_reports())
    if not data["reports"]:
        print("No reports yet. Run a scan first.")
        return 0

    bar = "=" * 62
    print()
    print(paint(bar, BOLD))
    print(paint(f" Report summary: {data['reports']} report(s) "
                f"in {config.report_dir}", BOLD))
    print(bar)
    print(f" Infected reports: {data['infected']}    "
          f"clean: {data['clean']}")
    print(f" Total findings:   {data['total_findings']}")
    if data["by_severity"]:
        parts = [f"{s}: {c}" for s, c in data["by_severity"].items()]
        print(" By severity:      " + "   ".join(parts))
    if data["top_indicators"]:
        print()
        print(paint(" Top indicators:", BOLD))
        for item in data["top_indicators"]:
            print(f"   {item['count']:>4}  {item['name']}")
    print(bar)
    return 0


def _report_diff(config: Config, args) -> int:
    if not args.old and not args.new:
        if len(ReportWriter(config.report_dir).all_reports()) < 2:
            raise FileNotFoundError("diff needs at least two saved reports")
    old_path, old = _load_report_file(config, args.old, default_index=-2)
    new_path, new = _load_report_file(config, args.new, default_index=-1)
    diff = diff_reports(old, new)
    if args.json:
        payload = {
            "old": str(old_path), "new": str(new_path),
            "old_target": old.get("target"), "new_target": new.get("target"),
            "new": diff["new"], "cleared": diff["cleared"],
            "unchanged_count": len(diff["unchanged"]),
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0 if not diff["new"] else 1

    bar = "=" * 62
    print()
    print(paint(bar, BOLD))
    print(paint(f" Report diff: {old_path.name}  ->  {new_path.name}", BOLD))
    print(bar)
    print(f"  old: {old.get('target')}  ({len(old.get('findings', []))} finding(s))")
    print(f"  new: {new.get('target')}  ({len(new.get('findings', []))} finding(s))")
    print()
    if diff["new"]:
        print(paint(f" NEW threats since {old_path.name}: {len(diff['new'])}", RED))
        for f in diff["new"]:
            sev = f.get("severity", "?").upper()
            fc = SEVERITY_COLOR.get(f.get("severity", "info"), YELLOW)
            print(f"  {paint(f'[{sev}]', fc)} {f.get('name')}   {f.get('path')}")
        print()
    if diff["cleared"]:
        print(paint(f" Cleared (in old, not in new): {len(diff['cleared'])}", GREEN))
        for f in diff["cleared"]:
            print(f"  {f.get('name')}   {f.get('path')}")
        print()
    print(f" Unchanged: {len(diff['unchanged'])}")
    print(bar)
    return 0 if not diff["new"] else 1


# --------------------------------------------------------------------- main
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="antivirus",
        description="A lightweight, dependency-free antivirus in pure Python (educational).",
    )
    parser.add_argument("--version", action="version",
                        version=f"antivirus {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="scan a file or directory")
    _common_options(p)
    p.add_argument("target", help="file or directory to scan")
    p.add_argument("--action", choices=("detect", "quarantine", "kill", "delete"),
                   default="detect",
                   help="what to do with threats (kill = obfuscate in place, "
                        "key/IV go to the registry)")
    p.add_argument("--threads", default="auto", metavar="N",
                   help="worker threads for directory scans: auto (default), "
                        "a number, or 1/0 for fully sequential")
    p.add_argument("--no-behavior", action="store_true",
                   help="disable behavioural analysis of executable-looking files")
    p.add_argument("--fast", action="store_true",
                   help="fast mode: hash + pattern layers only (no behaviour, "
                        "no entropy) – for quick rescans")
    p.add_argument("--no-cache", action="store_true",
                   help="ignore the scan cache and re-read every file")
    p.add_argument("--no-archives", action="store_true",
                   help="do not inspect the contents of ZIP archives")
    p.add_argument("--exclude", action="append", default=None, metavar="GLOB",
                   help="skip files whose name or relative path matches GLOB "
                        "(repeatable), e.g. --exclude '*.log'")
    p.add_argument("--since", type=_argparse_since, default=0.0, metavar="DURATION",
                   help="only scan files modified within DURATION "
                        "(30s / 30m / 2h / 1d / 1w / N seconds) – older "
                        "files are skipped and counted as such")
    p.add_argument("--baseline", default=None, metavar="FILE",
                   help="integrity baseline (manifest) to compare against – "
                        "reports changed / missing / new files "
                        "(see: antivirus manifest)")
    p.add_argument("--json", action="store_true", help="machine readable output")

    p = sub.add_parser("monitor", help="watch a directory and scan new/changed files")
    _common_options(p)
    p.add_argument("target", help="directory to watch")
    p.add_argument("--action", choices=("detect", "quarantine", "kill", "delete"),
                   default="detect",
                   help="what to do with threats (kill = obfuscate in place)")
    p.add_argument("--interval", type=float, default=2.0,
                   help="poll interval in seconds (default 2)")
    p.add_argument("--no-behavior", action="store_true",
                   help="disable behavioural analysis of executable-looking files")
    p.add_argument("--no-archives", action="store_true",
                   help="do not inspect the contents of ZIP archives")
    p.add_argument("--exclude", action="append", default=None, metavar="GLOB",
                   help="skip files whose name or relative path matches GLOB "
                        "(repeatable), e.g. --exclude '*.log'")
    p.add_argument("--since", type=_argparse_since, default=0.0, metavar="DURATION",
                   help="only track files modified within DURATION "
                        "(30s / 30m / 2h / 1d / 1w / N seconds)")
    p.add_argument("--json", action="store_true",
                   help="emit one JSON object per event (removed / clean / "
                        "threat / quarantined / deleted / error)")

    p = sub.add_parser("quarantine", help="list, restore or purge quarantined files")
    _common_options(p)
    qsub = p.add_subparsers(dest="qaction", required=True)
    qsub.add_parser("list", help="list quarantined files")
    pr = qsub.add_parser("restore", help="restore a quarantined file")
    pr.add_argument("id", help="quarantine id (a prefix is enough)")
    pp = qsub.add_parser("purge", help="permanently delete a quarantined file")
    pp.add_argument("id", help="quarantine id (a prefix is enough)")

    p = sub.add_parser("kill",
                       help="list, revive or purge in-place killed files "
                            "(key/IV registry)")
    _common_options(p)
    ksub = p.add_subparsers(dest="kaction", required=True)
    ksub.add_parser("list", help="list neutralized files and their registry entries")
    kr = ksub.add_parser("revive",
                         help="restore a killed file's original bytes using "
                              "the registry's key/IV")
    kr.add_argument("id", help="kill registry id (a prefix is enough)")
    kp = ksub.add_parser("purge",
                         help="permanently delete a killed file and its "
                              "registry entry (irreversible)")
    kp.add_argument("id", help="kill registry id (a prefix is enough)")

    p = sub.add_parser(
        "guard", help="background real-time guard: auto-scan new/changed "
                      "files, detached and lightweight")
    gsub = p.add_subparsers(dest="gaction", required=True)

    gs = gsub.add_parser("start", help="start the guard in the background")
    gs.add_argument("target", nargs="?", default=".",
                    help="directory to watch (default .)")
    gs.add_argument("--action",
                    choices=("detect", "quarantine", "kill", "delete"),
                    default="quarantine",
                    help="what to do with threats (default quarantine)")
    gs.add_argument("--interval", type=float, default=5.0, metavar="SECONDS",
                    help="poll interval in seconds (default 5, min 0.5)")
    gs.add_argument("--initial", action="store_true",
                    help="run one full scan of the tree at startup "
                         "(default: watch new/changed files only)")
    gs.add_argument("--state-dir", default="guard", metavar="DIR",
                    help="where pid/state/log/quarantine live (default "
                         "./guard)")
    gs.add_argument("--signatures", default=None, metavar="FILE",
                    help="signature database (default: the usual one)")

    gstop = gsub.add_parser("stop", help="stop the background guard")
    gstop.add_argument("--state-dir", default="guard", metavar="DIR")

    gstat = gsub.add_parser("status", help="show guard status")
    gstat.add_argument("--state-dir", default="guard", metavar="DIR")

    gl = gsub.add_parser("log", help="show recent guard log lines")
    gl.add_argument("--state-dir", default="guard", metavar="DIR")
    gl.add_argument("--lines", type=int, default=30, metavar="N",
                    help="how many lines (default 30)")

    gd = gsub.add_parser("_daemon", help=argparse.SUPPRESS)
    gd.add_argument("--state-dir", default="guard")
    gd.add_argument("--target", required=True)
    gd.add_argument("--action",
                    choices=("detect", "quarantine", "kill", "delete"),
                    default="quarantine")
    gd.add_argument("--interval", type=float, default=5.0)
    gd.add_argument("--initial", action="store_true")
    gd.add_argument("--signatures", default=None)

    p = sub.add_parser("sig", help="inspect or extend the signature database")
    _common_options(p)
    ssub = p.add_subparsers(dest="saction", required=True)
    ssub.add_parser("show", help="list signatures")
    pr = ssub.add_parser("remove", help="remove a signature by id")
    pr.add_argument("id", help="signature id to remove")
    pe = ssub.add_parser("export", help="export the database to a JSON file")
    pe.add_argument("file", help="destination JSON file")
    pi = ssub.add_parser(
        "import", help="merge signatures from a JSON file or a plain-text "
                       "IOC file (hash / pattern lines)")
    # Same options as the parent `sig` parser, but with SUPPRESS defaults
    # so that values given *before* the subcommand (the usual position)
    # are kept, while values given after `import` also work.
    pi.add_argument("--signatures", default=argparse.SUPPRESS,
                    help=argparse.SUPPRESS)
    pi.add_argument("--quarantine-dir", default=argparse.SUPPRESS,
                    help=argparse.SUPPRESS)
    pi.add_argument("--report-dir", default=argparse.SUPPRESS,
                    help=argparse.SUPPRESS)
    pi.add_argument("--max-size", type=int, default=argparse.SUPPRESS,
                    help=argparse.SUPPRESS)
    pi.add_argument("file", help="JSON file (export format) or plain-text "
                                 "IOC file to import from")
    pi.add_argument("--source", default="",
                    help="category stamped on imported signatures "
                         "(plain-text imports; default: the file's stem)")
    pi.add_argument("--severity", choices=VALID_SEVERITIES, default="medium",
                    help="severity for plain-text IOC imports")
    pa = ssub.add_parser("add", help="add a signature")
    pa.add_argument("--id", required=True, help="unique signature id")
    pa.add_argument("--name", required=True, help="human readable name")
    pa.add_argument("--category", default="custom")
    pa.add_argument("--severity", choices=VALID_SEVERITIES, default="medium")
    pa.add_argument("--description", default="")
    pa.add_argument("--sha256", default="", help="full file SHA-256 digest")
    pa.add_argument("--md5", default="", help="full file MD5 digest")
    pa.add_argument("--pattern", default="",
                    help="regular expression matched against raw file bytes")

    p = sub.add_parser(
        "behavior",
        help="static behavioural analysis (what does a file do?)")
    bsub = p.add_subparsers(dest="baction", required=True)
    pa = bsub.add_parser("analyze", help="analyse one file")
    _common_options(pa)
    pa.add_argument("file", help="file to analyse")
    pa.add_argument("--json", action="store_true", help="machine readable output")

    sub.add_parser("gui",
                   help="open the graphical user interface (Tkinter)")

    p = sub.add_parser("pe",
                       help="PE/.exe deep dissection (static 'debug report')")
    esub = p.add_subparsers(dest="eaction", required=True)
    pa = esub.add_parser("analyze",
                         help="dissect a PE image: headers, sections, imports, "
                              "exports, resources, relocations, TLS, debug dirs")
    _common_options(pa)
    pa.add_argument("file", help="PE/.exe file to dissect")
    pa.add_argument("--json", action="store_true",
                    help="machine readable output")

    sub.add_parser("selftest",
                   help="run the built-in self test (harmless EICAR string)")

    p = sub.add_parser("report", help="list, show or diff saved scan reports")
    _common_options(p)
    rsub = p.add_subparsers(dest="raction", required=True)
    rsub.add_parser("list", help="list saved reports")
    ps = rsub.add_parser("show", help="show a report (default: the latest)")
    _common_options(ps)
    ps.add_argument("file", nargs="?", help="report file or name in the report dir")
    py = rsub.add_parser("summary", help="aggregate all saved reports")
    _common_options(py)
    pd = rsub.add_parser(
        "diff",
        help="compare two reports (default: the two newest) and show what "
             "is new / what was cleared")
    pd.add_argument("old", nargs="?", default=None,
                    help="older report (default: 2nd newest)")
    pd.add_argument("new", nargs="?", default=None,
                    help="newer report (default: the newest)")
    _common_options(pd)
    pd.add_argument("--json", action="store_true",
                    help="machine readable output")

    p = sub.add_parser("hash",
                       help="print SHA-256 / MD5 / SHA-1 digests of files")
    p.add_argument("files", nargs="+", help="file(s) to hash")
    p.add_argument("--json", action="store_true",
                   help="machine readable output")

    p = sub.add_parser("manifest",
                       help="build a file-integrity baseline (hashes) for a tree")
    _common_options(p)
    p.add_argument("target", help="file or directory to baseline")
    p.add_argument("--out", default=None, metavar="FILE",
                   help="manifest file (default: print JSON to stdout)")

    p = sub.add_parser("samples",
                       help="write the inert demo sample tree (safe test material)")
    p.add_argument("dir", nargs="?", default="samples",
                   help="destination directory (default: ./samples)")

    p = sub.add_parser("web",
                       help="open the web console (dashboard + JSON API)")
    _common_options(p)
    p.add_argument("--host", default="0.0.0.0",
                   help="bind address (default 0.0.0.0)")
    p.add_argument("--port", type=int, default=8420,
                   help="port (default 8420)")

    p = sub.add_parser("tui",
                       help="terminal UI (curses): live scan, findings, actions")
    _common_options(p)
    p.add_argument("target", nargs="?", default=".",
                   help="initial target (default .)")

    p = sub.add_parser("fileinfo",
                       help="identify one or more files (type, size, digests)")
    p.add_argument("files", nargs="+", help="file(s) to identify")

    p = sub.add_parser(
        "verify",
        help="fast integrity check against a baseline (hash + diff, "
             "no signature scanning)")
    _common_options(p)
    p.add_argument("target", help="file or directory to check")
    p.add_argument("--baseline", required=True, metavar="FILE",
                   help="manifest file (see: antivirus manifest)")
    p.add_argument("--json", action="store_true",
                   help="machine readable output")

    p = sub.add_parser(
        "export",
        help="export findings from saved reports to CSV or JSONL")
    _common_options(p)
    p.add_argument("reports", nargs="*",
                   help="report file or name in the report dir "
                        "(default: all saved reports)")
    p.add_argument("--format", choices=("csv", "jsonl"), default="csv",
                   help="output format (default csv)")
    p.add_argument("--out", default=None, metavar="FILE",
                   help="write to FILE instead of stdout")

    p = sub.add_parser(
        "stats",
        help="engine statistics (signatures, cache, quarantine, reports)")
    _common_options(p)
    p.add_argument("--no-reports", action="store_true",
                   help="skip the report aggregation")
    p.add_argument("--json", action="store_true",
                   help="machine readable output")

    p = sub.add_parser(
        "rescue",
        help="rescue disk: build a self-contained kit/ISO, scan a mounted "
             "volume from a live system, verify a kit")
    rsub = p.add_subparsers(dest="rescue_action", required=True)
    rb = rsub.add_parser(
        "build", help="build the rescue kit (directory + ISO image)")
    _common_options(rb)
    rb.add_argument("--out", default="rescue-kit", metavar="DIR",
                    help="kit directory (default ./rescue-kit)")
    rb.add_argument("--iso", default="rescue.iso", metavar="FILE",
                    help="ISO image path (default ./rescue.iso)")
    rb.add_argument("--no-iso", action="store_true",
                    help="skip the ISO image (directory kit only)")
    rr = rsub.add_parser(
        "run", help="rescue scan of a mounted volume — quarantine goes to "
                    "the rescue side, never into the scanned tree")
    _common_options(rr)
    rr.add_argument("target", help="mounted volume / directory to scan")
    rr.add_argument("--action",
                    choices=("detect", "quarantine", "kill", "delete"),
                    default="detect",
                    help="what to do with threats (kill = obfuscate in "
                         "place, key/IV on the live side)")
    rr.add_argument("--fast", action="store_true",
                    help="hash + pattern layers only")
    rr.add_argument("--since", type=_argparse_since, default=0.0,
                    metavar="DURATION",
                    help="only files modified within DURATION "
                         "(30s / 30m / 2h / 1d / 1w)")
    rr.add_argument("--exclude", action="append", default=None,
                    metavar="GLOB", help="skip matching files (repeatable)")
    rr.add_argument("--rescue-quarantine", default="rescue-quarantine",
                    metavar="DIR",
                    help="quarantine on the live side (default "
                         "./rescue-quarantine)")
    rr.add_argument("--rescue-reports", default="rescue-reports",
                    metavar="DIR", help="report dir on the live side")
    rr.add_argument("--rescue-registry", default="rescue-registry",
                    metavar="DIR",
                    help="kill registry (key/IV store) on the live side")
    rr.add_argument("--json", action="store_true",
                    help="machine readable output")
    rv = rsub.add_parser(
        "verify", help="verify a rescue kit against its SHA-256 manifest")
    rv.add_argument("kit", nargs="?", default="rescue-kit",
                    help="kit directory (default ./rescue-kit)")

    return parser


_COMMANDS = {
    "scan": cmd_scan,
    "monitor": cmd_monitor,
    "quarantine": cmd_quarantine,
    "kill": cmd_kill,
    "guard": cmd_guard,
    "sig": cmd_sig,
    "behavior": cmd_behavior,
    "pe": cmd_pe,
    "gui": lambda args: run_gui(),
    "selftest": lambda args: run_selftest(),
    "report": cmd_report,
    "hash": cmd_hash,
    "manifest": cmd_manifest,
    "samples": cmd_samples,
    "web": cmd_web,
    "tui": cmd_tui,
    "fileinfo": cmd_fileinfo,
    "verify": cmd_verify,
    "export": cmd_export,
    "stats": cmd_stats,
    "rescue": _cmd_rescue,
}


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _COMMANDS[args.command](args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # last line of defence for a friendly error
        print(paint(f"error: {exc}", RED), file=sys.stderr)
        return 2
