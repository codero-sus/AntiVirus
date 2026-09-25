"""Command line interface for AntiVirus."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path
from typing import Optional

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
from .report import ReportWriter, render_report
from .scanner import ScanResult, Scanner
from .selftest import run_selftest
from .signatures import Signature, SignatureDB, VALID_SEVERITIES
from .utils import human_size

BUNDLED_SIGNATURES = Path(__file__).resolve().parent.parent / "data" / "signatures.json"


def _build(args):
    """Create config + collaborators from CLI arguments."""
    config = Config()
    config.quarantine_dir = Path(args.quarantine_dir)
    config.report_dir = Path(args.report_dir)
    sig_path = Path(args.signatures)
    if not sig_path.exists() and BUNDLED_SIGNATURES.exists():
        # First run from a directory without a DB: start from the bundled one.
        sig_path = Path.cwd() / "data" / "signatures.json"
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
    parser.add_argument("--max-size", type=int, default=0, metavar="BYTES",
                        help="skip files larger than BYTES")


# --------------------------------------------------------------------- scan
def cmd_scan(args) -> int:
    config, db, scanner, quarantine = _build(args)
    target = Path(args.target)
    if not target.exists():
        print(paint(f"error: no such file or directory: {target}", RED), file=sys.stderr)
        return 2

    try:
        result = scanner.scan_path(target)
    except OSError as exc:
        print(paint(f"error: {exc}", RED), file=sys.stderr)
        return 2

    notes: dict = {}
    if args.action != "detect":
        handled = set()
        for finding in result.findings:
            if finding.path in handled:
                continue
            handled.add(finding.path)
            path = Path(finding.path)
            if not path.exists():
                notes[finding.path] = "already gone"
            elif args.action == "quarantine":
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
    else:
        print(paint(" No threats found.", GREEN))
    for err in result.errors[:5]:
        print(paint(f" warning: {err}", YELLOW))
    print(f" Result: {paint('CLEAN' if result.clean else 'INFECTED', GREEN if result.clean else RED)}")
    print(f" Report: {report_path}")
    print(paint(bar, BOLD))


# ------------------------------------------------------------------ monitor
def cmd_monitor(args) -> int:
    config, db, scanner, quarantine = _build(args)
    target = Path(args.target)
    if not target.exists():
        print(paint(f"error: no such file or directory: {target}", RED), file=sys.stderr)
        return 2
    watcher = DirectoryWatcher(scanner, quarantine, action=args.action,
                               interval=args.interval)
    print(paint(f"Monitoring {target} – press Ctrl+C to stop", CYAN))
    try:
        watcher.run(target)
    except KeyboardInterrupt:
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
    p.add_argument("--action", choices=("detect", "quarantine", "delete"),
                   default="detect", help="what to do with threats")
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
    p.add_argument("--json", action="store_true", help="machine readable output")

    p = sub.add_parser("monitor", help="watch a directory and scan new/changed files")
    _common_options(p)
    p.add_argument("target", help="directory to watch")
    p.add_argument("--action", choices=("detect", "quarantine", "delete"),
                   default="detect", help="what to do with threats")
    p.add_argument("--interval", type=float, default=2.0,
                   help="poll interval in seconds (default 2)")
    p.add_argument("--no-behavior", action="store_true",
                   help="disable behavioural analysis of executable-looking files")
    p.add_argument("--no-archives", action="store_true",
                   help="do not inspect the contents of ZIP archives")
    p.add_argument("--exclude", action="append", default=None, metavar="GLOB",
                   help="skip files whose name or relative path matches GLOB "
                        "(repeatable), e.g. --exclude '*.log'")

    p = sub.add_parser("quarantine", help="list, restore or purge quarantined files")
    _common_options(p)
    qsub = p.add_subparsers(dest="qaction", required=True)
    qsub.add_parser("list", help="list quarantined files")
    pr = qsub.add_parser("restore", help="restore a quarantined file")
    pr.add_argument("id", help="quarantine id (a prefix is enough)")
    pp = qsub.add_parser("purge", help="permanently delete a quarantined file")
    pp.add_argument("id", help="quarantine id (a prefix is enough)")

    p = sub.add_parser("sig", help="inspect or extend the signature database")
    _common_options(p)
    ssub = p.add_subparsers(dest="saction", required=True)
    ssub.add_parser("show", help="list signatures")
    pr = ssub.add_parser("remove", help="remove a signature by id")
    pr.add_argument("id", help="signature id to remove")
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

    p = sub.add_parser("report", help="list or show saved scan reports")
    _common_options(p)
    rsub = p.add_subparsers(dest="raction", required=True)
    rsub.add_parser("list", help="list saved reports")
    ps = rsub.add_parser("show", help="show a report (default: the latest)")
    ps.add_argument("file", nargs="?", help="report file or name in the report dir")

    return parser


_COMMANDS = {
    "scan": cmd_scan,
    "monitor": cmd_monitor,
    "quarantine": cmd_quarantine,
    "sig": cmd_sig,
    "behavior": cmd_behavior,
    "pe": cmd_pe,
    "gui": lambda args: run_gui(),
    "selftest": lambda args: run_selftest(),
    "report": cmd_report,
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
