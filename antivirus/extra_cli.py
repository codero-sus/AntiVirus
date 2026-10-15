"""v2.8 CLI commands (indicators, rules, exports, diagnostics).

Kept in their own module so ``cli.py`` stays readable; the dispatcher in
``cli.py`` registers these functions.  Everything the commands share with
the main CLI (config building, exit codes, the parser for completion) is
imported lazily *inside* the functions to avoid an import cycle.
"""
from __future__ import annotations

import argparse
import json
import sys
import textwrap
import time
from collections import Counter
from typing import Dict
from pathlib import Path

from . import __version__
from .config import Config
from .output import BOLD, CYAN, GREEN, RED, SEVERITY_COLOR, YELLOW, paint
from .report import ReportWriter
from .utils import human_size, utf16_view

#: severity ordering shared with the main CLI
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _deps():
    """The main CLI's shared helpers (lazy – avoids a circular import)."""
    from . import cli
    return cli


def _exit_code_for(result, fail_on: str) -> int:
    if fail_on == "none":
        return 0
    if fail_on == "any":
        return 0 if result.clean else 1
    threshold = _SEV_RANK.get(fail_on, 3)
    return 1 if any(_SEV_RANK.get(f.severity, 2) >= threshold
                    for f in result.findings) else 0


# --------------------------------------------------------------- indicators
def cmd_indicators(args) -> int:
    """List or explain the technique-indicator checks (v2.8)."""
    from . import indicators as ind_mod

    if getattr(args, "show", None):
        ind = ind_mod.get_check(args.show)
        if ind is None:
            print(paint(f"error: no indicator with id {args.show!r}", RED),
                  file=sys.stderr)
            return 2
        print(paint(ind.id, BOLD))
        print(f"  name:     {ind.name}")
        print(f"  category: {ind.category} - "
              f"{ind_mod.CATEGORY_TITLES.get(ind.category, '')}")
        print(f"  severity: {ind.severity}")
        print(f"  about:    {ind.description}")
        if ind.patterns:
            print("  patterns:")
            for pat in ind.patterns:
                print(f"    {pat}")
        if ind.require:
            print("  requires all of:")
            for pat in ind.require:
                print(f"    {pat}")
        if ind.filenames:
            print("  file names matching:")
            for pat in ind.filenames:
                print(f"    {pat}")
        if ind.tags:
            print(f"  tags:     {', '.join(ind.tags)}")
        return 0

    checks = ind_mod.list_checks(getattr(args, "category", None))
    if getattr(args, "json", False):
        print(json.dumps([c.to_dict() for c in checks], indent=2,
                         ensure_ascii=False))
        return 0
    print(paint(f"Technique indicators ({len(checks)} checks)", BOLD))
    current = None
    for ind in checks:
        if ind.category != current:
            current = ind.category
            print()
            print(paint(f" {current}: "
                        f"{ind_mod.CATEGORY_TITLES.get(current, '')}", CYAN))
        sev = paint(ind.severity.upper().ljust(8),
                    SEVERITY_COLOR.get(ind.severity))
        print(f"   {ind.id:<28} {sev} {ind.name}")
    print()
    print(f" {len(ind_mod.CHECKS)} checks total - "
          f"antivirus indicators --show IND-ID for details")
    return 0


# -------------------------------------------------------------------- rules
def cmd_rules(args) -> int:
    """Manage user-defined detection rules (v2.8)."""
    from . import rules as rules_mod

    path = Path(args.user_rules) if getattr(args, "user_rules", None) \
        else Path("data/user_rules.json")
    action = getattr(args, "raction", "list")

    if action == "list":
        data = rules_mod.summary(path)
        if getattr(args, "json", False):
            print(json.dumps(data, indent=2, ensure_ascii=False))
            return 0
        print(paint(f"User rules: {path}", BOLD))
        if not data["count"]:
            print(" (no user rules yet - add one with "
                  "'antivirus rules add --id USER-1 --pattern ...')")
            return 0
        print(f" {data['count']} rule(s), updated {data['updated'] or '-'}")
        print()
        for rule in data["rules"]:
            sev = paint(rule["severity"].upper().ljust(8),
                        SEVERITY_COLOR.get(rule["severity"]))
            glob = rules_mod.filename_condition(path, rule["id"])
            extra = f"  [file name: {glob}]" if glob else ""
            print(f" {rule['id']:<24} {sev} {rule['name']}{extra}")
            print(f" {'':<24} pattern: {rule['pattern']}")
        return 0

    if action == "add":
        try:
            sig = rules_mod.add_rule(
                path, args.id, args.pattern, args.severity,
                name=args.name or "", description=args.description or "",
                filename=args.filename or "", family=args.family or "")
        except ValueError as exc:
            print(paint(f"error: {exc}", RED), file=sys.stderr)
            return 2
        print(paint(f"Rule {sig.id!r} installed in {path}", GREEN))
        return 0

    if action == "remove":
        try:
            removed = rules_mod.remove_rule(path, args.id)
        except KeyError as exc:
            print(paint(f"error: {exc.args[0]}", RED), file=sys.stderr)
            return 2
        print(paint(f"Removed rule {removed.id!r}", GREEN))
        return 0

    if action == "import":
        src = Path(args.file)
        if not src.is_file():
            print(paint(f"error: no such file: {src}", RED), file=sys.stderr)
            return 2
        try:
            count = rules_mod.import_ioc_text(
                path, src.read_text(encoding="utf-8", errors="replace"),
                source=args.source or "ioc-import", severity=args.severity)
        except ValueError as exc:
            print(paint(f"error: {exc}", RED), file=sys.stderr)
            return 2
        print(paint(f"Imported {count} pattern rule(s) from {src} into {path}",
                    GREEN))
        return 0

    if action == "test":
        target = Path(args.file)
        if not target.is_file():
            print(paint(f"error: no such file: {target}", RED), file=sys.stderr)
            return 2
        if args.id:
            matching = [r for r in rules_mod.list_rules(path)
                        if r.id.lower() == args.id.lower()]
            if not matching:
                print(paint(f"error: no rule with id {args.id!r}", RED),
                      file=sys.stderr)
                return 2
            pattern = matching[0].pattern
            glob = rules_mod.filename_condition(path, matching[0].id)
        elif args.pattern:
            pattern, glob = args.pattern, args.filename or ""
        else:
            print(paint("error: give a rule id or --pattern to test", RED),
                  file=sys.stderr)
            return 2
        try:
            hits = rules_mod.test_rule(pattern, target.read_bytes(),
                                       target.name, glob)
        except ValueError as exc:
            print(paint(f"error: {exc}", RED), file=sys.stderr)
            return 2
        if hits:
            print(paint(f"MATCH: {target} ({len(hits)} hit(s))", RED))
            for hit in hits:
                print(f"   ...{hit}...")
            return 1
        print(paint(f"no match: {target}", GREEN))
        return 0

    print(paint(f"error: unknown rules action {action!r}", RED),
          file=sys.stderr)
    return 2


# ----------------------------------------------------------- report exports
def _scan_once(args):
    """Build the engine from *args* and scan ``args.target``."""
    cli = _deps()
    config, db, scanner, quarantine = cli._build(args)
    target = Path(args.target)
    if not target.exists():
        raise FileNotFoundError(f"no such file or directory: {target}")
    return scanner.scan_path(target), config, target


def cmd_sarif(args) -> int:
    """Write a SARIF 2.1.0 report of a scan (CI code-scanning format)."""
    from . import exporters

    try:
        result, _config, target = _scan_once(args)
    except OSError as exc:
        print(paint(f"error: {exc}", RED), file=sys.stderr)
        return 2
    base = target if target.is_dir() else target.parent
    text = exporters.render_sarif(result, base=base)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(paint(f"SARIF report written to {out} "
                    f"({len(result.findings)} finding(s))", GREEN))
    else:
        print(text, end="")
    return _exit_code_for(result, getattr(args, "fail_on", "any"))


def cmd_html(args) -> int:
    """Write a standalone HTML report of a scan."""
    from . import exporters

    try:
        result, _config, target = _scan_once(args)
    except OSError as exc:
        print(paint(f"error: {exc}", RED), file=sys.stderr)
        return 2
    base = target if target.is_dir() else target.parent
    title = args.title or f"AntiVirus scan report - {result.target}"
    if args.out:
        path = exporters.write_html(result, Path(args.out), base=base,
                                    title=title)
        print(paint(f"HTML report written to {path} "
                    f"({len(result.findings)} finding(s))", GREEN))
    else:
        print(exporters.render_html(result, base=base, title=title), end="")
    if getattr(args, "fail_on", None):
        return _exit_code_for(result, args.fail_on)
    return 0


# ------------------------------------------------------------------ strings
def cmd_strings(args) -> int:
    """Extract printable strings from a file (ASCII + optional UTF-16)."""
    import re as _re

    path = Path(args.file)
    if not path.is_file():
        print(paint(f"error: no such file: {path}", RED), file=sys.stderr)
        return 2
    try:
        data = path.read_bytes()[: args.max_bytes]
    except OSError as exc:
        print(paint(f"error: {exc}", RED), file=sys.stderr)
        return 2
    min_len = max(int(args.min), 2)
    rx = _re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    hits = [(m.start(), m.group().decode("latin-1"), "ascii")
            for m in rx.finditer(data)]
    if args.utf16:
        wide = utf16_view(data)
        if wide:
            hits += [(m.start(), m.group().decode("latin-1"), "utf16")
                     for m in rx.finditer(wide)]
    if args.grep:
        try:
            gx = _re.compile(args.grep, _re.IGNORECASE)
        except _re.error as exc:
            print(paint(f"error: bad --grep pattern: {exc}", RED),
                  file=sys.stderr)
            return 2
        hits = [h for h in hits if gx.search(h[1])]
    hits.sort(key=lambda h: h[0])
    if args.max:
        hits = hits[: int(args.max)]
    if args.json:
        print(json.dumps([{"offset": off, "string": text, "encoding": enc}
                          for off, text, enc in hits],
                         indent=2, ensure_ascii=False))
        return 0
    if not hits:
        print(paint("no strings found", YELLOW))
        return 0
    for off, text, enc in hits:
        tag = "" if enc == "ascii" else "  [utf16]"
        print(f"{off:010d}  {text}{tag}")
    print(f"\n {len(hits)} string(s) of >= {min_len} chars "
          f"from {human_size(len(data))}")
    return 0


# ------------------------------------------------------------------ entropy
def cmd_entropy(args) -> int:
    """Report Shannon entropy and the byte histogram of files."""
    from .models import shannon_entropy

    rows, ok = [], True
    for name in args.files:
        path = Path(name)
        if not path.is_file():
            print(paint(f"error: no such file: {name}", RED), file=sys.stderr)
            ok = False
            continue
        try:
            data = path.read_bytes()[: args.sample]
        except OSError as exc:
            print(paint(f"error: {exc}", RED), file=sys.stderr)
            ok = False
            continue
        counts = Counter(data)
        entropy = shannon_entropy(data)
        rows.append({
            "file": name, "bytes_sampled": len(data),
            "entropy": round(entropy, 4), "distinct_bytes": len(counts),
            "top_bytes": [{"byte": f"0x{b:02x}", "count": c}
                          for b, c in counts.most_common(5)],
            "verdict": ("packed or encrypted"
                        if entropy >= 7.5 and len(data) >= 256 * 1024
                        else "text-like" if entropy < 5.0 else "normal"),
        })
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    else:
        for row in rows:
            print(paint(row["file"], BOLD))
            print(f"  entropy:        {row['entropy']:.4f} bits/byte "
                  f"({row['bytes_sampled']} bytes sampled)")
            print(f"  distinct bytes: {row['distinct_bytes']}/256")
            print("  top bytes:      " + ", ".join(
                f"{t['byte']} x{t['count']}" for t in row["top_bytes"]))
            print(f"  verdict:        {row['verdict']}")
            print()
    return 0 if ok else 2


# ------------------------------------------------------------------- doctor
def cmd_doctor(args) -> int:
    """Environment self-check: paths, databases, permissions, clock."""
    import shutil as _shutil

    cli = _deps()
    config, db, scanner, quarantine = cli._build(args)
    checks = []

    def check(name, fn):
        try:
            ok, detail = fn()
        except Exception as exc:  # a broken environment must not crash doctor
            ok, detail = False, f"exception: {exc}"
        checks.append((name, bool(ok), str(detail)))

    check("python version",
          lambda: (sys.version_info >= (3, 8),
                   f"{sys.version.split()[0]} (need >= 3.8)"))
    check("signature database",
          lambda: (Path(config.signatures_file).exists(),
                   f"{config.signatures_file} - {len(db.list())} signature(s)"))
    broken = [s.id for s in db.list() if s.pattern and s.compiled is None]
    check("signature patterns compile",
          lambda: (not broken, "all patterns compile" if not broken
                   else f"{len(broken)} broken: {', '.join(broken[:3])}"))
    ids = [s.id.lower() for s in db.list()]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    check("no duplicate signature ids",
          lambda: (not dupes,
                   "unique" if not dupes else f"duplicates: {dupes[:3]}"))
    check("threat intel database",
          lambda: (not Path(config.threat_intel_file).exists()
                   or Path(config.threat_intel_file).stat().st_size > 2,
                   str(config.threat_intel_file)))
    from . import rules as rules_mod
    rules_summary = rules_mod.summary(config.user_rules_file)
    check("user rules",
          lambda: (True, f"{rules_summary['count']} rule(s) in "
                   f"{config.user_rules_file}"))
    from . import indicators as ind_mod
    check("indicator table",
          lambda: (len(ind_mod.CHECKS) >= 50,
                   f"{len(ind_mod.CHECKS)} technique checks"))

    for label, directory in (("quarantine", config.quarantine_dir),
                             ("reports", config.report_dir),
                             ("scan cache", config.cache_dir),
                             ("kill registry", config.registry_dir)):
        def _writable(d=directory):
            d = Path(d)
            d.mkdir(parents=True, exist_ok=True)
            probe = d / ".doctor-write-test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            return True, f"{d} writable"
        check(f"{label} directory", _writable)

    check("disk space (cwd)",
          lambda: (True, f"{human_size(_shutil.disk_usage('.').free)} free"))
    check("clock",
          lambda: (time.time() > 1_600_000_000,
                   time.strftime("%Y-%m-%d %H:%M:%S %Z")))
    check("metrics file",
          lambda: (True, f"{config.metrics_file} "
                   f"({'present' if Path(config.metrics_file).exists() else 'not yet written'})"))
    check("terminals",
          lambda: (True, f"stdout isatty={sys.stdout.isatty()}"))

    if args.json:
        print(json.dumps([{"check": n, "ok": o, "detail": d}
                          for n, o, d in checks], indent=2,
                         ensure_ascii=False))
    else:
        print(paint(f"AntiVirus doctor ({__version__})", BOLD))
        print()
        for name, ok, detail in checks:
            mark = paint("  ok  ", GREEN) if ok else paint(" FAIL ", RED)
            print(f" [{mark}] {name:<26} {detail}")
        failed = [n for n, ok, _ in checks if not ok]
        print()
        if failed:
            print(paint(f" {len(failed)} check(s) failed: "
                        f"{', '.join(failed)}", RED))
        else:
            print(paint(" all checks passed", GREEN))
    return 0 if all(ok for _, ok, _ in checks) else 1


# --------------------------------------------------------------- completion
def _completion_data():
    """``{command: [options]}`` introspected from the real parser."""
    cli = _deps()
    parser = cli.build_parser()
    data = {}
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                opts = []
                for sub_action in sub._actions:
                    opts.extend(sub_action.option_strings)
                data[name] = sorted(set(opts))
    return data


def cmd_completion(args) -> int:
    """Emit a shell completion script (bash / zsh / fish)."""
    data = _completion_data()
    commands = sorted(data)
    if args.shell == "bash":
        cases = "\n".join(
            f"    {cmd}) opts=\"{' '.join(opts)}\" ;;"
            for cmd, opts in sorted(data.items()))
        print(f"""# AntiVirus bash completion - eval "$(antivirus completion bash)"
_antivirus_complete() {{
  local cur prev cmd opts
  cur="${{COMP_WORDS[COMP_CWORD]}}"
  prev="${{COMP_WORDS[COMP_CWORD-1]}}"
  cmd="${{COMP_WORDS[1]}}"
  opts="{' '.join(commands)}"
  if [ "$COMP_CWORD" -gt 1 ]; then
    case "$cmd" in
{cases}
    esac
  fi
  COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
  return 0
}}
complete -F _antivirus_complete antivirus""")
    elif args.shell == "zsh":
        items = "\n".join(f"    '{cmd}:{cmd} command'" for cmd in commands)
        print(f"""# AntiVirus zsh completion - source <(antivirus completion zsh)
_antivirus() {{
  local -a commands
  commands=(
{items}
  )
  _arguments '1:command:->cmds' '*::arg:->args'
  case $state in
    cmds) _describe 'command' commands ;;
  esac
}}
compdef _antivirus antivirus""")
    else:  # fish
        print("# AntiVirus fish completion - antivirus completion fish | source")
        for cmd in commands:
            print(f"complete -c antivirus -n '__fish_use_subcommand' -a {cmd}")
        for cmd, opts in sorted(data.items()):
            for opt in opts:
                if opt.startswith("--"):
                    print(f"complete -c antivirus -n "
                          f"'__fish_seen_subcommand_from {cmd}' -l {opt[2:]}")
    return 0


# ------------------------------------------------------------------ metrics
def cmd_metrics(args) -> int:
    """Cumulative engine counters (JSON or Prometheus text)."""
    from . import metrics as metrics_mod

    config = Config()
    path = Path(args.metrics) if args.metrics else config.metrics_file
    if args.reset:
        metrics_mod.reset(path)
        print(paint(f"metrics reset: {path}", GREEN))
        return 0
    data = metrics_mod.load(path)
    if args.format == "prometheus":
        print(metrics_mod.render_prometheus(data), end="")
    else:
        print(json.dumps(metrics_mod.summary(data), indent=2,
                         ensure_ascii=False))
    return 0


# ------------------------------------------------------------------ history
def cmd_history(args) -> int:
    """Recent scans, from the saved reports (newest first)."""
    config = Config()
    config.report_dir = Path(args.report_dir)
    config.resolve_paths(Path.cwd())
    writer = ReportWriter(config.report_dir)
    reports = sorted(writer.all_reports(),
                     key=lambda p: p.stat().st_mtime if p.exists() else 0,
                     reverse=True)[: args.limit]
    rows = []
    for path in reports:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        findings = data.get("findings") or []
        worst = "info"
        for f in findings:
            if _SEV_RANK.get(f.get("severity", "info"), 0) > _SEV_RANK[worst]:
                worst = f["severity"]
        rows.append({
            "report": str(path),
            "when": time.strftime("%Y-%m-%d %H:%M:%S",
                                  time.localtime(path.stat().st_mtime)),
            "target": data.get("target", "?"),
            "action": data.get("action", "detect"),
            "files_scanned": data.get("files_scanned", 0),
            "findings": len(findings),
            "worst": worst if findings else "-",
            "clean": not findings,
        })
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    if not rows:
        print(paint("no saved reports yet (run a scan first)", YELLOW))
        return 0
    print(paint(f"Scan history ({len(rows)} most recent)", BOLD))
    print(f" {'WHEN':<20} {'FILES':>7} {'FINDINGS':>9} {'WORST':<9} TARGET")
    for row in rows:
        color = GREEN if row["clean"] else SEVERITY_COLOR.get(row["worst"], YELLOW)
        print(f" {row['when']:<20} {row['files_scanned']:>7} "
              f"{row['findings']:>9} {paint(row['worst'].ljust(9), color)} "
              f"{row['target']}  ({row['action']})")
    return 0


# ------------------------------------------------------------------ version
def cmd_version(args) -> int:
    """Version and engine inventory (``--json`` for machines)."""
    from . import indicators as ind_mod
    from . import rules as rules_mod
    from .engine import _ENGINES
    from .cli import BUNDLED_SIGNATURES, _COMMANDS
    from .signatures import SignatureDB

    sig_path = Path(args.signatures) if args.signatures else BUNDLED_SIGNATURES
    try:
        sig_count = len(SignatureDB(sig_path).list())
    except Exception:
        sig_count = 0
    rule_count = rules_mod.summary(
        args.user_rules or "data/user_rules.json")["count"]
    from . import feeds as feeds_mod

    feed_stats = feeds_mod.FeedDB(Path(getattr(args, "feeds_dir", None)
                                       or "data/feeds")).stats()
    info = {
        "version": __version__,
        "python": sys.version.split()[0],
        "engines": list(_ENGINES),
        "engine_count": len(_ENGINES),
        "signatures": sig_count,
        "indicators": len(ind_mod.CHECKS),
        "user_rules": rule_count,
        "feeds": {
            "built": feed_stats["built"],
            "indicators": feed_stats["tokens"],
            "patterns": feed_stats["patterns"],
            "sources": feed_stats["sources"],
            "built_at": feed_stats["built_at"],
            "by_license": feed_stats["by_license"],
        },
        "commands": sorted(_COMMANDS),
    }
    if args.json:
        print(json.dumps(info, indent=2, ensure_ascii=False))
        return 0
    print(paint(f"AntiVirus {__version__}", BOLD))
    print(f" python      {info['python']}")
    print(f" engines     {info['engine_count']}: {', '.join(info['engines'])}")
    print(f" signatures  {sig_count} (bundled database)")
    print(f" indicators  {info['indicators']} technique checks")
    print(f" user rules  {rule_count}")
    feeds = info["feeds"]
    if feeds["built"]:
        print(f" feeds       {feeds['indicators']:,} indicators, "
              f"{feeds['patterns']:,} converted patterns "
              f"({feeds['sources']} source(s), {feeds['built_at']})")
    else:
        print(" feeds       none built (antivirus feeds build)")
    print(f" commands    {len(info['commands'])}")
    return 0


# -------------------------------------------------------------------- feeds
def cmd_feeds(args) -> int:
    """Public threat-intel feeds: list, build, import, stats, audit, verify."""
    from . import feeds as feeds_mod

    action = getattr(args, "feeds_action", None) or "stats"
    root = Path(getattr(args, "feeds_dir", None) or "data/feeds")

    if action == "list":
        rows = []
        for source in feeds_mod.SOURCES:
            rows.append({
                "id": source.id, "provider": source.provider,
                "category": source.category, "kind": source.kind,
                "license": source.license,
                "redistribution": source.redistribution,
                "path": f"{source.repo}/{source.path}",
                "note": source.note,
            })
        if args.json:
            print(json.dumps(rows, indent=2, ensure_ascii=False))
            return 0
        print(paint(f"{len(rows)} vetted public feed source(s)", BOLD))
        for row in rows:
            tag = ("ship" if row["redistribution"] == "redistributable"
                   else "runtime-only")
            print(f"  {row['id']:28} {row['kind']:8} {row['license']:28} [{tag}]")
            print(f"      {row['provider']} – {row['category']}"
                  f"  ({row['path']})")
        print("\n  build them with:  antivirus feeds build")
        return 0

    if action == "build":
        only = list(args.source or [])
        include_restricted = bool(getattr(args, "all_sources", False) or only)
        chosen = feeds_mod.build_sources(include_restricted=include_restricted,
                                         only=only or None)
        if not chosen:
            print("no source matched – see `antivirus feeds list`",
                  file=sys.stderr)
            return 2
        print(paint(f"building {len(chosen)} feed source(s) into {root}",
                    BOLD))
        if not include_restricted:
            print("  (licence-safe default: redistributable sources only; "
                  "add --all for runtime-only sources)")
        report = feeds_mod.build(
            chosen, root,
            include_restricted=include_restricted,
            max_per_source=getattr(args, "limit", None),
            max_patterns=getattr(args, "max_patterns", 20000),
            benign=feeds_mod.load_benign_corpus("samples"),
            progress=(None if args.json else lambda message: print(" ", message)))
        if args.json:
            print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        else:
            print(paint("\nindexes", BOLD))
            for key, meta in sorted(report.indexes.items()):
                print(f"  {key:18} {meta['count']:>9,} entries"
                      f"  ({meta['bytes'] / 1e6:.1f} MB)")
            print(f"  {'patterns':18} {report.patterns:>9,} signatures")
            print(f"  total tokens: {report.total_tokens:,}")
            if report.skipped:
                print("  skipped: " + ", ".join(
                    f"{k}={v:,}" for k, v in report.skipped.items()))
            for error in report.errors:
                print(paint(f"  error: {error}", RED), file=sys.stderr)
        return 0 if not report.errors else 1

    if action == "import-clamav":
        path = Path(args.file)
        if not path.exists():
            print(paint(f"error: no such file: {path}", RED), file=sys.stderr)
            return 2
        print(f"importing {path} into {root} …")
        report = feeds_mod.import_clamav_file(
            path, root, max_patterns=getattr(args, "max_patterns", 20000),
            benign=feeds_mod.load_benign_corpus("samples"))
        if args.json:
            print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
            return 0
        for key, meta in sorted(report.indexes.items()):
            print(f"  {key:18} {meta['count']:>9,} entries")
        print(f"  {'patterns':18} {report.patterns:>9,} signatures")
        if report.skipped:
            print("  skipped: " + ", ".join(
                f"{k}={v:,}" for k, v in report.skipped.items()))
        print("  note: imported signatures stay on this machine; the ClamAV "
              "database is not redistributed by this project.")
        return 0

    if action == "clear":
        removed = feeds_mod.clear(root)
        print(f"removed {removed} feed file(s) from {root}")
        return 0

    if action == "verify":
        result = feeds_mod.verify(root)
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0 if result["ok"] else 1
        status = paint("ok", GREEN) if result["ok"] else paint("FAILED", RED)
        print(f"feeds verify: {status} – {result['checked']} index(es), "
              f"{result['patterns']} pattern(s)")
        for error in result["errors"]:
            print(f"  {error}", file=sys.stderr)
        return 0 if result["ok"] else 1

    if action in ("audit", "stats"):
        db = feeds_mod.FeedDB(root)
        stats = db.stats()
        manifest = db.manifest()
        if args.json:
            print(json.dumps({"stats": stats, "sources": manifest.get(
                "sources", [])}, indent=2, ensure_ascii=False))
            return 0
        if not stats["built"]:
            print(paint("no feed database built yet", BOLD))
            print(f"  directory: {root}")
            print("  build it with:  antivirus feeds build"
                  "        (downloads from public GitHub sources)")
            return 0
        print(paint("feed database", BOLD))
        print(f"  built      {stats['built_at']}")
        print(f"  directory  {stats['root']}")
        print(f"  tokens     {stats['tokens']:,}")
        print(f"  patterns   {stats['patterns']:,}")
        print(f"  buckets    {len(stats['indexes'])}")
        if action == "audit":
            print(paint("\nsources (provenance + licence)", BOLD))
            for source in manifest.get("sources", []):
                state = source.get("status", "?")
                print(f"  {source.get('id', '?'):28} {state:6} "
                      f"{source.get('tokens', 0):>9,} tokens  "
                      f"{source.get('license', '?')}")
                if source.get("raw_sha256"):
                    print(f"      sha256 {source['raw_sha256'][:32]}…  "
                          f"({source.get('raw_bytes', 0) / 1e6:.1f} MB)  "
                          f"{source.get('redistribution', '')}")
                if source.get("skipped"):
                    print("      skipped: " + ", ".join(
                        f"{k}={v:,}" for k, v in source["skipped"].items()))
            print(paint("\nlicence mix (tokens)", BOLD))
            for license_name, count in sorted(stats["by_license"].items(),
                                              key=lambda kv: -kv[1]):
                print(f"  {count:>9,}  {license_name}")
        else:
            for key, count in sorted(stats["indexes"].items()):
                print(f"  {key:18} {count:>9,}")
        return 0

    print(f"unknown feeds action: {action}", file=sys.stderr)
    return 2


# ------------------------------------------------------------------ explain
_GLOSSARY = {
    "signature-hash": "The file's SHA-256/MD5 is in the signature database - a definite match for a known sample.",
    "feed-ioc": "A domain or IP address inside the file appears in the public feed database (build it with `antivirus feeds build`).",
    "signature-pattern": "A signature pattern (family marker, IOC string or user rule) was found in the file body.",
    "indicator": "An attack *technique* marker was found (LOLBin, persistence, evasion, credential access, impact...). Technique markers describe what the file does, not which family it is.",
    "behavior": "Static behavioural analysis: the file looks executable and imports/uses APIs associated with that behaviour.",
    "suspicious": "The suspicion engine scored the file (name tricks, type mismatch, entropy, location) above the threshold.",
    "malicious_url": "Web shield: a URL inside the file matches threat intel or scores as risky.",
    "archive": "A finding inside an archive (member flagged, zip-slip/tar-slip path traversal, or an entry limit).",
    "polyglot": "One file is valid in two or more formats (PDF/PE, image/PE, text + binary blob).",
    "obfuscation": "The file hides its content: encoded blobs, double encoding, junk code, packed PE without imports.",
    "integrity": "Mutation detection: the content of a trusted file changed since the trust baseline, or a trusted file is missing.",
    "heuristic": "Generic heuristic (e.g. high Shannon entropy for the file's size).",
    "info": "Severity: informational - context, no action needed.",
    "low": "Severity: low - worth a look when convenient.",
    "medium": "Severity: medium - suspicious; review or quarantine.",
    "high": "Severity: high - very likely malicious or a dangerous technique.",
    "critical": "Severity: critical - known malware, or an attack step with immediate impact (ransomware encryption, credential dump).",
}


def cmd_explain(args) -> int:
    """Explain a finding kind, a severity, or an indicator id."""
    from . import indicators as ind_mod

    topic = args.topic
    if ind_mod.get_check(topic) is not None:
        return cmd_indicators(argparse.Namespace(show=topic, json=False,
                                                 category=None))
    text = _GLOSSARY.get(topic.lower())
    if text is None and "_" in topic:
        text = _GLOSSARY.get(topic.lower().replace("_", "-"))
    if text is None:
        print(paint(f"unknown topic {topic!r}", RED), file=sys.stderr)
        print(" known topics: " + ", ".join(sorted(_GLOSSARY)),
              file=sys.stderr)
        return 2
    print(paint(topic, BOLD))
    print(textwrap.fill(text, 78, initial_indent="  ", subsequent_indent="  "))
    return 0


# --------------------------------------------------------------------------
# allowlist (v3.0) – false-positive suppression that is auditable
# --------------------------------------------------------------------------
def _allow_file(args) -> Path:
    return Path(getattr(args, "allowlist_file", None) or "data/allowlist.json")


def cmd_allowlist(args) -> int:
    """Manage the false-positive allowlist (hashes, names, paths, domains)."""
    from . import allowlist as al_mod

    action = getattr(args, "allowlist_action", None) or "list"
    if action == "audit":
        return cmd_allowlist_audit(args)
    path = _allow_file(args)
    allow = al_mod.AllowList.load(path)

    if action == "list":
        stats = allow.stats()
        if args.json:
            print(json.dumps({"path": str(path), "stats": stats,
                              "entries": [e.to_dict() for e in allow.entries]},
                             indent=2, ensure_ascii=False))
            return 0
        print(paint(f"allowlist {path} – {stats['total']} entry(s)", BOLD))
        if not allow.entries:
            print("  empty: nothing is suppressed")
            print("  add with:  antivirus allowlist add hash <sha256> --note why")
            return 0
        print("  " + "  ".join(f"{k}={v}" for k, v in stats.items()
                               if k != "total" and v))
        for entry in allow.entries:
            print(f"  {entry.id:16} {entry.kind:6} {entry.value[:64]}")
            meta = " – ".join(x for x in (entry.note, entry.added_at,
                                          entry.source) if x)
            if meta:
                print(f"      {meta}")
        return 0

    if action in ("add", "allow"):
        kind = getattr(args, "kind", None)
        value = getattr(args, "value", None)
        targets = list(getattr(args, "targets", None) or [])
        if not kind and len(targets) >= 2:
            kind, value = targets[0], targets[1]
        elif not kind and len(targets) == 1:
            value = targets[0]
        if not value and getattr(args, "file", None):
            entry = al_mod.add_hash_from_file(
                allow, Path(args.file), note=args.note or "")
            allow.save()
            print(f"allowlisted {entry.kind} {entry.value}")
            return 0
        if not kind:
            print("usage: antivirus allowlist add hash|name|path|domain VALUE "
                  "[--note why]", file=sys.stderr)
            return 2
        try:
            entry, created = allow.add(kind, value, note=getattr(args, "note", "")
                                       or "")
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if created:
            allow.save()
            print(f"allowlisted {entry.kind} {entry.value}")
        else:
            print(f"already allowlisted: {entry.kind} {entry.value}")
        return 0

    if action in ("remove", "delete", "rm"):
        target = getattr(args, "value", None) or (
            (getattr(args, "targets", None) or [""])[0])
        if not target:
            print("usage: antivirus allowlist remove ID|VALUE", file=sys.stderr)
            return 2
        try:
            entry = allow.remove(target)
        except KeyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        allow.save()
        print(f"removed {entry.kind} {entry.value}")
        return 0

    if action == "clear":
        count = allow.clear()
        allow.save()
        print(f"cleared {count} allowlist entry(s)")
        return 0

    if action in ("check", "why"):
        target = getattr(args, "value", None) or (
            (getattr(args, "targets", None) or [""])[0])
        if not target:
            print("usage: antivirus allowlist check PATH|DOMAIN", file=sys.stderr)
            return 2
        p = Path(target)
        hit = allow.check(str(p), name=p.name)
        if hit is None and p.exists():
            digest = __import__("hashlib").sha256(p.read_bytes()).hexdigest()
            hit = allow.check(str(p), sha256=digest, name=p.name)
        if hit is None:
            hit = allow.check_domain(target)
        if hit is None:
            print(f"{target}: NOT allowlisted – findings would be reported")
            return 1
        if args.json:
            print(json.dumps(hit.to_dict(), indent=2, ensure_ascii=False))
        else:
            print(f"{target}: suppressed – {hit.reason}")
            print(f"  entry {hit.entry.id} ({hit.entry.kind} "
                  f"{hit.entry.value}) {hit.entry.note}".rstrip())
        return 0

    if action in ("export", "import"):
        file_arg = getattr(args, "file", None) or (
            (getattr(args, "targets", None) or [None])[0])
        if not file_arg:
            print(f"usage: antivirus allowlist {action} FILE", file=sys.stderr)
            return 2
        target = Path(file_arg)
        if action == "export":
            payload = {"version": 1, "entries": [e.to_dict()
                                                 for e in allow.entries]}
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                              encoding="utf-8")
            print(f"exported {len(allow.entries)} entry(s) to {target}")
            return 0
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"error: cannot read {target}: {exc}", file=sys.stderr)
            return 2
        added = skipped = 0
        for raw in (data.get("entries") if isinstance(data, dict) else data) or []:
            try:
                _, created = allow.add(str(raw.get("kind", "")),
                                       str(raw.get("value", "")),
                                       note=str(raw.get("note", "")),
                                       source="import")
            except ValueError:
                skipped += 1
                continue
            added += int(created)
            skipped += int(not created)
        allow.save()
        print(f"imported {added} new entry(s), {skipped} skipped/duplicate")
        return 0

    if action in ("from-findings", "auto", "autoadd"):
        """Allowlist everything a previous report flagged (JSON report input)."""
        source = getattr(args, "file", None) or (
            (getattr(args, "targets", None) or [None])[0])
        if not source:
            print("usage: antivirus allowlist from-findings report.json",
                  file=sys.stderr)
            return 2
        try:
            data = json.loads(Path(source).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"error: cannot read {source}: {exc}", file=sys.stderr)
            return 2
        findings = data.get("findings") if isinstance(data, dict) else data
        only = getattr(args, "kind", None)
        added = 0
        seen = set()
        for finding in findings or []:
            digest = str(finding.get("sha256") or "")
            if only in (None, "hash") and digest and digest not in seen:
                seen.add(digest)
                if allow.add_hash(digest, note=f"suppressed by {source}",
                                  source="report")[1]:
                    added += 1
            domain = str(finding.get("domain") or "")
            if only in (None, "domain") and domain:
                if allow.add_domain(domain, note=f"seen in {source}",
                                    source="report")[1]:
                    added += 1
        allow.save()
        print(f"allowlisted {added} item(s) from {len(findings or [])} finding(s)"
              f" -> {path}")
        print("  review before trusting: an allowlisted hash is never reported "
              "again")
        return 0

    print(f"unknown allowlist action: {action}", file=sys.stderr)
    return 2


def cmd_allowlist_audit(args) -> int:
    """Show how many findings the allowlist is currently hiding, and where."""
    from . import allowlist as al_mod

    path = _allow_file(args)
    allow = al_mod.AllowList.load(path)
    suspects = [e for e in allow.entries if e.kind == "hash" and not e.note]
    stats = allow.stats()
    if args.json:
        print(json.dumps({"path": str(path), "stats": stats,
                          "unexplained": [e.to_dict() for e in suspects]},
                         indent=2, ensure_ascii=False))
        return 0
    print(paint(f"allowlist audit – {stats['total']} entry(s)", BOLD))
    print(f"  hashes {stats.get('hash', 0)}  names {stats.get('name', 0)}  "
          f"paths {stats.get('path', 0)}  domains {stats.get('domain', 0)}")
    if stats.get("name") or stats.get("path"):
        print(paint("  note: name/path entries are broad – prefer hashes where "
                    "possible", YELLOW))
    if suspects:
        print(paint(f"  {len(suspects)} hash entry(s) without an explanation:",
                    YELLOW))
        for entry in suspects[:20]:
            print(f"    {entry.id} {entry.value}")
    else:
        print("  every entry carries an explanation")
    return 0


def cmd_fpcheck(args) -> int:
    """False-positive audit of the indicator library against clean data."""
    from . import fpcheck as fp_mod

    severity = getattr(args, "min_severity", None) or "info"
    seeds = (1, 7, 20261015)
    blobs = int(getattr(args, "blobs", None) or 150)
    size_kib = int(getattr(args, "size", None) or 300)
    report = fp_mod.run(blobs=blobs, size=size_kib * 1024, seeds=seeds,
                        min_severity=severity,
                        blobs_only=getattr(args, "blobs_only", False),
                        text_only=getattr(args, "text_only", False))

    if getattr(args, "json", False):
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        return 0 if report.clean else 1

    print(paint(f"false-positive audit – {__version__}", BOLD))
    print(f"  random binary : {report.blobs} × {human_size(report.blob_size)}"
          f"  (seeds {', '.join(str(s) for s in seeds)})")
    if not getattr(args, "blobs_only", False):
        samples = fp_mod.corpus_summary()
        print(f"  clean text    : {len(samples)} file(s) – "
              + ", ".join(name for _, name, _ in samples))
    print(f"  threshold     : findings below '{severity}' are ignored")
    print()
    for corpus, count in sorted(report.per_corpus.items()):
        flagged = sum(1 for h in report.hits if h.corpus == corpus)
        mark = paint("ok", GREEN) if not flagged else paint(
            f"{flagged} flagged", RED)
        print(f"  {corpus:14} {count:4} file(s)   {mark}")
    print()
    if report.clean:
        print(paint(f"  no false positive above '{severity}' in "
                    f"{report.total_files} clean file(s)  "
                    f"({report.elapsed:.1f} s)", GREEN))
        return 0
    print(paint(f"  {report.flagged_files}/{report.total_files} clean file(s) "
                f"flagged ({report.rate:.2%})", RED))
    for check, count in Counter(report.counts).most_common(15):
        example = next(h for h in report.hits if h.check == check)
        print(f"    {count:4}  {check}")
        print(f"          e.g. {example.file} [{example.severity}] "
              f"{example.message[:90]}")
    print()
    print("  fix by tightening the pattern (see indicators.py) – never by "
          "deleting the check without a replacement.")
    return 1


def cmd_yara(args) -> int:
    """Export the detection content as a portable YARA ruleset."""
    from . import yararules as yr

    min_sev = getattr(args, "min_severity", None) or "medium"
    order = ["info", "low", "medium", "high", "critical"]
    severities = tuple(order[order.index(min_sev):]) if min_sev in order else \
        ("critical", "high", "medium")
    patterns = [] if getattr(args, "no_feeds", False) else None
    text, stats = yr.generate(
        severities=severities, patterns=patterns,
        signatures_file=(Path(args.signatures) if getattr(args, "signatures",
                                                          None) else None),
        feeds_dir=(Path(args.feeds_dir) if getattr(args, "feeds_dir", None)
                   else None),
        max_feed=int(getattr(args, "max_feed", 5000) or 5000))
    out = Path(getattr(args, "out", None) or "av-rules.yar")
    yr.write(text, out)

    if args.json:
        print(json.dumps({"path": str(out), "bytes": len(text),
                          "stats": stats.to_dict()}, indent=2))
        return 0

    print(paint(f"YARA ruleset written to {out}", BOLD))
    print(f"  {stats.rules} rule(s): {stats.signatures} signature / "
          f"{stats.indicators} indicator / {stats.feed} feed")
    print(f"  skipped: {stats.skipped_hash_only} hash-only signature(s) "
          f"(YARA cannot match by hash), "
          f"{len(stats.skipped_regex)} pattern(s) outside YARA's regex subset")
    if stats.skipped_regex and getattr(args, "verbose", False):
        for id_ in stats.skipped_regex[:40]:
            print(f"    skipped pattern: {id_}")
    if getattr(args, "verify", False):
        result = yr.verify(out)
        if not result.get("available"):
            print(paint(f"  --verify: {result['detail']}", YELLOW))
        elif result.get("compiled"):
            print(paint("  --verify: yara-python compiled the ruleset "
                        "successfully", GREEN))
        else:
            print(paint(f"  --verify: COMPILE FAILED – {result.get('error')}",
                        RED))
            return 1
    else:
        print("  verify with:  yara -r av-rules.yar <path>   (or --verify)")
    return 0


def cmd_matrix(args) -> int:
    """ATT&CK-style coverage view of the indicator library."""
    from . import indicators as ind_mod

    checks = list(ind_mod.CHECKS)
    want_tags = {t.lower() for t in (getattr(args, "tag", None) or [])}
    if want_tags:
        checks = [c for c in checks
                  if want_tags & {t.lower() for t in c.tags}]
    summary = ind_mod.matrix_summary(checks)

    if args.json:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return 0

    print(paint(f"indicator coverage by ATT&CK tactic – {__version__}", BOLD))
    print(f"  {summary['total']} checks"
          + (f" matching {', '.join(sorted(want_tags))}" if want_tags else ""))
    print()
    width = max(len(t["tactic"]) for t in summary["tactics"])
    for tactic in summary["tactics"]:
        entries = tactic["checks"]
        if not entries:
            print(f"  {tactic['tactic']:<{width}}  " + paint("no coverage",
                                                           YELLOW))
            continue
        sev = tactic["by_severity"]
        bar = "".join(_SEV_GLYPH.get(sev_name, "?") * min(count, 12)
                      for sev_name, count in sorted(
                          sev.items(), key=lambda kv: -_SEV_RANK.get(kv[0], 0)))
        print(f"  {tactic['tactic']:<{width}}  {entries:3}  {bar}")
        print(f"  {'':<{width}}  {tactic['description']}")
        if tactic["tags"]:
            print(f"  {'':<{width}}  top tags: "
                  + ", ".join(tag for tag, _ in tactic["tags"][:5]))
        if tactic.get("example"):
            print(f"  {'':<{width}}  e.g. {tactic['example']}")
    print()
    if summary["extra_categories"]:
        for category in summary["extra_categories"]:
            print(f"  (no tactic assigned: {category})")
    print("  glyphs: " + "  ".join(f"{_SEV_GLYPH[s]}{s}"
                                  for s in ("critical", "high", "medium",
                                            "low")))
    print("  list one:  antivirus explain IND-EXEC-PS-ENCODED")
    return 0


_SEV_GLYPH = {"critical": "#", "high": "+", "medium": "-", "low": "."}
