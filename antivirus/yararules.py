"""YARA ruleset export (v3.0).

There is a large amount of threat-intel tooling that speaks YARA and
nothing else: sandboxes, YARA-X, ``yara`` CLI in a SOC pipeline, Velociraptor,
Nextron's THOR.  Shipping a ruleset that those tools can consume makes this
project's detection content portable instead of locked inside it.

The generator is deliberately conservative – a rule that does not compile is
worse than no rule at all:

* signature patterns are emitted as YARA strings (escaped byte-for-byte)
* hash-only signatures cannot be expressed in YARA and are counted as
  skipped, with the reason reported
* indicator patterns are Python regexes; only those inside the YARA regex
  subset are converted (``(?i)`` becomes the ``nocase`` modifier, the
  ``\\b``/``(?:…)``/``{n,m}`` constructs are fine, unsupported ones like
  lookaround or backreferences are skipped and counted)
* feed-derived literals are emitted as ``ascii wide`` strings

``antivirus export --format yara`` writes the ruleset; ``--verify`` compiles
it with ``yara-python`` when that module is installed (it is *not* a
project dependency – the ruleset is generated with the standard library
alone).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

#: Characters YARA requires to be escaped inside a double-quoted string.
_STRING_ESCAPES = (("\\", "\\\\"), ('"', '\\"'), ("\n", "\\n"), ("\r", "\\r"),
                   ("\t", "\\t"))

#: Regex constructs YARA's regex engine does not support.
_UNSUPPORTED_REGEX = (
    "(?=", "(?!", "(?<=", "(?<!", "(?>", "(?P", "\\1", "\\2", "\\3", "\\4",
    "\\5", "\\6", "\\7", "\\8", "\\9", "\\A", "\\Z", "\\K", "(?#", "(?(",
)

_IDENT_OK = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass
class YaraStats:
    rules: int = 0
    signatures: int = 0
    indicators: int = 0
    feed: int = 0
    skipped_hash_only: int = 0
    skipped_regex: List[str] = field(default_factory=list)
    skipped_error: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rules": self.rules, "signatures": self.signatures,
            "indicators": self.indicators, "feed": self.feed,
            "skipped_hash_only": self.skipped_hash_only,
            "skipped_regex": len(self.skipped_regex),
            "skipped_error": len(self.skipped_error),
        }

    def summary(self) -> str:
        return (f"{self.rules} rule(s): {self.signatures} from signatures, "
                f"{self.indicators} from indicators, {self.feed} from feeds; "
                f"skipped {self.skipped_hash_only} hash-only, "
                f"{len(self.skipped_regex)} unsupported regex")


def yara_escape(text: str) -> str:
    """Escape a literal for use inside a YARA double-quoted string."""
    out = text
    for raw, escaped in _STRING_ESCAPES:
        out = out.replace(raw, escaped)
    return out


def yara_identifier(text: str) -> str:
    """Turn an arbitrary id into a legal YARA identifier."""
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", text)
    if not cleaned or cleaned[0].isdigit():
        cleaned = "r_" + cleaned
    return cleaned[:120]


def regex_to_yara(pattern: str) -> Optional[str]:
    """Convert a Python regex into a complete YARA regex literal.

    Returns e.g. ``/foo\.exe/i`` or ``None`` when the pattern uses a
    construct YARA cannot express (lookaround, backreferences, inline
    flags in the middle of the pattern).  Callers must treat ``None`` as
    "skip this rule", never as "no pattern".
    """
    if not pattern:
        return None
    for needle in _UNSUPPORTED_REGEX:
        if needle in pattern:
            return None
    out = pattern
    nocase = False
    if out.startswith("(?i)"):
        nocase = True
        out = out[4:]
    elif out.endswith("(?i)"):
        nocase = True
        out = out[:-4]
    # YARA's regex engine (RE2) has no non-capturing groups; they are
    # semantically identical to capturing ones for matching purposes, so
    # rewrite them.  Anything else starting with "(?" is unsupported.
    out = out.replace("(?:", "(")
    if "(?" in out:
        return None  # lookaround / inline flags / named groups
    # YARA regexes are unanchored and have no ^/$ anchors: a leading "^"
    # would be a syntax error, and dropping it broadens the match, so such
    # patterns are skipped rather than silently weakened.
    if out.startswith("^") or out.endswith("$"):
        return None
    inner = out.replace("/", "\\/")
    if not inner:
        return None
    return f"/{inner}/" + ("i" if nocase else "")


def _rule(name: str, strings: Sequence[Tuple[str, str]],
          *, meta: Dict[str, object], wide: bool = False,
          condition: str = "any of them", tags: Sequence[str] = ()) -> str:
    lines = [f"rule {yara_identifier(name)}"]
    if tags:
        seen: List[str] = []
        for tag in tags:
            if not tag:
                continue
            ident = yara_identifier(tag)
            if ident not in seen:
                seen.append(ident)
        tag_text = " ".join(seen)
        if tag_text:
            lines[0] += " : " + tag_text
    lines.append("{")
    lines.append("    meta:")
    for key, value in meta.items():
        if isinstance(value, bool):
            value = "true" if value else "false"
        elif isinstance(value, (int, float)):
            value = str(value)
        else:
            value = f'"{yara_escape(str(value))}"'
        lines.append(f"        {yara_identifier(str(key))} = {value}")
    lines.append("    strings:")
    for ident, value in strings:
        # Callers hand over *complete* YARA literals: either a quoted text
        # string (`"abc"`) or a regex (`/abc/i`).  Quoting happens exactly
        # once, in the helper that knows the escaping rules.
        suffix = " ascii wide" if (wide and value.startswith('"')) else ""
        lines.append(f"        {ident} = {value}{suffix}")
    lines.append(f"    condition:\n        {condition}")
    lines.append("}")
    return "\n".join(lines)


def _unescape_literal(text: str) -> str:
    """Turn a regex-escaped literal back into the bytes it represents."""
    out = text.replace("(?:", "").replace(")", "") if text.startswith("(?:") \
        else text
    return re.sub(r"\\(.)", r"\1", out)


def _string_line(text: str) -> bool:
    """Is this pattern a plain literal (not a regex)?"""
    return bool(text) and not any(ch in text for ch in ".^$*+?[]{}()|\\")


def from_signatures(signatures: Iterable[dict], stats: YaraStats) -> List[str]:
    """One YARA rule per signature that carries a matchable pattern."""
    rules: List[str] = []
    for sig in signatures:
        pattern = str(sig.get("pattern") or "")
        hashes = [h for h in (sig.get("sha256"), sig.get("md5")) if h]
        if not pattern:
            if hashes:
                stats.skipped_hash_only += 1
            continue
        try:
            compiled = re.compile(pattern)
        except re.error:
            stats.skipped_error.append(str(sig.get("id", "?")))
            continue
        if compiled.match("") or compiled.search(""):
            # a pattern that matches the empty string would flag every file
            stats.skipped_regex.append(str(sig.get("id", "?")))
            continue
        if _string_line(pattern):
            # plain literal: emit it as a YARA text string (faster than a
            # regex and impossible to misread)
            body = '"' + yara_escape(pattern) + '"'
        else:
            converted = regex_to_yara(pattern)
            if converted is None:
                stats.skipped_regex.append(str(sig.get("id", "?")))
                continue
            body = converted
        meta = {
            "author": "AntiVirus",
            "source": "signature database",
            "id": sig.get("id", ""),
            "description": sig.get("description", ""),
            "severity": sig.get("severity", ""),
            "category": sig.get("category", ""),
            "family": sig.get("family", ""),
            "reference_hash": sig.get("sha256", ""),
        }
        tags = [t for t in (sig.get("category"), sig.get("severity"),
                            "anti-virus") if t]
        rules.append(_rule(f"AV_SIG_{sig.get('id', 'unknown')}",
                           [("$a", body)], meta=meta, tags=tags))
        stats.signatures += 1
    return rules


def from_indicators(checks: Iterable, stats: YaraStats,
                    *, severities: Sequence[str] = ("critical", "high",
                                                    "medium")) -> List[str]:
    """One YARA rule per indicator check whose patterns convert cleanly."""
    rules: List[str] = []
    wanted = set(severities)
    for check in checks:
        if wanted and check.severity not in wanted:
            continue
        strings: List[Tuple[str, str]] = []
        for index, pattern in enumerate(check.patterns or ()):
            converted = regex_to_yara(str(pattern))
            if converted is None:
                stats.skipped_regex.append(check.id)
                continue
            strings.append((f"$p{index}", converted))
        if not strings:
            stats.skipped_error.append(check.id)
            continue
        meta = {
            "author": "AntiVirus",
            "source": "technique indicators",
            "id": check.id,
            "description": check.description,
            "severity": check.severity,
            "category": check.category,
        }
        tags = [t for t in (check.category, check.severity, *check.tags[:4],
                            "anti-virus") if t]
        rules.append(_rule(f"AV_IND_{check.id}", strings, meta=meta,
                           tags=tags))
        stats.indicators += 1
    return rules


def from_feed_patterns(patterns: Iterable[dict], stats: YaraStats) -> List[str]:
    """Feed-derived literals as ``ascii wide`` rules.

    Feed records store a *regex-escaped* literal (``658C8B7F\\-3664…``),
    so the escapes are removed again before the text is embedded in the
    ruleset.
    """
    rules: List[str] = []
    for index, record in enumerate(patterns):
        literal = _unescape_literal(str(record.get("pattern")
                                        or record.get("literal") or ""))
        if not literal or len(literal) < 6:
            continue
        meta = {
            "author": "AntiVirus",
            "source": "public feed",
            "description": f"Feed-derived literal from {record.get('source', '?')}",
            "severity": record.get("severity", "medium"),
            "reference": ", ".join(record.get("providers") or [])[:200],
            "id": record.get("id", ""),
        }
        rules.append(_rule(f"AV_FEED_{index:05d}_{literal[:24]}",
                           [("$a", '"' + yara_escape(literal) + '"')],
                           meta=meta, wide=True,
                           tags=["feed", str(record.get("severity", ""))
                                 or "medium", "anti-virus"]))
        stats.feed += 1
    return rules


def generate(*, signatures: Optional[Sequence[dict]] = None,
             checks: Optional[Sequence] = None,
             patterns: Optional[Sequence[dict]] = None,
             severities: Sequence[str] = ("critical", "high", "medium"),
             max_feed: int = 5000,
             signatures_file: Optional[Path] = None,
             feeds_dir: Optional[Path] = None) -> Tuple[str, YaraStats]:
    """Build a complete ruleset; returns ``(text, stats)``.

    *signatures_file* / *feeds_dir* override where the source data is read
    from - important for a rescue kit or an installed copy, where the
    package directory and the data directory are not siblings.
    """
    stats = YaraStats()
    body: List[str] = []
    if signatures is None:
        signatures = _load_signatures(signatures_file)
    if checks is None:
        from . import indicators as indicators_mod
        checks = indicators_mod.CHECKS
    if patterns is None:
        patterns = _load_feed_patterns(feeds_dir)
    body.extend(from_signatures(signatures, stats))
    body.extend(from_indicators(checks, stats, severities=severities))
    if patterns:
        body.extend(from_feed_patterns(list(patterns)[:max_feed], stats))
    stats.rules = len(body)
    header = [
        "/*",
        "   AntiVirus – portable YARA ruleset",
        "   generated by `antivirus export --format yara`",
        "",
        "   Every rule is derived from this project's own detection content:",
        "   signature database entries, technique indicators and (optionally)",
        "   feed-derived literals.  Rules that YARA cannot express (pure hash",
        "   signatures, regexes using lookaround/backreferences) are omitted",
        "   and counted in the summary printed by the generator.",
        "",
        f"   {stats.summary()}",
        "*/",
        "",
        "import \"hash\"",
        "",
    ]
    return "\n".join(header + body) + "\n", stats


def _load_signatures(path: Optional[Path] = None) -> List[dict]:
    """Signature database records.

    Defaults to ``<package>/../data/signatures.json`` but callers that know
    better (the CLI, a rescue kit) pass their own path.
    """
    if path is None:
        from .config import Config
        path = Path(Config().signatures_file)
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return list(data.get("signatures") or [])


def _load_feed_patterns(feeds_dir: Optional[Path] = None) -> List[dict]:
    from . import feeds as feeds_mod

    if feeds_dir is None:
        from .config import Config
        feeds_dir = Config().feeds_dir
    db = feeds_mod.FeedDB(Path(feeds_dir))
    if not db.built:
        return []
    return [record for record in db.patterns() if record.get("pattern")]


def write(text: str, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def verify(path: Path) -> dict:
    """Compile the ruleset with ``yara-python`` when it happens to be installed."""
    try:
        import yara  # type: ignore
    except ImportError:
        return {"available": False,
                "detail": "yara-python is not installed (optional)"}
    try:
        rules = yara.compile(filepath=str(path))
    except Exception as exc:  # pragma: no cover - depends on external lib
        return {"available": True, "compiled": False, "error": str(exc)}
    return {"available": True, "compiled": True,
            "detail": f"compiled {len(rules) if hasattr(rules, '__len__') else '?'} rule(s)"}


def match(path: Path, data: bytes) -> List[str]:
    """Rule names matching *data* – needs ``yara-python``; returns [] without it."""
    try:
        import yara  # type: ignore
    except ImportError:
        return []
    rules = yara.compile(filepath=str(path))
    return [m.rule for m in rules.match(data=data)]
