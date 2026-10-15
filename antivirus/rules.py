"""User-defined detection rules (v2.8) — a small, honest YARA-lite.

The bundled database covers known families and techniques; every incident
also has its own local indicators ("this exact PowerShell line", "our
customer's exfil domain").  This module manages a *user rule file*
(``data/user_rules.json`` by default) in exactly the same shape as the
signature database, so user rules flow through the same engine, the same
report kinds and the same provenance fields — no second pattern engine.

Rules are pattern-only (regex over raw bytes, case-sensitive unless the
pattern sets ``(?i:…)``) plus an optional ``filename`` glob that must match
the file *name*.  Nothing is executed.

CLI: ``antivirus rules list|add|remove|test|import``.
"""
from __future__ import annotations

import json
import re
import time
from fnmatch import fnmatch
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .signatures import Signature, VALID_SEVERITIES
from .utils import atomic_write_json

RULES_VERSION = 1

#: Rule id prefix so user rules never collide with bundled signatures.
PREFIX = "USER-"


def _empty() -> Dict:
    return {"version": RULES_VERSION, "updated": None, "signatures": []}


def load(path) -> Dict:
    """Load the rule file (empty structure when missing/corrupt)."""
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(
                data.get("signatures"), list):
            raise ValueError
    except (OSError, ValueError):
        return _empty()
    return data


def save(path, data: Dict) -> Path:
    """Persist the rule file atomically, stamping the update time."""
    data = dict(data)
    data["version"] = RULES_VERSION
    data["updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return atomic_write_json(path, data)


def list_rules(path) -> List[Signature]:
    """All rules as :class:`~antivirus.signatures.Signature` objects."""
    out = []
    known = set(Signature.__dataclass_fields__)
    for item in load(path).get("signatures", []):
        if not isinstance(item, dict):
            continue
        kwargs = {k: v for k, v in item.items() if k in known}
        if "id" not in kwargs or "name" not in kwargs:
            continue
        kwargs.setdefault("category", "user-rule")
        kwargs.setdefault("severity", "medium")
        kwargs.setdefault("description", "")
        out.append(Signature(**kwargs))
    return out


def validate(rule_id: str, pattern: str, severity: str,
             filename: str = "") -> Tuple[bool, str]:
    """Check a prospective rule; returns ``(ok, message)``.

    ``filename`` is a *glob* (``*.ps1``), not a regex.
    """
    if not rule_id or not rule_id.strip():
        return False, "rule id must not be empty"
    if not pattern or not pattern.strip():
        return False, "a rule needs a pattern"
    if severity not in VALID_SEVERITIES:
        return False, f"severity must be one of {', '.join(VALID_SEVERITIES)}"
    try:
        re.compile(pattern.encode("utf-8"))
    except re.error as exc:
        return False, f"invalid regex: {exc}"
    if filename and not filename.strip():
        return False, "file-name condition must not be blank"
    return True, "ok"


def add_rule(path, rule_id: str, pattern: str, severity: str = "medium",
             name: str = "", description: str = "", filename: str = "",
             family: str = "") -> Signature:
    """Add (or replace) a user rule.  Raises ``ValueError`` on bad input."""
    rule_id = rule_id.strip()
    ok, message = validate(rule_id, pattern, severity, filename)
    if not ok:
        raise ValueError(message)
    data = load(path)
    sig = Signature(
        id=rule_id, name=name.strip() or rule_id,
        category="user-rule", severity=severity,
        description=(description.strip() or f"user rule {rule_id}")
        + (f" [filename: {filename}]" if filename else ""),
        pattern=pattern, family=family, source="user rule",
        indicator="pattern",
    )
    kept = []
    replaced = False
    for item in data.get("signatures", []):
        if str(item.get("id", "")).lower() == rule_id.lower():
            kept.append(json.loads(json.dumps(_asdict(sig))))
            replaced = True
        else:
            kept.append(item)
    if not replaced:
        kept.append(json.loads(json.dumps(_asdict(sig))))
    data["signatures"] = kept
    if filename:
        data.setdefault("filename_conditions", {})[rule_id] = filename
    save(path, data)
    return sig


def _asdict(sig: Signature) -> Dict:
    from dataclasses import asdict
    return asdict(sig)


def filename_condition(path, rule_id: str) -> str:
    """The optional file-name glob attached to a rule (or "")."""
    return str(load(path).get("filename_conditions", {}).get(rule_id, ""))


def rules_with_globs(path) -> Tuple[List[Signature], Dict[str, str]]:
    """``(rules, {rule_id: filename_glob})`` for the scanner.

    Rules with a file-name condition must not join the merged content
    alternation (a match is only valid for matching file names), so the
    scanner evaluates them separately.
    """
    conditions = load(path).get("filename_conditions") or {}
    if not isinstance(conditions, dict):
        conditions = {}
    return list_rules(path), {str(k): str(v) for k, v in conditions.items()}


def remove_rule(path, rule_id: str) -> Signature:
    """Remove a rule by id (case-insensitive)."""
    data = load(path)
    wanted = rule_id.strip().lower()
    kept, removed = [], None
    for item in data.get("signatures", []):
        if str(item.get("id", "")).lower() == wanted and removed is None:
            removed = list_rules_from_item(item)
        else:
            kept.append(item)
    if removed is None:
        raise KeyError(f"no user rule with id {rule_id!r}")
    data["signatures"] = kept
    conditions = data.get("filename_conditions")
    if isinstance(conditions, dict):
        conditions.pop(removed.id, None)
        data["filename_conditions"] = conditions
    save(path, data)
    return removed


def list_rules_from_item(item: Dict) -> Signature:
    kwargs = {k: v for k, v in item.items()
              if k in Signature.__dataclass_fields__}
    kwargs.setdefault("category", "user-rule")
    kwargs.setdefault("severity", "medium")
    return Signature(**kwargs)


def test_rule(pattern: str, data: bytes, filename: str = "",
              glob: str = "") -> List[str]:
    """Return the matched substrings for a candidate rule (empty = no match).

    Used by ``antivirus rules test RULE FILE`` so a new rule can be tried
    against real files before it is saved.
    """
    out: List[str] = []
    if glob and not fnmatch(filename, glob):
        return out
    try:
        rx = re.compile(pattern.encode("utf-8"))
    except re.error as exc:
        raise ValueError(f"invalid regex: {exc}") from None
    for m in rx.finditer(data):
        snippet = data[max(0, m.start() - 16): m.end() + 16]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in snippet)
        if text not in out:
            out.append(text)
        if len(out) >= 5:
            break
    return out


def merged_signatures(rules_path, db) -> List[Signature]:
    """Bundled signatures + user rules (later rules win on id collision)."""
    out = {s.id.lower(): s for s in db.list()}
    for sig in list_rules(rules_path):
        out[sig.id.lower()] = sig
    return list(out.values())


def summary(path) -> Dict:
    """Counts for the CLI / web console."""
    rules = list_rules(path)
    by_sev: Dict[str, int] = {}
    for sig in rules:
        by_sev[sig.severity] = by_sev.get(sig.severity, 0) + 1
    return {
        "path": str(path),
        "count": len(rules),
        "updated": load(path).get("updated"),
        "by_severity": by_sev,
        "rules": [{"id": s.id, "name": s.name, "severity": s.severity,
                   "family": s.family, "pattern": s.pattern} for s in rules],
    }


def import_ioc_text(path, text: str, source: str = "ioc",
                    severity: str = "medium") -> int:
    """Import a plain-text IOC file as user rules (see parse_ioc_text)."""
    from .signatures import parse_ioc_text
    imported = 0
    for sig in parse_ioc_text(text, source=source, severity=severity):
        if not sig.pattern:      # hash-only IOCs cannot become pattern rules
            continue
        add_rule(path, rule_id=prefix_rule_id(sig.id), pattern=sig.pattern,
                 severity=sig.severity, name=sig.name,
                 description=sig.description, family=sig.family)
        imported += 1
    return imported


def prefix_rule_id(rule_id: str) -> str:
    """Ensure *rule_id* carries the ``USER-`` namespace prefix."""
    rule_id = rule_id.strip()
    return rule_id if rule_id.upper().startswith(PREFIX) else PREFIX + rule_id


