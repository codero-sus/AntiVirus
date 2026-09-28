"""Signature database (hashes + regex patterns), stored as JSON on disk."""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Dict, List, Optional

VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")

_HEX64 = re.compile(r"[0-9a-fA-F]{64}\Z")
_HEX32 = re.compile(r"[0-9a-fA-F]{32}\Z")


def parse_ioc_text(text: str, source: str = "ioc",
                   severity: str = "medium") -> List["Signature"]:
    """Parse a plain-text IOC (indicator) file into signatures.

    Line grammar (hex is case-insensitive):

    * blank lines, or lines starting with ``#`` / ``;``  → ignored
    * 64 hex digits (optional ``sha256=`` prefix)        → SHA-256 signature
    * 32 hex digits (optional ``md5=`` prefix)           → MD5 signature
    * ``pattern: <regex>``                               → regex, verbatim
    * any other line                                     → literal bytes
      (special characters are escaped automatically)

    Signature ids are generated as ``IOC-<KIND>-<prefix>``; the *source*
    string is used as the category. Invalid lines (e.g. 20 hex digits)
    are treated as literal patterns rather than rejected, so a sloppy
    paste still produces something reviewable.
    """
    out: List[Signature] = []
    seen = set()

    def _unique(base: str) -> str:
        candidate, n = base, 1
        while candidate.lower() in seen:
            n += 1
            candidate = f"{base}-{n}"
        seen.add(candidate.lower())
        return candidate

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        kind = value = ""
        lowered = line.lower()
        if lowered.startswith(("sha256=", "sha256:")):
            value = line.split("=", 1)[1] if "=" in line else line.split(":", 1)[1]
            kind = "sha256" if _HEX64.match(value.strip()) else "literal"
        elif lowered.startswith(("md5=", "md5:")):
            value = line.split("=", 1)[1] if "=" in line else line.split(":", 1)[1]
            kind = "md5" if _HEX32.match(value.strip()) else "literal"
        elif _HEX64.match(line):
            kind, value = "sha256", line
        elif _HEX32.match(line):
            kind, value = "md5", line
        elif lowered.startswith("pattern:"):
            kind, value = "pattern", line.split(":", 1)[1].strip()
        else:
            kind, value = "literal", line
        value = value.strip()
        if not value:
            continue
        if kind in ("sha256", "md5"):
            value = value.lower()
            sig_id = f"IOC-{'SHA256' if kind == 'sha256' else 'MD5'}-{value[:12].upper()}"
            kwargs = {kind: value}
        elif kind == "pattern":
            try:
                re.compile(value.encode("utf-8"))
            except re.error:
                value = re.escape(value)
            sig_id = "IOC-PAT-" + hashlib.sha1(value.encode("utf-8")).hexdigest()[:10]
            kwargs = {"pattern": value}
        else:  # literal
            kwargs = {"pattern": re.escape(value)}
            sig_id = "IOC-PAT-" + hashlib.sha1(value.encode("utf-8")).hexdigest()[:10]
        out.append(Signature(
            id=_unique(sig_id),
            name=f"IOC {kind} {value[:16]}",
            category=source,
            severity=severity if severity in VALID_SEVERITIES else "medium",
            description=f"imported from an IOC file (source: {source})",
            **kwargs,
        ))
    return out


@dataclass
class Signature:
    """One entry of the signature database.

    At least one of ``sha256``, ``md5`` or ``pattern`` should be set:
    hashes identify a file exactly, a pattern is a regular expression that
    is matched against the raw file bytes.
    """

    id: str
    name: str
    category: str
    severity: str
    description: str = ""
    sha256: str = ""
    md5: str = ""
    pattern: str = ""

    @property
    def compiled(self) -> Optional["re.Pattern[bytes]"]:
        """The pattern compiled for binary matching, or ``None`` (cached)."""
        cache = getattr(self, "_compiled_cache", "missing")
        if cache == "missing":
            if not self.pattern:
                cache = None
            else:
                try:
                    cache = re.compile(self.pattern.encode("utf-8"))
                except re.error:
                    cache = False
            self._compiled_cache = cache
        return None if cache is False else cache


class SignatureDB:
    """Loads, queries, mutates and saves the signature database."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.signatures: List[Signature] = []
        self.version = 0
        self._by_sha256: Dict[str, Signature] = {}
        self._by_md5: Dict[str, Signature] = {}
        self._load()

    # ------------------------------------------------------------------ load
    def _load(self) -> None:
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                data = {}
            known = {f.name for f in fields(Signature)}
            for item in data.get("signatures", []):
                kwargs = {k: v for k, v in item.items() if k in known}
                if "id" not in kwargs or "name" not in kwargs:
                    continue
                self.signatures.append(Signature(**kwargs))
        self.version += 1
        self._reindex()

    def _reindex(self) -> None:
        self._by_sha256 = {s.sha256.lower(): s for s in self.signatures if s.sha256}
        self._by_md5 = {s.md5.lower(): s for s in self.signatures if s.md5}

    # ----------------------------------------------------------------- query
    def by_sha256(self, digest: str) -> Optional[Signature]:
        return self._by_sha256.get(digest.lower())

    def by_md5(self, digest: str) -> Optional[Signature]:
        return self._by_md5.get(digest.lower())

    def list(self) -> List[Signature]:
        return list(self.signatures)

    # ---------------------------------------------------------------- mutate
    def remove(self, sig_id: str, save: bool = True) -> Signature:
        """Remove the signature with *sig_id* (case-insensitive); returns it."""
        lowered = sig_id.lower()
        for i, sig in enumerate(self.signatures):
            if sig.id.lower() == lowered:
                removed = self.signatures.pop(i)
                self._reindex()
                self.version += 1
                if save:
                    self.save()
                return removed
        raise KeyError(f"no signature with id {sig_id!r}")

    def add(self, signature: Signature, save: bool = True) -> None:
        if signature.severity not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {VALID_SEVERITIES}")
        if signature.pattern and signature.compiled is None:
            raise ValueError(f"invalid regular expression: {signature.pattern!r}")
        if not signature.sha256 and not signature.md5 and not signature.pattern:
            raise ValueError("a signature needs a sha256, md5 or pattern")
        self.signatures.append(signature)
        self._reindex()
        self.version += 1
        if save:
            self.save()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "signatures": [asdict(s) for s in self.signatures],
        }
        self.path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
