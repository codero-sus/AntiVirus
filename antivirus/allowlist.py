"""Allowlist – suppress known-good files, names and domains (v3.0).

Why this exists
---------------
Every detector produces false positives on *someone's* machine: a
penetration-test script, an in-house admin tool, a domain your company
legitimately talks to.  Commercial products solve that with an exclusion
list; without one, users learn to ignore findings, which is worse than
having no detector at all.

This module is that exclusion list, kept deliberately narrow:

* ``hash``   – an exact SHA-256/MD5/SHA-1 (the strongest, most precise form)
* ``name``   – a file-name glob (``*.ps1``-style, matched case-insensitively)
* ``path``   – a path glob, matched against the scanned path *and* its
               absolute form
* ``domain`` – a domain or IP whose feed/IOC findings should be suppressed

Every entry records when it was added, why, and by what - so an allowlist
can be reviewed instead of becoming an invisible hole.  ``allowlist check``
answers "would this file be excluded, and because of what?" without scanning,
and ``--no-allowlist`` disables the whole mechanism for one run.
"""
from __future__ import annotations

import fnmatch
import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .utils import atomic_write_json

#: The kinds an entry can have.
KINDS = ("hash", "name", "path", "domain")

#: Length -> kind for hash entries.
_HASH_KINDS = {32: "md5", 40: "sha1", 64: "sha256"}

DEFAULT_ALLOWLIST = Path("data/allowlist.json")


@dataclass
class AllowEntry:
    id: str
    kind: str
    value: str
    note: str = ""
    added_at: str = ""
    source: str = "manual"       # manual | scan | import

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AllowHit:
    """Why a file/domain was allowed through."""

    entry: AllowEntry
    reason: str

    def to_dict(self) -> dict:
        return {"entry": self.entry.to_dict(), "reason": self.reason}


class AllowList:
    """JSON-backed allowlist with in-memory glob caches."""

    def __init__(self, path: Optional[Path] = None,
                 entries: Optional[Iterable[dict]] = None) -> None:
        self.path = Path(path) if path is not None else DEFAULT_ALLOWLIST
        self.entries: List[AllowEntry] = []
        self._loaded = False
        self._name_globs: List[AllowEntry] = []
        self._path_globs: List[AllowEntry] = []
        self._hashes: Dict[str, AllowEntry] = {}
        self._domains: Dict[str, AllowEntry] = {}
        if entries is not None:
            self._adopt(entries)

    # --------------------------------------------------------------- storage
    @classmethod
    def load(cls, path: Optional[Path] = None) -> "AllowList":
        allow = cls(path)
        allow.reload()
        return allow

    def reload(self) -> None:
        data: dict = {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        entries = data.get("entries") if isinstance(data, dict) else []
        self._adopt(entries or [])
        self._loaded = True

    def _adopt(self, entries: Iterable[dict]) -> None:
        self.entries = [
            AllowEntry(
                id=str(raw.get("id") or _make_id(raw.get("kind", ""),
                                                  raw.get("value", ""))),
                kind=str(raw.get("kind", "")),
                value=str(raw.get("value", "")),
                note=str(raw.get("note", "")),
                added_at=str(raw.get("added_at", "")),
                source=str(raw.get("source", "manual")),
            )
            for raw in entries
            if raw.get("kind") in KINDS and raw.get("value")
        ]
        self._index()

    def _index(self) -> None:
        self._name_globs, self._path_globs = [], []
        self._hashes, self._domains = {}, {}
        for entry in self.entries:
            if entry.kind == "name":
                self._name_globs.append(entry)
            elif entry.kind == "path":
                self._path_globs.append(entry)
            elif entry.kind == "domain":
                self._domains[entry.value.strip().lower()] = entry
            else:
                self._hashes[entry.value.strip().lower()] = entry

    def save(self) -> None:
        payload = {
            "version": 1,
            "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "entries": [e.to_dict() for e in self.entries],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.path, payload)

    # ------------------------------------------------------------ operations
    def add(self, kind: str, value: str, *, note: str = "",
            source: str = "manual") -> Tuple[AllowEntry, bool]:
        """Add an entry; returns ``(entry, created)``."""
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {', '.join(KINDS)}")
        value = value.strip()
        if not value:
            raise ValueError("value must not be empty")
        if kind == "hash":
            digest = value.lower()
            if len(digest) not in _HASH_KINDS or any(
                    c not in "0123456789abcdef" for c in digest):
                raise ValueError("hash must be an MD5, SHA-1 or SHA-256 hex "
                                 "digest")
        existing = self._find(kind, value)
        if existing is not None:
            return existing, False
        entry = AllowEntry(
            id=_make_id(kind, value), kind=kind, value=value,
            note=note, source=source,
            added_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        self.entries.append(entry)
        self._index()
        return entry, True

    def add_domain(self, value: str, *, note: str = "",
                   source: str = "manual") -> Tuple[AllowEntry, bool]:
        return self.add("domain", value, note=note, source=source)

    def add_hash(self, value: str, *, note: str = "",
                 source: str = "manual") -> Tuple[AllowEntry, bool]:
        return self.add("hash", value, note=note, source=source)

    def remove(self, id_or_value: str) -> AllowEntry:
        target = id_or_value.strip().lower()
        for entry in list(self.entries):
            if entry.id.lower().startswith(target) or \
                    entry.value.lower() == target:
                self.entries.remove(entry)
                self._index()
                return entry
        raise KeyError(f"no allowlist entry matching {id_or_value!r}")

    def clear(self) -> int:
        count = len(self.entries)
        self.entries = []
        self._index()
        return count

    def _find(self, kind: str, value: str) -> Optional[AllowEntry]:
        if kind == "domain":
            return self._domains.get(value.strip().lower())
        if kind == "hash":
            return self._hashes.get(value.strip().lower())
        for entry in self.entries:
            if entry.kind == kind and entry.value.lower() == value.lower():
                return entry
        return None

    # --------------------------------------------------------------- queries
    def check(self, path: str = "", *, sha256: str = "", md5: str = "",
              sha1: str = "", name: str = "") -> Optional[AllowHit]:
        """Does anything in the allowlist cover this file?"""
        for digest, kind in ((sha256, "sha256"), (sha1, "sha1"), (md5, "md5")):
            if digest:
                entry = self._hashes.get(digest.strip().lower())
                if entry is not None:
                    return AllowHit(entry, f"{kind} hash is allowlisted")
        file_name = name or (Path(path).name if path else "")
        if file_name:
            for entry in self._name_globs:
                if fnmatch.fnmatch(file_name.lower(), entry.value.lower()):
                    return AllowHit(entry, f"file name matches {entry.value!r}")
        if path:
            candidates = [str(path), os.path.normpath(str(path))]
            try:
                candidates.append(str(Path(path).resolve()))
            except (OSError, RuntimeError):
                pass
            for entry in self._path_globs:
                pattern = entry.value.lower()
                for candidate in candidates:
                    if fnmatch.fnmatch(candidate.lower(), pattern):
                        return AllowHit(
                            entry, f"path matches {entry.value!r}")
        return None

    def check_domain(self, value: str) -> Optional[AllowHit]:
        token = (value or "").strip().lower()
        if not token:
            return None
        entry = self._domains.get(token)
        if entry is not None:
            return AllowHit(entry, "domain is allowlisted")
        # ``*.example.com`` style coverage for sub-domains
        for domain, entry in self._domains.items():
            if domain.startswith("*.") and token.endswith(domain[1:]):
                return AllowHit(entry, f"covered by {domain!r}")
        return None

    def filter_findings(self, findings: List) -> Tuple[List, List]:
        """Split findings into ``(kept, suppressed)`` using domain entries."""
        if not self._domains:
            return findings, []
        kept, suppressed = [], []
        for finding in findings:
            token = _finding_token(finding)
            if token and self.check_domain(token) is not None:
                suppressed.append(finding)
            else:
                kept.append(finding)
        return kept, suppressed

    def stats(self) -> Dict[str, int]:
        counts = {kind: 0 for kind in KINDS}
        for entry in self.entries:
            counts[entry.kind] = counts.get(entry.kind, 0) + 1
        counts["total"] = len(self.entries)
        return counts


def _finding_token(finding) -> str:
    """Extract the domain/IP a finding refers to, if it names one."""
    message = getattr(finding, "message", "") or ""
    kind = getattr(finding, "kind", "")
    if kind not in ("feed-ioc", "malicious_url", "signature-pattern"):
        return ""
    for quote in ("'", '"'):
        if quote in message:
            parts = message.split(quote)
            if len(parts) >= 2:
                token = parts[1]
                if "/" in token:
                    token = token.split("://")[-1].split("/")[0]
                return token.strip().lower()
    return ""


def _make_id(kind: str, value: str) -> str:
    """Stable short id – python's ``hash()`` is salted, so use sha1."""
    import hashlib

    digest = hashlib.sha1(f"{kind}:{value.lower()}".encode()).hexdigest()
    return f"{kind[:4]}-{int(digest[:12], 16) % (10 ** 8):08d}"


def add_hash_from_file(allow: AllowList, path: Path, *,
                       note: str = "") -> AllowEntry:
    """Convenience: allowlist a file by its SHA-256."""
    import hashlib

    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    entry, _ = allow.add("hash", digest, note=note or f"scan: {path}",
                         source="scan")
    return entry
