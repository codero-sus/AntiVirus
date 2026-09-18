"""Signature database (hashes + regex patterns), stored as JSON on disk."""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Dict, List, Optional

VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")


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
        """The pattern compiled for binary matching, or ``None``."""
        if not self.pattern:
            return None
        try:
            return re.compile(self.pattern.encode("utf-8"))
        except re.error:
            return None


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
