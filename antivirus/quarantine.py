"""Quarantine store.

Detected files are moved into ``<quarantine-dir>/files/`` under an opaque id
and a JSON manifest records everything needed to restore (or purge) them.
"""
from __future__ import annotations

import json
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

from .scanner import Finding

_ITEM_FIELDS = ("id", "original_path", "file_name", "sha256", "size", "quarantined_at", "reason")


@dataclass
class QuarantineItem:
    id: str
    original_path: str
    file_name: str
    sha256: str
    size: int
    quarantined_at: str
    reason: str

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in _ITEM_FIELDS}


class Quarantine:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.files_dir = self.root / "files"
        self.manifest_path = self.root / "manifest.json"
        self.files_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------- manifest
    def _load_items(self) -> List[dict]:
        if self.manifest_path.exists():
            try:
                return json.loads(self.manifest_path.read_text(encoding="utf-8")).get("items", [])
            except (json.JSONDecodeError, OSError):
                return []
        return []

    def _save_items(self, items: List[dict]) -> None:
        payload = {
            "version": 1,
            "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "items": items,
        }
        self.manifest_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def items(self) -> List[QuarantineItem]:
        return [
            QuarantineItem(**{k: it[k] for k in _ITEM_FIELDS if k in it})
            for it in self._load_items()
        ]

    # ------------------------------------------------------------ operations
    def put(self, path: Path, finding: Finding) -> QuarantineItem:
        """Move *path* into the quarantine and record it in the manifest."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"cannot quarantine, file is gone: {path}")
        item_id = (
            f"{(finding.sha256 or 'unknown')[:12]}-"
            f"{time.strftime('%Y%m%d-%H%M%S')}-"
            f"{uuid.uuid4().hex[:6]}"
        )
        dest = self.files_dir / f"{item_id}.quarantined"
        shutil.move(str(path), str(dest))
        entry = {
            "id": item_id,
            "original_path": str(path),
            "file_name": path.name,
            "sha256": finding.sha256,
            "size": finding.size or dest.stat().st_size,
            "quarantined_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "reason": f"[{finding.kind}] {finding.name}: {finding.message}",
        }
        items = self._load_items()
        items.append(entry)
        self._save_items(items)
        return QuarantineItem(**entry)

    def restore(self, item_id: str) -> Tuple[QuarantineItem, Path]:
        """Restore a quarantined file (back to its original location if possible)."""
        items = self._load_items()
        entry = self._match(items, item_id)
        source = self.files_dir / f"{entry['id']}.quarantined"
        if not source.exists():
            raise FileNotFoundError(f"quarantine file missing: {source}")
        original = Path(entry["original_path"])
        if original.parent.exists():
            target = original
        else:
            target = Path.cwd() / original.name
        target = self._unique(target)
        shutil.move(str(source), str(target))
        items.remove(entry)
        self._save_items(items)
        return QuarantineItem(**entry), target

    def purge(self, item_id: str) -> QuarantineItem:
        """Permanently delete a quarantined file and its manifest entry."""
        items = self._load_items()
        entry = self._match(items, item_id)
        source = self.files_dir / f"{entry['id']}.quarantined"
        if source.exists():
            source.unlink()
        items.remove(entry)
        self._save_items(items)
        return QuarantineItem(**entry)

    # ------------------------------------------------------------- internals
    @staticmethod
    def _match(items: List[dict], item_id: str) -> dict:
        candidates = [it for it in items if it["id"].startswith(item_id)]
        if not candidates:
            raise KeyError(f"no quarantined item with id starting with {item_id!r}")
        if len(candidates) > 1:
            raise ValueError(
                f"ambiguous id {item_id!r}: {', '.join(c['id'] for c in candidates)}"
            )
        return candidates[0]

    @staticmethod
    def _unique(path: Path) -> Path:
        if not path.exists():
            return path
        n = 1
        while True:
            candidate = path.with_name(f"{path.stem}.{n}{path.suffix}")
            if not candidate.exists():
                return candidate
            n += 1
