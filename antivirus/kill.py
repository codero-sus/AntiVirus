"""Kill engine — neutralize a threat *in place* without moving or deleting it.

The idea behind "killing" malware here:

* The file's bytes are **obfuscated in place** with a one-time,
  stdlib-only stream cipher (a SHA-512 counter-mode keystream).  The
  original binary is turned into unreadable, non-executable garbage *where
  it sits* — so it no longer matches its own SHA-256 signature, no longer
  matches its behavioural patterns, and can no longer run.
* The **key and IV** that undo the obfuscation are stored in the
  **AntiVirus registry** (a local JSON store, ``registry/kill.json``).
  That lets the owner *revive* the exact original bytes later (forensics,
  false-positive recovery) — and proves to the AV what it killed.

Because the key/IV never touch the scanned volume, the registry is the
single source of recovery material.  Purging an entry destroys both the
obfuscated file and the material to restore it (irreversible).

This is deliberately a *neutralization* mechanism, not general-purpose
encryption: it is meant to render a specific detected file inert while
keeping an auditable, revivable record in the registry.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from .scanner import Finding

#: Key / IV sizes for the kill keystream (256-bit key, 128-bit IV).
KEY_SIZE = 32
IV_SIZE = 16

#: One SHA-512 counter block yields this many keystream bytes.
_BLOCK = 64

_ENTRY_FIELDS = (
    "id", "original_path", "file_name", "original_sha256", "ciphertext_sha256",
    "size", "killed_at", "reason", "key", "iv",
)


# --------------------------------------------------------------------------- cipher
def _xor(data: bytes, ks: bytes) -> bytes:
    """XOR two same-length byte strings (big-int XOR, fast for large data)."""
    if not data:
        return data
    return (int.from_bytes(data, "big") ^ int.from_bytes(ks, "big")
            ).to_bytes(len(data), "big")


def transform(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Obfuscate / de-obfuscate *data* with the kill keystream.

    The operation is symmetric: ``transform(transform(x, k, iv), k, iv) == x``.
    The keystream is ``SHA-512(key || iv || counter)`` for counter = 0, 1, …,
    i.e. a counter-mode stream cipher built only from the standard library.
    """
    if not data:
        return data
    base = key + iv
    out = bytearray()
    counter = 0
    step = 1024 * 1024  # process 1 MiB at a time
    for off in range(0, len(data), step):
        chunk = data[off:off + step]
        ks = bytearray()
        while len(ks) < len(chunk):
            ks += hashlib.sha512(base + counter.to_bytes(8, "big")).digest()
            counter += 1
        out += _xor(chunk, bytes(ks[:len(chunk)]))
    return bytes(out)


#: Convenience aliases — the cipher is its own inverse.
obfuscate = transform
deobfuscate = transform


def new_key_iv() -> Tuple[bytes, bytes]:
    """A fresh (key, iv) pair for one kill operation."""
    return secrets.token_bytes(KEY_SIZE), secrets.token_bytes(IV_SIZE)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------------------ item
@dataclass
class KillItem:
    id: str
    original_path: str
    file_name: str
    original_sha256: str
    ciphertext_sha256: str
    size: int
    killed_at: str
    reason: str
    key: str
    iv: str

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in _ENTRY_FIELDS}


# ---------------------------------------------------------------------- registry
class KillRegistry:
    """The AntiVirus registry: where key/IV pairs for killed files live.

    A single JSON document (``<registry-dir>/kill.json``) holds one entry
    per neutralized file, including the cryptographic material needed to
    revive it.  The interface mirrors :class:`~antivirus.quarantine.Quarantine`.
    """

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.path = self.root / "kill.json"
        self.root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------- manifest
    def _load_entries(self) -> List[dict]:
        if self.path.exists():
            try:
                return json.loads(self.path.read_text(encoding="utf-8")).get("entries", [])
            except (json.JSONDecodeError, OSError):
                return []
        return []

    def _save_entries(self, entries: List[dict]) -> None:
        payload = {
            "version": 1,
            "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "entries": entries,
        }
        self.path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def entries(self) -> List[KillItem]:
        return [
            KillItem(**{k: it[k] for k in _ENTRY_FIELDS if k in it})
            for it in self._load_entries()
        ]

    def by_ciphertext_sha256(self, sha: str) -> Optional[dict]:
        """Look up an entry by the hash of its current (obfuscated) bytes."""
        for it in self._load_entries():
            if it.get("ciphertext_sha256") == sha:
                return it
        return None

    # ------------------------------------------------------------ operations
    def kill(self, path: Path, finding: Finding) -> KillItem:
        """Obfuscate *path* in place and record its key/IV in the registry."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"cannot kill, file is gone: {path}")
        data = path.read_bytes()
        original_sha = finding.sha256 or _sha256(data)
        key, iv = new_key_iv()
        cipher = transform(data, key, iv)
        _atomic_write(path, cipher)

        item_id = (
            f"{original_sha[:12]}-"
            f"{time.strftime('%Y%m%d-%H%M%S')}-"
            f"{uuid.uuid4().hex[:6]}"
        )
        entry = {
            "id": item_id,
            "original_path": str(path),
            "file_name": path.name,
            "original_sha256": original_sha,
            "ciphertext_sha256": _sha256(cipher),
            "size": len(data),
            "killed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "reason": f"[{finding.kind}] {finding.name}: {finding.message}",
            "key": key.hex(),
            "iv": iv.hex(),
        }
        items = self._load_entries()
        items.append(entry)
        self._save_entries(items)
        return KillItem(**entry)

    def revive(self, item_id: str) -> Tuple[KillItem, Path]:
        """Restore the original bytes of a killed file (key/IV from registry)."""
        entries = self._load_entries()
        entry = self._match(entries, item_id)
        path = Path(entry["original_path"])
        if not path.exists():
            raise FileNotFoundError(
                f"killed file is no longer at {path}; cannot revive in place")
        data = path.read_bytes()
        if _sha256(data) != entry["ciphertext_sha256"]:
            raise ValueError(
                "file changed after it was killed; refusing to revive "
                "(the stored key/IV no longer match the bytes on disk)")
        original = transform(data, bytes.fromhex(entry["key"]),
                             bytes.fromhex(entry["iv"]))
        if _sha256(original) != entry["original_sha256"]:
            raise ValueError("revived bytes do not match the recorded "
                             "original hash (registry corrupt?)")
        target = path if path.parent.exists() else Path.cwd() / entry["file_name"]
        _atomic_write(target, original)
        entries.remove(entry)
        self._save_entries(entries)
        return KillItem(**entry), target

    def purge(self, item_id: str) -> KillItem:
        """Permanently delete a killed file and its registry entry."""
        entries = self._load_entries()
        entry = self._match(entries, item_id)
        path = Path(entry["original_path"])
        if path.exists():
            path.unlink()
        entries.remove(entry)
        self._save_entries(entries)
        return KillItem(**entry)

    # ------------------------------------------------------------- internals
    @staticmethod
    def _match(entries: List[dict], item_id: str) -> dict:
        candidates = [it for it in entries if it["id"].startswith(item_id)]
        if not candidates:
            raise KeyError(f"no killed file with id starting with {item_id!r}")
        if len(candidates) > 1:
            raise ValueError(
                f"ambiguous id {item_id!r}: {', '.join(c['id'] for c in candidates)}")
        return candidates[0]


def _atomic_write(path: Path, data: bytes) -> None:
    """Write *data* to *path* atomically (temp file + rename)."""
    path = Path(path)
    tmp = path.with_name(path.name + ".av-kill-tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)
