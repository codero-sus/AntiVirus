"""Small shared helpers."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import BinaryIO, Union


def human_size(num: float) -> str:
    """Format a byte count for humans: ``1234567 -> '1.2 MiB'``."""
    num = float(num)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(num) < 1024.0 or unit == "PiB":
            if unit == "B":
                return f"{int(num)} {unit}"
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PiB"  # pragma: no cover - unreachable


def md5_new() -> "hashlib._Hash":
    """``hashlib.md5`` with a safe fallback for FIPS-mode builds."""
    try:
        return hashlib.md5(usedforsecurity=False)
    except TypeError:
        return hashlib.md5()


def parse_since(text: str) -> float:
    """Parse a *--since* duration (``30s``, ``30m``, ``2h``, ``1d``, ``1w``
    or a bare number of seconds) into seconds.

    Raises ``ValueError`` on invalid input (callers map it to their own
    error type – e.g. ``argparse.ArgumentTypeError``).
    """
    import argparse

    t = text.strip().lower()
    if not t:
        raise ValueError("--since needs a duration")
    unit = t[-1]
    units = {"s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0, "w": 604800.0}
    value = t[:-1] if unit in units else t
    try:
        seconds = float(value) * units.get(unit, 1.0)
    except ValueError:
        raise ValueError(f"invalid --since duration: {text!r}") from None
    if seconds <= 0:
        raise ValueError("--since duration must be positive")
    return seconds


def utf16_view(data: bytes) -> bytes:
    """Return a UTF-8 view of *data* when it looks like UTF-16 text.

    Windows command lines, registry exports and PowerShell ``-enc`` blobs
    are frequently stored as UTF-16LE (every ASCII byte followed by a NUL).
    Regex patterns written for ASCII never match that layout, so scanners
    miss half the story.  The decoded view has the same characters with the
    NULs removed, which the normal pattern engine can match.

    Returns ``b""`` when the data does not look like UTF-16 (cheap check:
    BOM, or a NUL in every second byte of the first 4 KiB).
    """
    if len(data) < 4:
        return b""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        enc = "utf-16"
    else:
        sample = data[:4096]
        if sample.count(0) * 4 < len(sample):
            return b""
        enc = "utf-16-le" if data[1:2] == b"\x00" else "utf-16-be"
    try:
        return data.decode(enc, "ignore").encode("utf-8", "ignore")
    except (LookupError, UnicodeDecodeError):  # pragma: no cover - defensive
        return b""


def is_utf16(data: bytes) -> bool:
    """True when :func:`utf16_view` would produce a decoded view."""
    return bool(utf16_view(data))


def atomic_write_json(path: Union[str, Path], payload, indent: int = 2) -> Path:
    """Write *payload* as JSON to *path* atomically (temp file + rename).

    Crash-safe: a reader never sees a half-written file, and an interrupted
    write leaves the previous contents intact.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp",
                               dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=indent, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def atomic_write_text(path: Union[str, Path], text: str) -> Path:
    """Write *text* to *path* atomically (temp file + rename)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp",
                               dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def text_context_ratio(view: bytes, start: int, end: int,
                       radius: int = 16) -> float:
    """Share of *text-like* bytes around ``view[start:end]``.

    Text-like means printable ASCII plus tab/newline/CR.  This is how the
    engine tells a marker found in a script/document apart from the same
    three letters occurring by chance inside a compressed or encrypted
    blob: real markers are surrounded by readable text, random bytes are
    not (their printable-ASCII ratio is ~0.37).
    """
    lo = max(0, start - radius)
    hi = min(len(view), end + radius)
    region = view[lo:hi]
    if not region:
        return 1.0
    good = sum(1 for b in region if 32 <= b < 127 or b in (9, 10, 13))
    return good / len(region)


#: Minimum text-like ratio around a marker for it to be reported.
TEXT_CONTEXT_MIN = 0.75
#: Matches at least this long are self-authenticating: a random binary
#: coincidence is astronomically unlikely, so they are reported wherever
#: they are found (e.g. the 68-byte EICAR string inside a binary blob).
#: Shorter markers (a family name, a three-letter alias) must sit in
#: readable text, otherwise every compressed file would "contain" them.
SHORT_MARKER_MAX = 12


def marker_text_ok(view: bytes, start: int, end: int) -> bool:
    """Whether a match at ``view[start:end]`` may be reported.

    Long matches are always accepted (:data:`SHORT_MARKER_MAX`); short ones
    must sit in readable text.
    """
    if end - start >= SHORT_MARKER_MAX:
        return True
    return in_text_context(view, start, end)


def in_text_context(view: bytes, start: int, end: int,
                    radius: int = 16) -> bool:
    """True when a match at ``view[start:end]`` sits in readable text."""
    return text_context_ratio(view, start, end, radius) >= TEXT_CONTEXT_MIN


def sanitize_text(text: str, max_len: int = 0) -> str:
    """Make *text* safe for terminals/reports: control characters (except
    tab) become ``'.'`` so a hostile file name cannot move the cursor,
    inject ANSI colours or forge log lines."""
    out = "".join(ch if (ch == "\t" or 32 <= ord(ch) < 127) else "."
                  for ch in str(text))
    if max_len and len(out) > max_len:
        out = out[: max_len - 1] + "…"
    return out
