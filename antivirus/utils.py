"""Small shared helpers."""
from __future__ import annotations

import hashlib
from typing import BinaryIO


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
