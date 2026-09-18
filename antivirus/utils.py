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
