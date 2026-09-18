"""Tiny ANSI colour helper (auto-disabled when not a TTY or when NO_COLOR)."""
from __future__ import annotations

import os
import sys

BOLD = "1"
DIM = "2"
RED = "31"
GREEN = "32"
YELLOW = "33"
CYAN = "36"

SEVERITY_COLOR = {
    "critical": RED,
    "high": RED,
    "medium": YELLOW,
    "low": CYAN,
    "info": DIM,
}


def _enabled() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    try:
        return sys.stdout.isatty()
    except Exception:  # pragma: no cover - odd environments
        return False


def paint(text: str, code: str) -> str:
    """Wrap *text* in an ANSI *code*, unless colour output is disabled."""
    if not _enabled():
        return text
    return f"\033[{code}m{text}\033[0m"
