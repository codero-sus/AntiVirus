"""Tiny ANSI colour helper (auto-disabled when not a TTY or when NO_COLOR).

On Windows, ANSI escape sequences only work when the console's
"virtual terminal processing" mode is enabled.  Windows 10+ consoles
support it; Python >= 3.12 enables it automatically, so for older
versions we enable it ourselves (best effort) the first time colour is
used.  If it cannot be enabled (Windows 7/8, non-console streams) the
sequences simply pass through — every consumer also honours NO_COLOR.
"""
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

_ANSI_READY = False


def _enabled() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    try:
        return sys.stdout.isatty()
    except Exception:  # pragma: no cover - odd environments
        return False


def _ensure_console() -> None:
    """Enable virtual-terminal (ANSI) processing on Windows consoles."""
    global _ANSI_READY
    if _ANSI_READY:
        return
    _ANSI_READY = True
    if os.name != "nt":
        return
    try:
        import ctypes

        k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        for std in (-11, -12):  # stdout, stderr
            handle = k32.GetStdHandle(std)
            if not handle:
                continue
            mode = ctypes.c_uint32()
            if k32.GetConsoleMode(handle, ctypes.byref(mode)):
                k32.SetConsoleMode(handle,
                                   mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
    except Exception:  # pragma: no cover - non-Windows / odd terminals
        pass


def paint(text: str, code: str) -> str:
    """Wrap *text* in an ANSI *code*, unless colour output is disabled."""
    if not _enabled():
        return text
    _ensure_console()
    return f"\033[{code}m{text}\033[0m"
