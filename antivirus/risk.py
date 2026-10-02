"""Suspicion engine: signature-independent file risk scoring (v2.4).

Commercial engines combine *known* indicators with *suspicious-looking*
signals.  This module is the latter half: a 0-100 risk score built from
what a file *looks* like without matching any signature -

* claims to be a document/image but contains a PE / ZIP / ELF binary
* double extensions (``invoice.pdf.exe``)
* executable / script extensions
* malware-typical name words (crack, keygen, update, …)
* random-looking filenames
* suspicious parent directories (Downloads, temp, …)
* high entropy (packed / encrypted / random blob)
* executable bit on a "data" file
* an executable that is suspiciously small

The scanner emits a single ``suspicious`` finding when the score crosses
``Config.risk_threshold`` - which means the *background guard* acts on
suspicious files automatically, without any known signature.
"""
from __future__ import annotations

import math
import os
import re
import stat as stat_mod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

#: Extensions that claim "I am not a program" but often hide one.
_CLAIMS_DATA_EXTS = {
    ".txt", ".log", ".md", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
    ".html", ".htm", ".csv", ".xml", ".pdf", ".doc", ".docx", ".xls",
    ".xlsx", ".ppt", ".pptx", ".ini", ".cfg", ".json", ".yml", ".yaml",
    ".tiff", ".wav", ".mp3", ".mp4",
}

#: Executable / script / dropper extensions.
_EXEC_EXTS = {
    ".exe", ".scr", ".pif", ".com", ".dll", ".ocx", ".hta", ".vbs", ".vbe",
    ".wsf", ".wsh", ".js", ".jse", ".vbe", ".bat", ".cmd", ".ps1", ".psm1",
    ".psd1", ".jar", ".lnk", ".msi", ".iso", ".elf",
}

#: Name words that appear disproportionately often in malware / fake
#: update / phishing drops (stem must match as a whole word).
_NAME_IOC_WORDS = {
    "crack", "cracked", "keygen", "keymaker", "serial", "activator",
    "unlock", "updater", "update", "installer", "setup", "patch",
    "invoice", "receipt", "password", "vpn", "proxy", "miner", "crypt",
    "torrent", "crackme", "exploit", "inject", "hook", "keylog",
}

#: Parent directory names where dropped files land in the wild.
_SUSPICIOUS_PARENTS = {
    "downloads", "download", "temp", "tmp", "appdata", "programdata",
    "public", "shared", "inbox", "mail", "mail attachments", "updates",
    "update", "tools", "utils", "temp files", "recent",
}

_MAGIC = (
    (b"MZ", "MS-DOS/PE executable"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"PK\x05\x06", "empty ZIP archive"),
    (b"\x7fELF", "ELF executable"),
    (b"\xca\xfe\xba\xbe", "Mach-O executable"),
    (b"\xd0\xcf\x11\xe0", "OLE2 (old Office) container"),
)


@dataclass
class RiskReport:
    """Outcome of :func:`assess_risk`."""

    score: int = 0
    reasons: List[Tuple[int, str]] = field(default_factory=list)

    @property
    def suspicious(self) -> bool:
        return self.score >= 45

    def top_reasons(self, n: int = 4) -> List[str]:
        return [r for _w, r in sorted(self.reasons, reverse=True)[:n]]

    def to_dict(self) -> Dict:
        return {
            "score": self.score,
            "suspicious": self.suspicious,
            "reasons": [{"weight": w, "detail": d} for w, d in self.reasons],
        }


def _add(report: RiskReport, weight: int, detail: str) -> None:
    if weight <= 0:
        return
    report.score += weight
    report.reasons.append((weight, detail))


def _name_parts(name: str) -> Tuple[str, str]:
    """(stem, lowercased extension incl. dot)."""
    stem, ext = os.path.splitext(name)
    return stem, ext.lower()


def assess_risk(path, st: Optional[os.stat_result],
                content: Optional[bytes] = None) -> RiskReport:
    """Score how suspicious *path* looks.  Never raises on odd inputs."""
    report = RiskReport()
    name = os.path.basename(str(path))
    stem, ext = _name_parts(name)
    head = (content or b"")[:65536]

    # -- content vs. claimed type -----------------------------------------
    claimed_data = ext in _CLAIMS_DATA_EXTS
    if head:
        for magic, label in _MAGIC:
            if head.startswith(magic):
                if claimed_data:
                    _add(report, 35,
                         f"claims to be a '{ext}' document but contains a "
                         f"{label} binary")
                elif ext not in (".zip", ".tar", ".gz", ".exe", ".elf",
                                 ".so", ".dll", ".msi", ".iso", ".jar",
                                 ".doc", ".docx", ".xls", ".xlsx", ".ppt",
                                 ".pptx"):
                    _add(report, 15, f"contains a {label} binary")
                break

    # -- double extension (invoice.pdf.exe) --------------------------------
    parts = name.split(".")
    if len(parts) >= 3 and ("." + parts[-1].lower()) in _EXEC_EXTS:
        _add(report, 30,
             f"double extension ('.{parts[-2]}.{parts[-1]}') - "
             "classic disguise")
        if ("." + parts[-2].lower()) in _CLAIMS_DATA_EXTS:
            _add(report, 15,
                 f"disguised as a common document type ('.{parts[-2]}')")

    # -- executable / script extension --------------------------------------
    if ext in _EXEC_EXTS:
        _add(report, 12, f"executable/script extension '{ext}'")

    # -- malware-typical name words ------------------------------------------
    stem_words = re.split(r"[-_ \t]+", stem.lower())
    hits = [w for w in stem_words if w in _NAME_IOC_WORDS]
    if hits:
        _add(report, min(8 * len(hits), 16),
             f"name contains suspicious word(s): {', '.join(hits[:3])}")

    # -- random-looking filename ---------------------------------------------
    if len(stem) >= 6:
        freq: Dict[str, int] = {}
        for ch in stem:
            freq[ch] = freq.get(ch, 0) + 1
        n = len(stem)
        ent = -sum((c / n) * math.log2(c / n) for c in freq.values())
        if ent > 3.2 and not any(w in _NAME_IOC_WORDS for w in stem_words):
            _add(report, 8, "random-looking filename (high name entropy)")

    # -- suspicious parent directory ------------------------------------------
    try:
        parent = os.path.basename(
            os.path.dirname(os.path.abspath(str(path))))
    except (OSError, ValueError):
        parent = ""
    if parent.lower() in _SUSPICIOUS_PARENTS:
        _add(report, 8, f"located in suspicious directory '{parent}'")

    # -- entropy ---------------------------------------------------------------
    if head and len(head) >= 1024:
        from .models import shannon_entropy
        e = shannon_entropy(head)
        if e >= 7.6:
            _add(report, 25,
                 f"very high entropy {e:.2f} bits/byte (packed/encrypted?)")
        elif e >= 7.3:
            _add(report, 18,
                 f"high entropy {e:.2f} bits/byte (packed/encrypted?)")

    # -- executable bit on a "data" file (POSIX) --------------------------------
    if st is not None:
        if os.name != "nt" and st.st_mode:
            if claimed_data and (st.st_mode & (stat_mod.S_IXUSR |
                                                stat_mod.S_IXGRP |
                                                stat_mod.S_IXOTH)):
                _add(report, 6,
                     "executable bit set on a data-looking file")
        # an exe smaller than a plausible PE is often a stub / dropper
        if st is not None and ext == ".exe" and 0 < st.st_size < 16384:
            _add(report, 6, "exe smaller than 16 KiB (stub/dropper size)")

    report.score = min(report.score, 100)
    return report


def severity_for(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"
