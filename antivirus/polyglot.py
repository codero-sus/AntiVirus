"""Polyglot file detection (v2.7).

A *polyglot* file is one file that is simultaneously a valid member of
two or more file formats.  The classic case is the **PDF/PE polyglot**
— a document that is also a Windows executable — the standard delivery
mechanism of the MalPDF exploit chain (2013–2016).  Others: PNG/JPEG
images that double as PE/ELF implants, OLE documents that are also
executables, plain text with an embedded binary blob (a steganography /
payload-hiding trick).

Detection is purely *structural*: every format is validated with its
real header rules (not a magic-byte coincidence), and only pairs that
are actually suspicious are reported.  A PDF that legitimately embeds a
JPEG image, or a ZIP that bundles a PDF document, is **not** flagged.

Nothing is executed; bytes are read and compared.
"""
from __future__ import annotations

import struct
from typing import Callable, Dict, List, Optional, Tuple

from .models import Finding, shannon_entropy

#: How far into a file embedded-format searches go.
SCAN_LIMIT = 4 * 1024 * 1024

#: A text file with an embedded high-entropy region of at least this many
#: bytes is "text + binary blob".
BLOB_MIN_SIZE = 16 * 1024
BLOB_ENTROPY = 7.3
_WINDOW = 64 * 1024
_WINDOW_STEP = 32 * 1024


# ------------------------------------------------------------ format checks
def _is_pe(data: bytes, off: int) -> bool:
    """A valid PE at *off*: MZ header, e_lfanew in range, PE signature."""
    if off + 64 > len(data) or data[off:off + 2] != b"MZ":
        return False
    try:
        e_lfanew = struct.unpack_from("<I", data, off + 0x3C)[0]
    except struct.error:
        return False
    sig = off + e_lfanew
    if e_lfanew < 0x40 or sig + 4 > len(data):
        return False
    return data[sig:sig + 4] == b"PE\0\0"


def _is_elf(data: bytes, off: int) -> bool:
    if off + 6 > len(data) or data[off:off + 4] != b"\x7fELF":
        return False
    return data[off + 4] in (1, 2)


def _is_pdf(data: bytes, off: int) -> bool:
    if data[off:off + 5] != b"%PDF-":
        return False
    ver = data[off + 5:off + 8]
    return len(ver) == 3 and ver[0:1].isdigit() and ver[1:2] == b"." \
        and ver[2:3].isdigit()


def _is_zip(data: bytes, off: int) -> bool:
    """A *complete* ZIP: local header at *off* plus an EOCD somewhere."""
    if data[off:off + 4] != b"PK\x03\x04":
        return False
    tail = max(0, len(data) - 65557)
    return b"PK\x05\x06" in data[tail:]


def _is_png(data: bytes, off: int) -> bool:
    if data[off:off + 8] != b"\x89PNG\r\n\x1a\n":
        return False
    return off + 16 <= len(data) and data[off + 12:off + 16] == b"IHDR"


def _is_jpeg(data: bytes, off: int) -> bool:
    if off + 4 > len(data) or data[off:off + 3] != b"\xff\xd8\xff":
        return False
    # First SOF/APP/DQT marker after the SOI.
    return data[off + 3] in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
                             0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF, 0xDB,
                             0xDD, 0xE0, 0xE1, 0xE2, 0xE3, 0xEE, 0xFE)


def _is_gzip(data: bytes, off: int) -> bool:
    return off + 3 <= len(data) and data[off:off + 3] == b"\x1f\x8b\x08"


def _is_rar(data: bytes, off: int) -> bool:
    return data[off:off + 7] in (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01")


def _is_7z(data: bytes, off: int) -> bool:
    return data[off:off + 6] == b"7z\xbc\xaf\x27\x1c"


def _is_ole(data: bytes, off: int) -> bool:
    return data[off:off + 8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


#: Format name -> (structural validator, first magic bytes for the
#: pre-filter search).
_FORMATS: Dict[str, Tuple[Callable[[bytes, int], bool], bytes]] = {
    "PE": (_is_pe, b"MZ"),
    "ELF": (_is_elf, b"\x7fELF"),
    "PDF": (_is_pdf, b"%PDF-"),
    "ZIP": (_is_zip, b"PK\x03\x04"),
    "PNG": (_is_png, b"\x89PNG"),
    "JPEG": (_is_jpeg, b"\xff\xd8\xff"),
    "GZIP": (_is_gzip, b"\x1f\x8b\x08"),
    "RAR": (_is_rar, b"Rar!"),
    "7z": (_is_7z, b"7z\xbc"),
    "OLE": (_is_ole, b"\xd0\xcf\x11\xe0"),
}

#: Reported pairs (primary at offset 0, embedded at offset > 0) ->
#: (severity, label).  Absent pairs are not reported: a ZIP that bundles
#: a PDF, a PDF that embeds a JPEG photo, ... are legitimate.
_PAIRS: Dict[Tuple[str, str], Tuple[str, str]] = {
    ("PDF", "PE"): ("critical",
                    "PDF/PE polyglot - valid PDF document that is also a "
                    "Windows PE executable (MalPDF exploit pattern)"),
    ("PDF", "ELF"): ("high",
                     "PDF/ELF polyglot - document that is also a Unix "
                     "executable"),
    ("PDF", "ZIP"): ("low", "PDF with an embedded standalone ZIP container"),
    ("PDF", "RAR"): ("low", "PDF with an embedded standalone RAR container"),
    ("PDF", "7z"): ("low", "PDF with an embedded 7z container"),
    ("PNG", "PE"): ("high",
                    "PNG/PE polyglot - image file that is also a Windows "
                    "executable (implant pattern)"),
    ("PNG", "ELF"): ("high",
                     "PNG/ELF polyglot - image file that is also a Unix "
                     "executable (implant pattern)"),
    ("PNG", "ZIP"): ("medium",
                     "PNG/ZIP polyglot - image file with an embedded "
                     "standalone ZIP container"),
    ("JPEG", "PE"): ("high",
                     "JPEG/PE polyglot - image file that is also a Windows "
                     "executable (implant pattern)"),
    ("JPEG", "ELF"): ("high",
                      "JPEG/ELF polyglot - image file that is also a Unix "
                      "executable (implant pattern)"),
    ("JPEG", "ZIP"): ("medium",
                      "JPEG/ZIP polyglot - image file with an embedded "
                      "standalone ZIP container"),
    ("OLE", "PE"): ("high",
                    "OLE/PE polyglot - Office-style document that is also "
                    "a Windows executable"),
    ("PE", "ELF"): ("high",
                    "PE/ELF polyglot - Windows executable that is also a "
                    "Unix executable"),
    ("ELF", "PE"): ("high",
                    "ELF/PE polyglot - Unix executable that is also a "
                    "Windows executable"),
    ("PE", "PDF"): ("low",
                    "PE with an embedded standalone PDF (self-extracting "
                    "installer pattern)"),
    ("PE", "ZIP"): ("low",
                    "PE + standalone ZIP container (self-extracting archive "
                    "pattern)"),
    ("PE", "PNG"): ("medium",
                    "PE with an embedded standalone PNG container"),
    ("PE", "JPEG"): ("medium",
                     "PE with an embedded standalone JPEG container"),
    ("ELF", "ZIP"): ("low",
                     "ELF with an embedded standalone ZIP container"),
    ("ELF", "PDF"): ("low", "ELF with an embedded standalone PDF"),
}


def _printable_ratio(chunk: bytes) -> float:
    if not chunk:
        return 0.0
    printable = sum(1 for b in chunk if b >= 0x20 or b in (9, 10, 13))
    return printable / len(chunk)


def _looks_like_text(data: bytes) -> bool:
    """The *start* of the file is text (a payload may follow later)."""
    head = data[:8192]
    if not head:
        return False
    nul = head.find(b"\x00")
    text_head = head if nul == -1 else head[:nul]
    return len(text_head) >= 64 and _printable_ratio(text_head) >= 0.9


def _embedded_pe_in_text(data: bytes) -> int:
    """Offset of a valid PE embedded after a text prefix, or -1.

    The bytes immediately before the PE must be text (the classic
    "note.txt" / "readme.txt" with a payload appended or spliced in).
    """
    off = data.find(b"MZ")
    while off != -1:
        if off > 0 and _is_pe(data, off):
            before = data[max(0, off - 512):off]
            if b"\x00" not in before and _printable_ratio(before) >= 0.9:
                return off
        off = data.find(b"MZ", off + 1)
    return -1


def _find_formats(data: bytes) -> Dict[str, int]:
    """All structurally valid formats in *data* -> first offset found.

    A format at offset 0 is the file's *primary* format; the same format
    embedded at a non-zero offset is a polyglot ingredient.
    """
    found: Dict[str, int] = {}
    for name, (validator, magic) in _FORMATS.items():
        try:
            if validator(data, 0):
                found[name] = 0
                continue
        except Exception:
            pass
        # Embedded copy: pre-filter on the first magic, then validate.
        off = data.find(magic, 1)
        while off != -1 and off < SCAN_LIMIT:
            try:
                if validator(data, off):
                    found[name] = off
                    break
            except Exception:
                pass
            off = data.find(magic, off + 1)
    return found


def _high_entropy_region(data: bytes) -> Optional[int]:
    """Offset of a >= BLOB_MIN_SIZE high-entropy region, or None."""
    n = len(data)
    if n < BLOB_MIN_SIZE:
        return None
    # Small files get a smaller window so a blob near the end is not
    # diluted by the text in front of it.
    window = _WINDOW if n >= 256 * 1024 else BLOB_MIN_SIZE
    step = max(window // 2, 1024)
    off = 0
    while off + window <= n:
        if shannon_entropy(data[off:off + window]) >= BLOB_ENTROPY:
            return off
        off += step
    if n - off < window and n - off >= BLOB_MIN_SIZE:
        if shannon_entropy(data[off:]) >= BLOB_ENTROPY:
            return off
    return None


def analyze(path_str: str, data: bytes) -> List[Finding]:
    """Run polyglot detection over *data*; returns findings (kind=polyglot)."""
    if not data:
        return []
    found = _find_formats(data)
    primary = next((n for n, o in found.items() if o == 0), None)
    out: List[Finding] = []

    if primary is None:
        # Not a known container at all: check "text with embedded payload".
        if _looks_like_text(data):
            pe_off = _embedded_pe_in_text(data)
            if pe_off != -1:
                out.append(Finding(
                    path=path_str, kind="polyglot",
                    name="Text file with embedded PE executable",
                    severity="high",
                    message=("the file starts as plain text but contains a "
                             f"valid Windows PE image at offset {pe_off}"),
                ))
            else:
                blob_off = _high_entropy_region(data)
                if blob_off is not None:
                    out.append(Finding(
                        path=path_str, kind="polyglot",
                        name="Text file with embedded binary blob",
                        severity="medium",
                        message=("plain-text file contains a "
                                 f"{BLOB_MIN_SIZE // 1024} KiB+ "
                                 f"high-entropy binary region at offset "
                                 f"{blob_off} (steganography / hidden "
                                 "payload pattern)"),
                    ))
        return out

    # A known container with an embedded second format: report flagged pairs.
    for name, off in found.items():
        if name == primary or off == 0:
            continue
        spec = _PAIRS.get((primary, name))
        if spec is None:
            continue
        severity, label = spec
        out.append(Finding(
            path=path_str, kind="polyglot", name=label, severity=severity,
            message=(f"valid {primary} at offset 0 and valid {name} at "
                     f"offset {off} in the same file"),
        ))
    return out
