"""Code-obfuscation-technique detection (v2.7).

The behaviour layer asks *what a file does*; this layer asks *whether the
file is deliberately hiding what it does*.  Techniques covered:

* **Encoded blobs** – long high-entropy base64 or hex runs inside any
  file (documents, scripts, binaries): the standard wrapper for embedded
  payloads (obfuscated PowerShell, shell stagers, malware-in-Word).
* **Double encoding** – base64 of base64: one layer deeper than the
  usual, a deliberate evasion step.
* **UTF-16 encoded blobs** – base64 stored as UTF-16LE (PowerShell
  ``-enc`` style) inside binary files.
* **Junk code** – NOP sleds / ``int3`` padding inside PE code (mutator
  and packer output).
* **Packed PE without an import table** – the image is packed/encrypted
  *and* declares no imports: the API surface is hidden entirely, which
  is aggressive obfuscation (a normal PE needs imports).

All checks are static; nothing is executed or decoded into memory for
execution.
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import List, Optional

from .models import Finding, shannon_entropy

#: Scan budget for the blob searches (bytes of *data* examined).
SCAN_LIMIT = 4 * 1024 * 1024

#: A base64-like run of at least this length with entropy >= B64_ENTROPY
#: is reported as an encoded payload blob.
B64_MIN_LEN = 512
B64_ENTROPY = 4.6
_HEX_MIN_LEN = 1024
HEX_ENTROPY = 3.4

B64_RE = re.compile(rb"[A-Za-z0-9+/]{%d,}={0,2}" % B64_MIN_LEN)
HEX_RE = re.compile(rb"[0-9a-fA-F]{%d,}" % _HEX_MIN_LEN)
NOP_RE = re.compile(rb"\x90{256,}")
INT3_RE = re.compile(rb"\xcc{256,}")
_B64_SAMPLE = 8192  # entropy is sampled on at most this many chars


def _blob_finding(path_str: str, kind: str, label: str, severity: str,
                  msg: str) -> Finding:
    return Finding(path=path_str, kind=kind, name=label, severity=severity,
                   message=msg)


def _check_b64_blobs(path_str: str, text: bytes, out: List[Finding],
                     label_prefix: str) -> Optional[bytes]:
    """Report long high-entropy base64 runs; returns the first one found."""
    first: Optional[bytes] = None
    count = 0
    for m in B64_RE.finditer(text):
        blob = m.group(0)
        if shannon_entropy(blob[:_B64_SAMPLE]) < B64_ENTROPY:
            continue
        if first is None:
            first = blob
        count += 1
        if count >= 2:
            break
    if count:
        ent = shannon_entropy(first[:_B64_SAMPLE])
        out.append(_blob_finding(
            path_str, "obfuscation",
            f"{label_prefix} high-entropy encoded blob", "medium",
            f"base64-like run of {len(first)} chars "
            f"(entropy {ent:.2f}) - possible obfuscated payload",
        ))
    return first


def _check_double_encoding(path_str: str, blob: bytes,
                           out: List[Finding]) -> None:
    """If *blob* decodes to yet another base64 layer, say so."""
    if not blob or len(blob) > 1024 * 1024:
        return
    try:
        inner = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        return
    if len(inner) < 256:
        return
    printable = sum(1 for b in inner if chr(b) in
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789+/=")
    if printable / len(inner) >= 0.95:
        out.append(_blob_finding(
            path_str, "obfuscation", "Double-encoded payload", "high",
            f"base64 blob decodes to another {len(inner)}-char base64 "
            "layer (deliberate extra obfuscation)",
        ))


def _check_pe_junk(path_str: str, data: bytes, out: List[Finding]) -> None:
    m = NOP_RE.search(data)
    if m is not None:
        out.append(_blob_finding(
            path_str, "obfuscation", "Junk code: NOP sled padding", "medium",
            f"run of {len(m.group(0))} consecutive NOP (0x90) bytes in the "
            "code image (mutator / packer output)",
        ))
    m = INT3_RE.search(data)
    if m is not None:
        out.append(_blob_finding(
            path_str, "obfuscation", "Junk code: int3 padding", "low",
            f"run of {len(m.group(0))} consecutive int3 (0xCC) bytes",
        ))


def _check_pe_packed_no_imports(path_str: str, data: bytes,
                                out: List[Finding]) -> None:
    if data[:2] != b"MZ" or len(data) < 0x200:
        return
    from .pe import parse_pe  # local import: no cycle at load time
    info = parse_pe(data)
    if not info.valid or info.is_dotnet:
        return
    packed = any(s.entropy is not None and s.entropy >= 7.0
                 for s in info.sections)
    if packed and not info.imports:
        sec = max((s for s in info.sections if s.entropy is not None),
                  key=lambda s: s.entropy or 0, default=None)
        detail = (f"section {sec.name} entropy {sec.entropy:.2f}"
                  if sec is not None else "packed sections")
        out.append(_blob_finding(
            path_str, "obfuscation",
            "Packed PE with no import table", "high",
            f"the image is packed/encrypted ({detail}) and declares no "
            "imports - the API surface is hidden (aggressive obfuscation)",
        ))


def analyze(path_str: str, data: bytes) -> List[Finding]:
    """Run all obfuscation-technique checks; returns findings (kind=obfuscation)."""
    if not data:
        return []
    data = data[:SCAN_LIMIT]
    out: List[Finding] = []

    is_binary = b"\x00" in data[:8192]

    # 1) ASCII/Latin-1 text view (covers scripts, documents, and the
    #    printable runs inside binaries).
    try:
        text = data.decode("latin-1")
    except (UnicodeDecodeError, ValueError):
        text = ""
    if text:
        first = _check_b64_blobs(path_str, text.encode("latin-1"), out,
                                 "Obfuscated payload:")
        if first is not None:
            _check_double_encoding(path_str, first, out)

    # 2) UTF-16LE view (PowerShell -enc style payloads in binary files).
    if is_binary and len(data) >= 2 * B64_MIN_LEN:
        try:
            u16 = data.decode("utf-16-le", "ignore")
        except (UnicodeDecodeError, ValueError):
            u16 = ""
        if u16:
            _check_b64_blobs(path_str, u16.encode("latin-1", "ignore"),
                             out, "UTF-16 obfuscated payload:")

    # 3) PE-specific: junk code + packed-with-no-imports.
    if data[:2] == b"MZ":
        _check_pe_junk(path_str, data, out)
        _check_pe_packed_no_imports(path_str, data, out)

    # 4) Hex blobs (only in text-ish files: a 1 KiB hex run inside a
    #    binary is indistinguishable from ordinary code bytes).
    if not is_binary and text:
        for m in HEX_RE.finditer(text.encode("latin-1")):
            blob = m.group(0)
            if shannon_entropy(blob[:_B64_SAMPLE]) >= HEX_ENTROPY:
                out.append(_blob_finding(
                    path_str, "obfuscation",
                    "Obfuscated payload: high-entropy hex blob", "medium",
                    f"hex run of {len(blob)} chars "
                    f"(entropy {shannon_entropy(blob[:_B64_SAMPLE]):.2f}) "
                    "- possible encoded payload",
                ))
                break
    return out
