"""Single-file identification: type (magic + extension), digests, metadata.

Powers the ``antivirus fileinfo`` command, the web console's quick-scan
box and the GUI's "file info" dialog.
"""
from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Dict, Optional

_TEXT_SUFFIXES = {
    ".py": "Python script",
    ".pyw": "Python script",
    ".sh": "shell script",
    ".bash": "shell script",
    ".ps1": "PowerShell script",
    ".bat": "Windows batch script",
    ".cmd": "Windows batch script",
    ".json": "JSON text",
    ".md": "markdown text",
    ".txt": "plain text",
    ".csv": "CSV text",
    ".toml": "TOML text",
    ".yml": "YAML text",
    ".yaml": "YAML text",
    ".ini": "INI text",
}


def identify_content(head: bytes, name: str) -> str:
    """Best-effort file type from magic bytes and the file extension."""
    if head[:2] == b"MZ":
        if head[:4] == b"MZ\x90":
            return "PE executable (Windows .exe/.dll)"
        return "DOS/PE executable"
    if head[:4] == b"\x7fELF":
        bits = "64-bit" if head[4:5] == b"\x02" else "32-bit"
        endian = "big" if head[5:6] == b"\x02" else "little"
        return f"ELF object ({bits}, {endian}-endian)"
    if head[:2] == b"\x1f\x8b":
        return "gzip stream"
    if head[:4] == b"PK\x03\x04" or head[:4] == b"PK\x05\x06":
        return "ZIP archive"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "TAR archive"
    if head.startswith(b"#!"):
        first = head.split(b"\n", 1)[0]
        return f"script (shebang: {first.decode('utf-8', 'replace').strip()})"
    if head[:5] == b"\xd0\xcf\x11\xe0\xa1\xb1":
        return "OLE2 compound document"
    if head[:4] == b"%PDF":
        return "PDF document"
    ext = Path(name).suffix.lower()
    if ext in _TEXT_SUFFIXES:
        return _TEXT_SUFFIXES[ext]
    if head and all(b == 0 or 32 <= b < 127 for b in head[:256]):
        return "text (plain/unknown)"
    return "binary (unknown)"


def file_info(path, chunk_size: int = 1024 * 1024) -> Dict:
    """Metadata + SHA-256 + MD5 for one file (streamed, single read)."""
    p = Path(path)
    st = p.lstat()
    head = b""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    try:
        with open(p, "rb") as fh:
            while chunk := fh.read(chunk_size):
                if not head:
                    head = chunk[:262]
                sha256.update(chunk)
                md5.update(chunk)
    except OSError:
        pass
    return {
        "path": str(p),
        "name": p.name,
        "size": st.st_size,
        "mtime": st.st_mtime,
        "mtime_iso": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
        "type": identify_content(head, p.name),
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
    }


def render_file_info(info: Dict) -> str:
    """Human-readable rendering for CLI / dialogs."""
    lines = [
        f"file:   {info['path']}",
        f"type:   {info['type']}",
        f"size:   {info['size']} bytes",
        f"mtime:  {info['mtime_iso']}",
        f"sha256: {info['sha256']}",
        f"md5:    {info['md5']}",
    ]
    return "\n".join(lines)


def quick_scan(path, scanner) -> list:
    """Findings for a single file, via the shared engine."""
    return scanner.scan_file(Path(path))
