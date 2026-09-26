"""Behavioural (static) analysis – *what does this file appear to do?*

Complements the signature layers: signatures ask "is this a known bad
file?", behaviour analysis asks "does this file *act* like malware?".

Everything here is **static** analysis – scripts are parsed with ``ast``
(never executed), binaries are dissected structurally.  Nothing produced
or found by this module is ever run.

Analysed files
--------------
Only files that *look executable* are examined (script extension, shebang,
PE/ELF magic) – a plain .txt/.md document is not treated as code.

Layers
------
* **Python** – AST analysis: ``eval``/``exec`` on non-constant input,
  ``subprocess(..., shell=True)``, ``os.system``, ``pty.spawn``, sockets
  connecting to hardcoded addresses, dynamic imports, base64 payload
  blobs.  Falls back to regexes when the source is not parseable.
* **Shell / PowerShell / Batch** – pipe-to-shell downloads, reverse-shell
  markers, crypto-mining C2 endpoints, LOLBin downloaders, persistence
  (cron / services / shell rc), encoded payloads.
* **PE binaries** – section table (per-section entropy = packers, known
  packer section names) and the import table (dangerous API combinations:
  process injection, download + execute, registry persistence, timestamp
  tampering, crypto).
* **ELF binaries** – program-header walk, high-entropy loadable segments.
* **Binary string IOCs** – reverse-shell / C2 byte markers inside any
  executable-looking binary.
* **File-system** – setuid/setgid executables.
"""
from __future__ import annotations

import ast
import os
import re
import stat as statmod
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from .models import Finding, shannon_entropy

#: Behavioural analysis is only applied to files up to this size.
MAX_BEHAVIOR_SIZE = 2 * 1024 * 1024

_SCRIPT_EXTS = {
    ".py", ".pyw", ".sh", ".bash", ".zsh", ".ksh", ".fish",
    ".ps1", ".psm1", ".psd1", ".bat", ".cmd",
    ".php", ".pl", ".pm", ".rb", ".js", ".mjs", ".cjs", ".ts",
    ".lua", ".tcl", ".vbs", ".vbe", ".wsf", ".swift", ".r",
}
_SHELL_EXTS = {".sh", ".bash", ".zsh", ".ksh", ".fish"}
_PS_EXTS = {".ps1", ".psm1", ".psd1"}
_BAT_EXTS = {".bat", ".cmd"}

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


@dataclass
class Indicator:
    """A behavioural indicator description (shared by the text analysers)."""

    name: str
    severity: str
    message: str


def looks_executable(path: Path, head: bytes) -> bool:
    """Heuristic: does this file look like something that can be executed?"""
    if head[:2] == b"MZ" or head[:4] == b"\x7fELF":
        return True
    if head.startswith(b"#!"):
        return True
    return Path(path).suffix.lower() in _SCRIPT_EXTS


# --------------------------------------------------------------------- Python
def _dotted(node: ast.AST) -> Optional[str]:
    """Best-effort dotted name for a call target: os.system, subprocess.run…"""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute) and isinstance(
        node.value, (ast.Name, ast.Attribute)
    ):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _is_const(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant)


def _long_base64_blobs(tree: ast.AST) -> List[int]:
    blobs = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and len(node.value) >= 200
        ):
            stripped = re.sub(r"\s+", "", node.value)
            if len(stripped) >= 200 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", stripped):
                blobs.append(len(node.value))
    return blobs


def _python_regex_fallback(text: str) -> List[Indicator]:
    out = []
    rules = [
        (re.compile(r"(?:eval|exec)\s*\(\s*(?:base64|b64|bytes\s*\.\s*fromhex|"
                    r"zlib\.decompress|urlopen|requests\.\w+|urllib)", re.I),
         "high", "Dynamic code execution on fetched/decoded data"),
        (re.compile(r"subprocess\.\w+\s*\([^)]*shell\s*=\s*True"),
         "medium", "subprocess call with shell=True"),
        (re.compile(r"\bos\s*\.\s*(?:system|popen)\s*\("),
         "medium", "Shell command execution via os.system / os.popen"),
        (re.compile(r"\bpty\s*\.\s*spawn\b"),
         "high", "Interactive pty spawn (typical of reverse shells)"),
        (re.compile(r"connect\s*\(\s*\(\s*[\"'](\d{1,3}(?:\.\d{1,3}){3})[\"']\s*,"
                    r"\s*(\d+)"),
         "high", "Network connect to a hardcoded address"),
    ]
    for rx, sev, msg in rules:
        if rx.search(text):
            out.append(Indicator(msg, sev, msg))
    return out


def analyze_python(text: str) -> List[Indicator]:
    """AST-based analysis of a Python source (never executes it)."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return _python_regex_fallback(text)

    out: List[Indicator] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        if not name:
            continue
        base = name.rsplit(".", 1)[-1]

        if base in ("eval", "exec", "compile") and node.args and not all(
            _is_const(a) for a in node.args
        ):
            out.append(Indicator(
                f"Dynamic code execution ({base})",
                "high" if base != "compile" else "medium",
                f"{name}() called on non-constant input",
            ))
        if name in ("os.system", "os.popen"):
            out.append(Indicator(
                "Shell command execution", "medium",
                f"{name}() runs commands through a shell",
            ))
        if name.startswith("subprocess.") and any(
            k.arg == "shell" and isinstance(k.value, ast.Constant)
            and k.value.value is True
            for k in node.keywords
        ):
            out.append(Indicator(
                "Subprocess with shell=True", "medium",
                f"{name}() interprets its argument as a shell command",
            ))
        if base in ("b64decode", "b85decode") or name in (
            "bytes.fromhex", "codecs.decode", "zlib.decompress",
            "marshal.loads", "pickle.loads",
        ):
            out.append(Indicator(
                "Encoded payload handling", "low",
                f"{name}() decodes/loads data that may be a payload",
            ))
        if name == "__import__" and node.args and not _is_const(node.args[0]):
            out.append(Indicator(
                "Dynamic import", "low",
                "__import__() of a non-constant module name",
            ))
        if name.endswith(".connect") and node.args and isinstance(
            node.args[0], ast.Tuple
        ) and len(node.args[0].elts) == 2:
            ip_el, port_el = node.args[0].elts
            if (
                isinstance(ip_el, ast.Constant)
                and isinstance(port_el, ast.Constant)
                and isinstance(ip_el.value, str)
                and _IP_RE.match(ip_el.value)
            ):
                out.append(Indicator(
                    "Hardcoded network target", "high",
                    f"socket.connect() to hardcoded {ip_el.value}:{port_el.value}",
                ))
    for length in _long_base64_blobs(tree):
        out.append(Indicator(
            "Obfuscated payload blob", "medium",
            f"base64-like string constant of {length} chars",
        ))
    return out


# ---------------------------------------------------------------------- Shell
_SHELL_RULES: List[Tuple["re.Pattern[str]", str, str]] = [
    (re.compile(r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b"),
     "high", "Downloads a remote script and pipes it into a shell"),
    (re.compile(r"base64\s+(?:-d|--decode)[^\n|]*\|\s*(?:ba|z|k)?sh\b"),
     "high", "Decodes embedded base64 and pipes it into a shell"),
    (re.compile(r"/dev/(?:tcp|udp)/"),
     "high", "Reverse-shell via /dev/tcp or /dev/udp"),
    (re.compile(r"\b(?:nc|ncat|netcat)\b[^\n]*\s-e\s"),
     "high", "netcat with exec flag (reverse shell)"),
    (re.compile(r"\bmkfifo\b"),
     "medium", "mkfifo pipe (common in reverse shells)"),
    (re.compile(r"chmod\s+(?:\+x|7\d\d)\s*[\"']?/(?:tmp|dev/shm|var/tmp)/"),
     "medium", "Stages an executable in world-writable space"),
    (re.compile(r"\bcrontab\b|/etc/cron|\b/var/spool/cron\b|\bsystemctl\s+(?:enable|start)\b"
                r"|>>\s*(?:~|\$HOME|\$HOME/)?/?\.(?:bash|zsh|profile)|\blaunchctl\s+load\b"
                r"|\b/etc/rc\.local\b", re.I),
     "medium", "Persistence mechanism (cron / service / shell rc / startup)"),
    (re.compile(r"stratum\+tcp://"),
     "medium", "Crypto-mining pool endpoint (C2)"),
    (re.compile(r"\bdd\b[^\n]*\bof=/dev/(?:sd|nvme|hd|mmcblk)"),
     "high", "Writes raw blocks directly to a disk device"),
    (re.compile(r"powershell[^\n]*-\s?enc(odedcommand)?\b", re.I),
     "high", "Spawns encoded PowerShell"),
]


def analyze_shell(text: str) -> List[Indicator]:
    return [Indicator(msg, sev, msg) for rx, sev, msg in _SHELL_RULES if rx.search(text)]


def analyze_powershell(text: str) -> List[Indicator]:
    out = []
    if re.search(r"\bIEX\b|Invoke-Expression", text, re.I) and re.search(
        r"DownloadString|DownloadFile|\biwr\b|Invoke-WebRequest|Net\.WebClient|Start-BitsTransfer",
        text, re.I,
    ):
        out.append(Indicator(
            "Download & execute", "high",
            "IEX/Invoke-Expression combined with a download call",
        ))
    if re.search(r"-ExecutionPolicy\s+Bypass", text, re.I):
        out.append(Indicator(
            "Execution policy bypass", "medium",
            "-ExecutionPolicy Bypass disables script signing checks",
        ))
    if re.search(r"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{40,}", text, re.I):
        out.append(Indicator(
            "Encoded payload", "high",
            "EncodedCommand argument (base64 PowerShell payload)",
        ))
    if re.search(r"TcpClient|Socket\(", text, re.I):
        out.append(Indicator(
            "Raw socket usage", "medium",
            "TcpClient/Socket primitives (possible C2 channel)",
        ))
    return out


def analyze_batch(text: str) -> List[Indicator]:
    out = []
    rules = [
        (re.compile(r"certutil\b[^\n]*-urlcache", re.I),
         "high", "certutil URL download (LOLBin)"),
        (re.compile(r"bitsadmin\s+/transfer", re.I),
         "high", "bitsadmin file download (LOLBin)"),
        (re.compile(r"\bmshta\b[^\n]*(?:http|javascript)", re.I),
         "high", "mshta remote/HTA script execution (LOLBin)"),
    ]
    for rx, sev, msg in rules:
        if rx.search(text):
            out.append(Indicator(msg, sev, msg))
    return out


# --------------------------------------------------------------------- PE files
def analyze_pe(data: bytes) -> List[Indicator]:
    """Full PE dissection + suspicious characteristics (see pe.py)."""
    from .pe import parse_pe, pe_indicators  # local import: no cycle at load

    return pe_indicators(parse_pe(data))


# --------------------------------------------------------------------- ELF files
def analyze_elf(data: bytes) -> List[Indicator]:
    """Light structural analysis of an ELF file."""
    out: List[Indicator] = []
    try:
        if len(data) < 0x40 or data[:4] != b"\x7fELF":
            return out
        is64 = data[4] == 2
        if is64:
            e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
            e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
        else:
            e_phoff = struct.unpack_from("<I", data, 0x1C)[0]
            e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x2E)
        for i in range(min(e_phnum, 64)):
            base = e_phoff + i * e_phentsize
            if base + e_phentsize > len(data) or e_phentsize == 0:
                break
            p_type = struct.unpack_from("<I", data, base)[0]
            if is64:
                p_offset, p_filesz = struct.unpack_from("<QQ", data, base + 8)
            else:
                p_offset, p_filesz = struct.unpack_from("<II", data, base + 4)
            if p_type == 1 and p_filesz >= 8192 and p_offset < len(data):  # PT_LOAD
                chunk = data[p_offset:p_offset + min(p_filesz, 256 * 1024)]
                ent = shannon_entropy(chunk)
                if ent >= 7.0:
                    out.append(Indicator(
                        "Packed/encrypted ELF segment", "medium",
                        f"PT_LOAD segment has entropy {ent:.2f} bits/byte "
                        f"– likely packed or encrypted",
                    ))
    except (struct.error, IndexError):
        pass
    out.extend(elf_import_indicators(data))
    return out


# ELF import-table analysis (the mirror of the PE import rules): which
# foreign symbols does the binary ask the dynamic linker to resolve?
_ELF_DANGEROUS_API_RULES: List[Tuple[set, int, str, str]] = [
    (
        {"system", "execve", "execv", "execvp", "popen", "popen2"},
        2, "high",
        "ELF process-execution API set (system/execve/popen)",
    ),
    (
        {"dlopen", "dlsym", "dlclose", "dlopen64"},
        2, "medium",
        "ELF dynamic library loading APIs (dlopen/dlsym)",
    ),
    (
        {"socket", "connect", "send", "recv", "bind", "listen", "accept"},
        3, "medium",
        "ELF raw network socket APIs",
    ),
    (
        {"ptrace"},
        1, "medium",
        "ELF ptrace import (debugging / anti-analysis)",
    ),
    (
        {"chroot", "chdir", "unlink", "unlinkat", "rename"},
        3, "low",
        "ELF file-system manipulation APIs",
    ),
]


def elf_imports(data: bytes) -> set:
    """Imported (undefined) dynamic symbols of an ELF file, or empty set."""
    symbols: set = set()
    try:
        if len(data) < 0x40 or data[:4] != b"\x7fELF":
            return symbols
        is64 = data[4] == 2
        endian = ">" if data[5] == 2 else "<"
        if is64:
            e_shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                endian + "HHH", data, 0x3A)
            # ELF64_Shdr field offsets (64 bytes; 6 pad bytes after sh_flags)
            F_OFF, F_SIZE, F_ENT = 24, 32, 56
            sym_size = 24
            # Elf64_Sym: name(I)@0 info(B)@4 other(B)@5 shndx(H)@6 value(Q)@8
            sym_name_f, sym_name_off = "I", 0
            sym_shndx_off = 6
        else:
            e_shoff = struct.unpack_from(endian + "I", data, 0x20)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                endian + "HHH", data, 0x2E)
            F_OFF, F_SIZE, F_ENT = 16, 20, 36
            sym_size = 16
            sym_name_f, sym_name_off = "I", 0
            sym_shndx_off = 14  # st_shndx (st_info/st_other are @12/@13)
        if e_shoff == 0 or e_shentsize == 0 or e_shnum > 512:
            return symbols

        def sec(i: int) -> Optional[int]:
            base = e_shoff + i * e_shentsize
            if base + e_shentsize > len(data):
                return None
            return base

        def field(base: int, fmt: str, off: int) -> int:
            return struct.unpack_from(endian + fmt, data, base + off)[0]

        shstr_base = sec(e_shstrndx)
        if shstr_base is None:
            return symbols
        shstr_sec_off = field(shstr_base, "Q" if is64 else "I", F_OFF)
        shstr_sec_size = field(shstr_base, "Q" if is64 else "I", F_SIZE)
        shstrtab = data[shstr_sec_off:shstr_sec_off + shstr_sec_size] \
            if shstr_sec_off < len(data) else b""

        def sec_name(i: int) -> str:
            base = sec(i)
            if base is None:
                return ""
            n = field(base, "I", 0)
            if n >= len(shstrtab):
                return ""
            end = shstrtab.find(b"\0", n)
            return shstrtab[n:end if end != -1 else len(shstrtab)].decode(
                "ascii", "replace")

        dynsym_i = dynstr_i = None
        for i in range(e_shnum):
            nm = sec_name(i)
            if nm == ".dynsym":
                dynsym_i = i
            elif nm == ".dynstr":
                dynstr_i = i
        if dynsym_i is None or dynstr_i is None:
            return symbols

        ds_base = sec(dynsym_i)
        dt_base = sec(dynstr_i)
        if ds_base is None or dt_base is None:
            return symbols
        dynstr_off = field(dt_base, "Q" if is64 else "I", F_OFF)
        dynstr_size = field(dt_base, "Q" if is64 else "I", F_SIZE)
        dynsym_off = field(ds_base, "Q" if is64 else "I", F_OFF)
        dynsym_size = field(ds_base, "Q" if is64 else "I", F_SIZE)
        n_syms = min(dynsym_size // sym_size, 8192)
        for j in range(n_syms):
            b = dynsym_off + j * sym_size
            if b + sym_size > len(data):
                break
            st_name = field(b, sym_name_f, sym_name_off)
            st_shndx = field(b, "H", sym_shndx_off)
            if st_name == 0 or st_name >= dynstr_size or st_shndx != 0:
                continue  # not an imported (SHN_UNDEF) symbol
            end = data.find(b"\0", dynstr_off + st_name)
            sym = data[dynstr_off + st_name:
                       end if end != -1 else dynstr_off + dynstr_size].decode(
                           "ascii", "replace")
            if sym:
                symbols.add(sym)
    except (struct.error, IndexError):
        pass
    return symbols


def elf_import_indicators(data: bytes) -> List[Indicator]:
    """Red flags derived from an ELF import table (like the PE layer)."""
    symbols = elf_imports(data)
    if not symbols:
        return []
    out: List[Indicator] = []
    for api_set, minimum, sev, msg in _ELF_DANGEROUS_API_RULES:
        hit = api_set & symbols
        if len(hit) >= minimum:
            out.append(Indicator(
                f"ELF imports: {msg}", sev,
                "imports " + ", ".join(sorted(hit)),
            ))
    return out


# ------------------------------------------------------------- binary string IOCs
_BINARY_IOCS: List[Tuple[bytes, str, str]] = [
    (b"/dev/tcp/", "high", "Reverse-shell marker (/dev/tcp)"),
    (b"/dev/udp/", "high", "Reverse-shell marker (/dev/udp)"),
    (b"stratum+tcp://", "medium", "Crypto-mining pool C2 marker"),
    (b"powershell -enc", "high", "Encoded PowerShell marker"),
    (b"-EncodedCommand", "high", "Encoded PowerShell marker"),
    (b"nc -e", "high", "netcat exec reverse-shell marker"),
    (b"mkfifo", "medium", "mkfifo reverse-shell marker"),
    (b"certutil -urlcache", "high", "certutil URL download (LOLBin)"),
    (b"bitsadmin /transfer", "high", "bitsadmin download (LOLBin)"),
    (b"mshta http", "high", "mshta remote script (LOLBin)"),
]


def analyze_binary_iocs(data: bytes) -> List[Indicator]:
    lowered = data.lower()
    return [
        Indicator(msg, sev, msg)
        for needle, sev, msg in _BINARY_IOCS
        if needle.lower() in lowered
    ]


# --------------------------------------------------------------------------- top
def _shebang_interpreter(head: bytes) -> str:
    if not head.startswith(b"#!"):
        return ""
    line = head.split(b"\n", 1)[0].decode("utf-8", "replace").lower()
    return " ".join(line.split())


def analyze_file(path: Path, st: Optional[os.stat_result], content: bytes) -> List[Finding]:
    """Run all behavioural layers over one file; returns Finding objects."""
    indicators: List[Indicator] = []
    head = content[:8192]
    is_binary = b"\x00" in head

    # File-system behaviour: setuid/setgid executables.
    if st is not None and (st.st_mode & (statmod.S_ISUID | statmod.S_ISGID)) \
            and (st.st_mode & 0o111):
        kind = "setuid" if st.st_mode & statmod.S_ISUID else "setgid"
        indicators.append(Indicator(
            f"{kind} executable", "high" if kind == "setuid" else "medium",
            f"file carries the {kind} bit and is executable",
        ))

    if head[:2] == b"MZ":
        indicators.extend(analyze_pe(content))
    elif head[:4] == b"\x7fELF":
        indicators.extend(analyze_elf(content))

    if is_binary:
        indicators.extend(analyze_binary_iocs(content))
    else:
        text = content.decode("utf-8", "replace")
        ext = Path(path).suffix.lower()
        shebang = _shebang_interpreter(head)
        if ext == ".py" or "python" in shebang:
            indicators.extend(analyze_python(text))
        if ext in _SHELL_EXTS or "sh" in shebang:
            indicators.extend(analyze_shell(text))
        if ext in _PS_EXTS or "powershell" in shebang or "pwsh" in shebang:
            indicators.extend(analyze_powershell(text))
        if ext in _BAT_EXTS:
            indicators.extend(analyze_batch(text))

    # Deduplicate identical indicators (e.g. shell rule + generic IOC).
    seen = set()
    findings: List[Finding] = []
    for ind in indicators:
        key = (ind.name, ind.severity, ind.message)
        if key in seen:
            continue
        seen.add(key)
        findings.append(Finding(
            path=str(path),
            kind="behavior",
            name=ind.name,
            severity=ind.severity,
            message=ind.message,
        ))
    return findings
