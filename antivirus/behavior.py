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
_PE_DANGEROUS_API_RULES: List[Tuple[set, int, str, str]] = [
    (
        {"kernel32.dll!VirtualAllocEx", "kernel32.dll!WriteProcessMemory",
         "kernel32.dll!CreateRemoteThread"},
        2, "high",
        "Process-injection API set (remote alloc + write + thread)",
    ),
    (
        {"wininet.dll!URLDownloadToFileA", "wininet.dll!InternetOpenA",
         "winhttp.dll!WinHttpSendRequest", "winhttp.dll!WinHttpOpen",
         "winhttp.dll!WinHttpReceiveResponse"},
        1, "medium",
        "Network download APIs",
    ),
    (
        {"kernel32.dll!ShellExecuteA", "kernel32.dll!ShellExecuteW",
         "kernel32.dll!WinExec", "kernel32.dll!CreateProcessA",
         "kernel32.dll!CreateProcessW"},
        1, "medium",
        "Process execution APIs",
    ),
    (
        {"advapi32.dll!RegSetValueExA", "advapi32.dll!RegSetValueExW",
         "advapi32.dll!RegCreateKeyA", "advapi32.dll!RegCreateKeyW"},
        1, "medium",
        "Registry modification (possible persistence)",
    ),
    (
        {"kernel32.dll!SetFileTime"},
        1, "low",
        "File timestamp tampering (anti-forensics)",
    ),
    (
        {"crypt32.dll!CryptDecrypt", "advapi32.dll!CryptDecrypt"},
        1, "low",
        "In-process decryption (possible encrypted payload)",
    ),
    (
        {"ws2_32.dll!connect", "ws2_32.dll!send", "ws2_32.dll!recv"},
        2, "medium",
        "Raw network sockets (possible C2)",
    ),
]

_PACKER_SECTION_NAMES = {b"UPX0", b"UPX1", b".nsp0", b".nsp1", b".themida", b".vmp0"}


def _pe_rva2off(sections, rva: int) -> Optional[int]:
    for _name, vsize, vrva, rawsize, rawptr in sections:
        if vrva and vrva <= rva < vrva + max(vsize, rawsize):
            return rawptr + (rva - vrva)
    return None


def analyze_pe(data: bytes) -> List[Indicator]:
    """Structural analysis of a PE file: sections + import table."""
    out: List[Indicator] = []
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return out
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            return out
        machine, nsections = struct.unpack_from("<HH", data, e_lfanew + 4)
        _timestamp, _ptr, _nsym, sizeof_optional, _chars = struct.unpack_from(
            "<IIIHH", data, e_lfanew + 8)
        opt = e_lfanew + 24
        if opt + 4 > len(data):
            return out
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic not in (0x10B, 0x20B):
            return out
        pe32plus = magic == 0x20B

        # Section table.
        sections = []
        sect = opt + sizeof_optional
        for i in range(nsections):
            s = sect + i * 40
            if s + 40 > len(data):
                break
            name = data[s:s + 8].rstrip(b"\0")
            vsize, vrva, rawsize, rawptr = struct.unpack_from("<IIII", data, s + 8)
            sections.append((name, vsize, vrva, rawsize, rawptr))

        # Per-section entropy (packer / encrypted-section detection).
        for name, vsize, vrva, rawsize, rawptr in sections:
            if rawsize >= 8192 and rawptr < len(data):
                chunk = data[rawptr:rawptr + min(rawsize, 256 * 1024)]
                ent = shannon_entropy(chunk)
                if ent >= 7.0:
                    out.append(Indicator(
                        "Packed/encrypted PE section", "medium",
                        f"section {name.decode('latin1')} has entropy "
                        f"{ent:.2f} bits/byte – likely packed or encrypted",
                    ))
            if name in _PACKER_SECTION_NAMES:
                out.append(Indicator(
                    "Known packer section name", "medium",
                    f"section name {name.decode('latin1')} is used by known packers",
                ))

        # Import table.
        dd_off = opt + (112 if pe32plus else 96)
        if dd_off + 16 > len(data):
            return out
        import_rva, _import_size = struct.unpack_from("<II", data, dd_off + 8)
        apis = _pe_imports(data, sections, import_rva, pe32plus)

        for api_set, minimum, sev, msg in _PE_DANGEROUS_API_RULES:
            hit = api_set & apis
            if len(hit) >= minimum:
                out.append(Indicator(
                    f"PE imports: {msg}", sev,
                    "imports " + ", ".join(sorted(hit)),
                ))
        # Download + execute combination escalates.
        downloads = apis & {
            "wininet.dll!URLDownloadToFileA", "wininet.dll!InternetOpenA",
            "winhttp.dll!WinHttpSendRequest", "winhttp.dll!WinHttpOpen",
        }
        execs = apis & {
            "kernel32.dll!ShellExecuteA", "kernel32.dll!ShellExecuteW",
            "kernel32.dll!WinExec", "kernel32.dll!CreateProcessA",
            "kernel32.dll!CreateProcessW",
        }
        if downloads and execs:
            out.append(Indicator(
                "PE downloads AND executes code", "high",
                "imports both network download and process execution APIs",
            ))
    except (struct.error, IndexError, UnicodeDecodeError):
        pass  # malformed PE – nothing to report
    return out


def _pe_imports(data: bytes, sections, import_rva: int,
                pe32plus: bool) -> set:
    apis: set = set()
    if not import_rva:
        return apis
    off = _pe_rva2off(sections, import_rva)
    if off is None:
        return apis
    entry_size = 8 if pe32plus else 4
    ordinal_flag = (1 << 63) if pe32plus else (1 << 31)
    fmt = "<Q" if pe32plus else "<I"
    i = 0
    while i < 1024:  # safety bound
        base = off + i * 20
        if base + 20 > len(data):
            break
        irt, _timestamp, _fwd, name_rva, iat = struct.unpack_from(
            "<IIIII", data, base)
        if irt == 0 and name_rva == 0 and iat == 0:
            break
        name_off = _pe_rva2off(sections, name_rva)
        dll = "?"
        if name_off is not None:
            end = data.find(b"\0", name_off)
            dll = data[name_off:end if end != -1 else len(data)].decode(
                "ascii", "replace").lower()
        thunk_rva = irt or iat
        thunk_off = _pe_rva2off(sections, thunk_rva) if thunk_rva else None
        if thunk_off is not None:
            j = 0
            while j < 1024:  # safety bound
                t = thunk_off + j * entry_size
                if t + entry_size > len(data):
                    break
                entry = struct.unpack_from(fmt, data, t)[0]
                if entry == 0:
                    break
                if entry & ordinal_flag:
                    apis.add(f"{dll}!#{entry & 0xFFFF}")
                else:
                    # entry -> 2-byte hint + null-terminated name
                    no = _pe_rva2off(sections, entry & (ordinal_flag - 1))
                    if no is not None and no + 3 <= len(data):
                        end = data.find(b"\0", no + 2)
                        nm = data[no + 2:end if end != -1 else len(data)].decode(
                            "ascii", "replace")
                        if nm:
                            apis.add(f"{dll}!{nm}")
                j += 1
        i += 1
    return apis


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
