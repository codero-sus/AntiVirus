"""PE / .exe dissection – a "debug report" for Windows PE images.

Static analysis only: the file is dissected structurally, exactly like a
debugger's module view (headers, sections, imports, exports, resources,
relocations, TLS, debug directories) and *never executed*.

Two audiences:
* ``render_pe_report`` – a human readable dissection report for the
  ``antivirus pe analyze`` command.
* ``pe_indicators`` – suspicious characteristics derived from the debug
  view (no relocations, DEP/ASLR disabled, embedded scripts in resources,
  TLS callbacks, dangerous import combinations, …) fed into the scanner
  as behavioural findings.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .models import Finding, shannon_entropy
from .behavior import Indicator

# --------------------------------------------------------------------- tables
_MACHINE_NAMES = {
    0x014C: "i386", 0x8664: "x86-64", 0x01C0: "ARM", 0xAA64: "ARM64",
    0x01C4: "ARMNT", 0x102: "Itanium", 0x0200: "PowerPC",
}

SUBSYSTEM_NAMES = {
    0: "unknown", 1: "native", 2: "windows gui", 3: "windows gui",
    7: "windows cui (console)", 8: "ce gui", 9: "efi application",
    10: "efi bootloader", 11: "efi rtd", 12: "efi free", 14: "xbox",
    16: "windows ce gui",
}

_CHAR_FLAGS = {
    0x0001: "RELOCS_STRIPPED",
    0x0002: "EXECUTABLE_IMAGE",
    0x0020: "LARGE_ADDRESS_AWARE",
    0x0100: "32BIT_MACHINE",
    0x2000: "DEBUG",
}

_DLL_CHAR_FLAGS = {
    0x0001: "ORIGINAL_FIRST_THUNK",
    0x0020: "HIGH_ENTROPY_VA",
    0x0040: "DYNAMIC_BASE (ASLR)",
    0x0100: "NX_COMPAT (DEP)",
    0x0200: "NO_ISOLATION",
    0x0400: "NO_SEH",
    0x0800: "NO_BIND",
    0x1000: "SUPPORTED",
    0x2000: "CET_COMPAT",
    0x8000: "TERMINAL_SERVER_AWARE",
}

_SECTION_FLAGS = {
    0x20: "CODE", 0x40: "INITIALIZED_DATA", 0x80: "UNINITIALIZED_DATA",
    0x200: "READ", 0x400: "WRITE", 0x1000: "EXECUTE", 0x2000: "MERGE",
    0x4000: "PREV_INIT", 0x8000: "16BIT", 0x10000: "LOCKED", 0x20000: "PRELOAD",
    0x40000: "ALIGN_1BYTES", 0x800000: "NO_DISCARD", 0x1000000: "NO_CACHE",
}

_RESOURCE_TYPES = {
    1: "RT_CURSOR", 2: "RT_BITMAP", 3: "RT_ICON", 4: "RT_MENU",
    5: "RT_DIALOG", 6: "RT_STRING", 7: "RT_FONTDIR", 8: "RT_FONT",
    9: "RT_ACCELERATOR", 10: "RT_GROUP_ICON", 11: "RT_VERSION",
    12: "RT_DLGINCLUDE", 16: "RT_RCDATA", 24: "RT_MANIFEST",
}

#: Byte markers that indicate scripts/commands hidden in resources –
#: a classic trojan technique ("office doc / icon + embedded payload").
_RESOURCE_MARKERS: List[Tuple[bytes, str]] = [
    (b"WScript.Shell", "VBScript (WScript.Shell)"),
    (b"WScript.Network", "VBScript (WScript.Network)"),
    (b"Microsoft.PowerShell", "PowerShell command"),
    (b"powershell", "PowerShell reference"),
    (b"javascript:", "JavaScript resource"),
    (b"vbscript:", "VBScript resource"),
    (b"mshta", "mshta LOLBin reference"),
    (b"regsvr32", "regsvr32 LOLBin reference"),
    (b"rundll32", "rundll32 reference"),
    (b"certutil", "certutil LOLBin reference"),
    (b"cmd.exe", "cmd.exe reference"),
    (b"bitsadmin", "bitsadmin LOLBin reference"),
]

_PACKER_SECTION_NAMES = {b"UPX0", b"UPX1", b".nsp0", b".nsp1", b".themida", b".vmp0"}

# Import-API rules (dangerous combinations observed in malware loaders).
_API_RULES: List[Tuple[set, int, str, str]] = [
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

_DOWNLOAD_APIS = {
    "wininet.dll!URLDownloadToFileA", "wininet.dll!InternetOpenA",
    "winhttp.dll!WinHttpSendRequest", "winhttp.dll!WinHttpOpen",
}
_EXEC_APIS = {
    "kernel32.dll!ShellExecuteA", "kernel32.dll!ShellExecuteW",
    "kernel32.dll!WinExec", "kernel32.dll!CreateProcessA",
    "kernel32.dll!CreateProcessW",
}


# ------------------------------------------------------------------ data model
@dataclass
class PeSection:
    name: str
    vsize: int
    vrva: int
    rawsize: int
    rawptr: int
    characteristics: int
    entropy: Optional[float] = None

    @property
    def flags(self) -> List[str]:
        return sorted(n for b, n in _SECTION_FLAGS.items()
                      if self.characteristics & b)


@dataclass
class PeResource:
    type_id: int
    name_id: int
    type_name: str
    leaf_rva: int
    size: int
    markers: List[str] = field(default_factory=list)


@dataclass
class PeInfo:
    valid: bool = False
    error: str = ""
    file_size: int = 0

    machine: int = 0
    machine_name: str = "?"
    is_64: bool = False
    magic: int = 0
    characteristics: int = 0
    subsystem: int = 0
    dll_characteristics: int = 0
    image_base: int = 0
    entry_point_rva: int = 0
    section_alignment: int = 0
    file_alignment: int = 0
    size_of_image: int = 0
    size_of_headers: int = 0
    checksum: int = 0

    sections: List[PeSection] = field(default_factory=list)
    data_dirs: List[Tuple[str, int, int]] = field(default_factory=list)
    imports: Dict[str, List[str]] = field(default_factory=dict)
    api_set: set = field(default_factory=set)
    ilt_missing: bool = False
    exports: List[str] = field(default_factory=list)
    resources: List[PeResource] = field(default_factory=list)
    resource_bytes: int = 0
    reloc_blocks: int = 0
    reloc_entries: int = 0
    has_debug_dir: bool = False
    debug_dirs: int = 0
    has_tls: bool = False
    has_delay_imports: bool = False
    delay_imports: int = 0
    is_dotnet: bool = False


_DATA_DIR_NAMES = [
    "Export", "Import", "Resource", "Exception", "Certificate",
    "BaseReloc", "Debug", "Architecture", "GlobalPtr", "TLS",
    "LoadConfig", "BoundImport", "IAT", "DelayImport", "CLR",
    "Reserved",
]


# ------------------------------------------------------------------ helpers
def _flag_names(value: int, table: Dict[int, str]) -> List[str]:
    return sorted(n for b, n in table.items() if value & b)


def _rva2off(sections: List[PeSection], rva: int) -> Optional[int]:
    for s in sections:
        if s.vrva and s.vrva <= rva < s.vrva + max(s.vsize, s.rawsize):
            return s.rawptr + (rva - s.vrva)
    return None


# -------------------------------------------------------------------- parser
def parse_pe(data: bytes) -> PeInfo:
    """Dissect a PE image into a PeInfo structure (never executes it)."""
    info = PeInfo(file_size=len(data))
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            info.error = "not a PE file (no MZ header)"
            return info
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            info.error = "no PE signature at e_lfanew"
            return info

        machine, nsections = struct.unpack_from("<HH", data, e_lfanew + 4)
        _timestamp, _ptr, _nsym, sizeof_optional, chars = struct.unpack_from(
            "<IIIHH", data, e_lfanew + 8)
        info.machine = machine
        info.machine_name = _MACHINE_NAMES.get(machine, hex(machine))
        info.characteristics = chars

        opt = e_lfanew + 24
        if opt + 4 > len(data):
            info.error = "truncated optional header"
            return info
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic not in (0x10B, 0x20B):
            info.error = f"unknown optional header magic {magic:#x}"
            return info
        info.magic = magic
        info.is_64 = magic == 0x20B

        # Standard fields.
        _major, _minor = struct.unpack_from("<BB", data, opt + 2)
        info.entry_point_rva = struct.unpack_from("<I", data, opt + 16)[0]
        if info.is_64:
            info.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        else:
            info.image_base = struct.unpack_from("<I", data, opt + 28)[0]
        info.section_alignment = struct.unpack_from("<I", data, opt + 32)[0]
        info.file_alignment = struct.unpack_from("<I", data, opt + 36)[0]
        if info.is_64:
            info.subsystem = struct.unpack_from("<H", data, opt + 68)[0]
            info.dll_characteristics = struct.unpack_from("<H", data, opt + 70)[0]
            info.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
            info.size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
            info.checksum = struct.unpack_from("<I", data, opt + 64)[0]
        else:
            info.subsystem = struct.unpack_from("<H", data, opt + 68)[0]
            info.dll_characteristics = struct.unpack_from("<H", data, opt + 70)[0]
            info.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
            info.size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
            info.checksum = struct.unpack_from("<I", data, opt + 64)[0]

        # Section table.
        sect = opt + sizeof_optional
        for i in range(min(nsections, 96)):
            s = sect + i * 40
            if s + 40 > len(data):
                break
            name = data[s:s + 8].rstrip(b"\0").decode("latin1")
            vsize, vrva, rawsize, rawptr = struct.unpack_from("<IIII", data, s + 8)
            _r1, _r2, rchar = struct.unpack_from("<III", data, s + 20)
            sec = PeSection(name=name, vsize=vsize, vrva=vrva,
                            rawsize=rawsize, rawptr=rawptr, characteristics=rchar)
            if rawsize >= 4096 and rawptr < len(data):
                chunk = data[rawptr:rawptr + min(rawsize, 256 * 1024)]
                sec.entropy = shannon_entropy(chunk)
            info.sections.append(sec)

        # Data directories.
        dd_off = opt + (112 if info.is_64 else 96)
        if dd_off + 16 <= len(data):
            for i in range(16):
                rva, size = struct.unpack_from("<II", data, dd_off + i * 8)
                if rva or size:
                    info.data_dirs.append((_DATA_DIR_NAMES[i], rva, size))
        dirs = dict((n, (rva, size)) for n, rva, size in info.data_dirs)

        # Imports.
        if "Import" in dirs:
            info.imports, info.api_set, info.ilt_missing = _parse_imports(
                data, info, dirs["Import"][0])

        # Exports.
        if "Export" in dirs:
            info.exports = _parse_exports(data, info, dirs["Export"][0])

        # Resources.
        if "Resource" in dirs:
            info.resources, info.resource_bytes = _parse_resources(
                data, info, dirs["Resource"][0])

        # Relocations.
        if "BaseReloc" in dirs:
            info.reloc_blocks, info.reloc_entries = _parse_relocs(
                data, info, dirs["BaseReloc"][0])

        # Debug / TLS / delay / CLR.
        if "Debug" in dirs:
            info.has_debug_dir = True
            info.debug_dirs = max(dirs["Debug"][1] // 28, 0)
        if "TLS" in dirs:
            info.has_tls = True
        if "DelayImport" in dirs:
            info.has_delay_imports = True
            info.delay_imports = max(dirs["DelayImport"][1] // 20, 0)
        if "CLR" in dirs:
            cli_off = _rva2off(info.sections, dirs["CLR"][0])
            if cli_off is not None and cli_off + 4 <= len(data):
                cb = struct.unpack_from("<I", data, cli_off)[0]
                if 0 < cb <= 512:
                    info.is_dotnet = True

        info.valid = True
    except (struct.error, IndexError, UnicodeDecodeError, ValueError) as exc:
        info.error = f"malformed PE ({exc})"
    return info


def _parse_imports(data: bytes, info: PeInfo, import_rva: int
                   ) -> Tuple[Dict[str, List[str]], set, bool]:
    imports: Dict[str, List[str]] = {}
    apis: set = set()
    ilt_missing = False
    off = _rva2off(info.sections, import_rva)
    if off is None:
        return imports, apis, ilt_missing
    entry_size = 8 if info.is_64 else 4
    ordinal_flag = (1 << 63) if info.is_64 else (1 << 31)
    fmt = "<Q" if info.is_64 else "<I"
    i = 0
    while i < 1024:
        base = off + i * 20
        if base + 20 > len(data):
            break
        irt, _ts, _fwd, name_rva, iat = struct.unpack_from("<IIIII", data, base)
        if irt == 0 and name_rva == 0 and iat == 0:
            break
        name_off = _rva2off(info.sections, name_rva)
        dll = "?"
        if name_off is not None:
            end = data.find(b"\0", name_off)
            dll = data[name_off:end if end != -1 else len(data)].decode(
                "ascii", "replace").lower()
        if not irt and iat:
            ilt_missing = True  # no lookup table -> hand-rolled imports
        thunk_rva = irt or iat
        thunk_off = _rva2off(info.sections, thunk_rva) if thunk_rva else None
        if thunk_off is None:
            i += 1
            continue
        j = 0
        while j < 4096:
            t = thunk_off + j * entry_size
            if t + entry_size > len(data):
                break
            entry = struct.unpack_from(fmt, data, t)[0]
            if entry == 0:
                break
            if entry & ordinal_flag:
                apis.add(f"{dll}!#{entry & 0xFFFF}")
                imports.setdefault(dll, []).append(f"#{entry & 0xFFFF}")
            else:
                no = _rva2off(info.sections, entry & (ordinal_flag - 1))
                if no is not None and no + 3 <= len(data):
                    end = data.find(b"\0", no + 2)
                    nm = data[no + 2:end if end != -1 else len(data)].decode(
                        "ascii", "replace")
                    if nm:
                        apis.add(f"{dll}!{nm}")
                        imports.setdefault(dll, []).append(nm)
            j += 1
        i += 1
    return imports, apis, ilt_missing


def _parse_exports(data: bytes, info: PeInfo, rva: int) -> List[str]:
    names: List[str] = []
    off = _rva2off(info.sections, rva)
    if off is None or off + 40 > len(data):
        return names
    _c, _ts, _maj, _min, name_rva, _ordinal_base = struct.unpack_from(
        "<IIHHII", data, off)
    nfuncs, nnames, funcs_rva, names_rva, nameords_rva = struct.unpack_from(
        "<IIIII", data, off + 20)
    if names_rva and names_rva < 0x80000000 and nameords_rva:
        names_off = _rva2off(info.sections, names_rva)
        ords_off = _rva2off(info.sections, nameords_rva)
        if names_off is not None and ords_off is not None:
            for i in range(min(nnames, 4096)):
                nr = struct.unpack_from("<I", data, names_off + i * 4)[0]
                o = struct.unpack_from("<H", data, ords_off + i * 2)[0]
                no = _rva2off(info.sections, nr)
                if no is None:
                    continue
                end = data.find(b"\0", no)
                nm = data[no:end if end != -1 else len(data)].decode(
                    "ascii", "replace")
                if nm:
                    names.append(nm)
    return names


def _parse_resources(data: bytes, info: PeInfo, rva: int
                     ) -> Tuple[List[PeResource], int]:
    """Walk the resource directory tree.

    Per the PE spec, directory entry offsets (to sub-directories *and* to
    data entries) are relative to the start of the resource section in the
    image; only IMAGE_RESOURCE_DATA_ENTRY.OffsetToData is an absolute RVA.
    """
    resources: List[PeResource] = []
    total_bytes = 0
    scan_budget = 4 * 1024 * 1024
    top = _rva2off(info.sections, rva)
    if top is None:
        return resources, total_bytes
    base_vrva = next(
        (s.vrva for s in info.sections
         if s.vrva and s.vrva <= rva < s.vrva + max(s.vsize, s.rawsize)),
        0,
    )

    def _key_name(key: int, depth: int) -> Tuple[int, str]:
        if key & 0x80000000:  # named (UTF-16, absolute RVA)
            no = _rva2off(info.sections, key & 0x7FFFFFFF)
            if no is not None:
                end = data.find(b"\x00\x00", no)
                raw = data[no:end if end != -1 else no + 256]
                return 0, raw.decode("utf-16-le", "replace").strip("\x00")
            return 0, "<named?>"
        return key, _RESOURCE_TYPES.get(key, "") if depth == 0 else ""

    def _walk(dir_off: int, depth: int, path: List[Tuple[int, str]]) -> None:
        nonlocal total_bytes, scan_budget
        if depth > 4 or len(resources) > 4096:
            return
        if dir_off + 16 > len(data):
            return
        _chars, _ts, _maj, _min, n_named, n_id = struct.unpack_from(
            "<IIHHHH", data, dir_off)
        entries = dir_off + 16
        n_total = min(n_named + n_id, 512)
        for i in range(n_total):
            e = entries + i * 8
            if e + 8 > len(data):
                return
            key, off_to_data = struct.unpack_from("<II", data, e)
            kid, kname = _key_name(key, depth)
            cur = path + [(kid, kname)]
            if off_to_data & 0x80000000:
                child = _rva2off(info.sections, base_vrva + (off_to_data & 0x7FFFFFFF))
                if child is not None:
                    _walk(child, depth + 1, cur)
            else:
                leaf = _rva2off(info.sections, base_vrva + off_to_data)
                if leaf is None or leaf + 16 > len(data):
                    continue
                data_rva, size, _codepage, _res = struct.unpack_from(
                    "<IIII", data, leaf)
                if not cur or size > 16 * 1024 * 1024:
                    continue
                type_id, type_name = cur[0]
                name_id, _name_label = cur[1] if len(cur) > 1 else (0, "")
                res = PeResource(type_id=type_id, name_id=name_id,
                                 type_name=type_name, leaf_rva=data_rva,
                                 size=size, markers=[])
                doff = _rva2off(info.sections, data_rva)
                if doff is not None and size and scan_budget > 0:
                    n = min(size, scan_budget)
                    blob = data[doff:doff + n]
                    total_bytes += n
                    scan_budget -= n
                    low = blob.lower()
                    for needle, label in _RESOURCE_MARKERS:
                        if needle.lower() in low:
                            res.markers.append(label)
                resources.append(res)

    _walk(top, 0, [])
    return resources, total_bytes


def _parse_relocs(data: bytes, info: PeInfo, rva: int
                  ) -> Tuple[int, int]:
    blocks = 0
    entries = 0
    off = _rva2off(info.sections, rva)
    if off is None:
        return 0, 0
    entry_bytes = 8 if info.is_64 else 4
    while blocks < 4096:
        if off + 8 > len(data):
            break
        _va, size_of_block = struct.unpack_from("<II", data, off)
        if size_of_block < 8 or off + size_of_block > len(data):
            break
        entries += max(0, (size_of_block - 8) // entry_bytes)
        off += size_of_block
        blocks += 1
    return blocks, entries


# -------------------------------------------------------------- indicators
def pe_indicators(info: PeInfo) -> List[Indicator]:
    """Suspicious characteristics derived from the PE debug view."""
    if not info.valid:
        return []
    out: List[Indicator] = []
    apis = info.api_set

    # Sections: entropy + known packer names.
    for s in info.sections:
        if s.entropy is not None and s.entropy >= 7.0:
            out.append(Indicator(
                "Packed/encrypted PE section", "medium",
                f"section {s.name} has entropy {s.entropy:.2f} bits/byte "
                f"– likely packed or encrypted",
            ))
        if s.name.encode("latin1") in _PACKER_SECTION_NAMES:
            out.append(Indicator(
                "Known packer section name", "medium",
                f"section name {s.name} is used by known packers",
            ))

    # Characteristics / DLL characteristics.
    if info.characteristics & 0x0001:
        out.append(Indicator(
            "RELOCS_STRIPPED", "medium",
            "relocations were stripped at build time (common in packed images)",
        ))
    if not (info.dll_characteristics & 0x0040):
        out.append(Indicator(
            "ASLR disabled", "medium",
            "DYNAMIC_BASE is not set – the image cannot be relocated at load",
        ))
    if not (info.dll_characteristics & 0x0100):
        out.append(Indicator(
            "DEP (NX) disabled", "medium",
            "NX_COMPAT is not set – memory pages may be executable",
        ))
    if info.entry_point_rva == 0:
        out.append(Indicator(
            "No entry point", "medium",
            "AddressOfEntryPoint is 0 (shellcode/stager or broken image)",
        ))

    # Directories.
    has_reloc_dir = any(n == "BaseReloc" for n, _r, _s in info.data_dirs)
    if not has_reloc_dir or info.reloc_entries == 0:
        out.append(Indicator(
            "No base relocations", "medium",
            "relocation table missing or empty (typical of packers/protectors)",
        ))
    if not info.has_debug_dir:
        out.append(Indicator(
            "No debug information", "low",
            "debug directory absent (stripped release or packed image)",
        ))
    if info.has_tls:
        out.append(Indicator(
            "TLS callbacks", "low",
            "TLS directory present – callbacks run before main (anti-debug/early hooks)",
        ))
    dir_names = {n for n, _r, _s in info.data_dirs}
    if not info.imports and not info.is_dotnet and "Import" not in dir_names:
        out.append(Indicator(
            "No import table", "low",
            "image declares no imports (self-contained/packed or hand-rolled)",
        ))
    if info.ilt_missing:
        out.append(Indicator(
            "Import lookup table missing", "medium",
            "OriginalFirstThunk absent for at least one DLL (IAT obfuscation)",
        ))

    # Resources: size + embedded script/LOLBin markers.
    rsrc_sec = next(
        (s for s in info.sections
         if any(n == "Resource"
                for n, rva, _s in info.data_dirs
                if s.vrva and s.vrva <= rva < s.vrva + max(s.vsize, s.rawsize))
         ),
        None,
    )
    if rsrc_sec is not None and rsrc_sec.rawsize > 1024 * 1024:
        out.append(Indicator(
            "Unusually large resource section", "medium",
            f"resource section is {rsrc_sec.rawsize} bytes",
        ))
    reported_markers = set()
    for res in info.resources:
        for label in res.markers:
            if label in reported_markers:
                continue
            reported_markers.add(label)
            where = (f"resource type {res.type_name or res.type_id} "
                     f"(id {res.name_id})")
            out.append(Indicator(
                f"Embedded in resources: {label}", "high",
                f"resource section contains {label} ({where}, {res.size} bytes)",
            ))

    # Import API combinations.
    for api_set, minimum, sev, msg in _API_RULES:
        hit = api_set & apis
        if len(hit) >= minimum:
            out.append(Indicator(
                f"PE imports: {msg}", sev, "imports " + ", ".join(sorted(hit)),
            ))
    if (apis & _DOWNLOAD_APIS) and (apis & _EXEC_APIS):
        out.append(Indicator(
            "PE downloads AND executes code", "high",
            "imports both network download and process execution APIs",
        ))
    if apis & {"kernel32.dll!LoadLibraryA", "kernel32.dll!LoadLibraryW"} \
            and apis & {"kernel32.dll!GetProcAddress"}:
        out.append(Indicator(
            "Dynamic API resolution", "low",
            "LoadLibrary + GetProcAddress: APIs resolved at runtime (can hide intent)",
        ))
    return out


# ----------------------------------------------------------------- reporting
def render_pe_report(info: PeInfo, indicators: Optional[List[Indicator]] = None) -> str:
    indicators = indicators if indicators is not None else (
        pe_indicators(info) if info.valid else [])
    lines: List[str] = []
    bar = "=" * 66
    lines.append(bar)
    lines.append(" PE debug report")
    lines.append(bar)
    if not info.valid:
        lines.append(f" Not a valid PE image: {info.error}")
        lines.append(bar)
        return "\n".join(lines) + "\n"

    bits = "64-bit (PE32+)" if info.is_64 else "32-bit (PE32)"
    lines.append(f" Machine:        {info.machine_name} ({info.machine:#06x}), {bits}")
    char_names = _flag_names(info.characteristics, _CHAR_FLAGS)
    lines.append(f" Characteristics:{' ' + ', '.join(char_names) if char_names else ' (none)'}")
    dll_names = _flag_names(info.dll_characteristics, _DLL_CHAR_FLAGS)
    lines.append(f" DllCharacteristics:{' ' + ', '.join(dll_names) if dll_names else ' (none)'}")
    lines.append(f" Subsystem:      {SUBSYSTEM_NAMES.get(info.subsystem, hex(info.subsystem))}")
    lines.append(f" ImageBase:      {info.image_base:#x}   Entry point: RVA {info.entry_point_rva:#x}")
    lines.append(f" SizeOfImage:    {info.size_of_image:#x}   Headers: {info.size_of_headers:#x}   Checksum: {info.checksum:#x}")
    if info.is_dotnet:
        lines.append(" .NET:           yes (CLR header present)")
    lines.append("")

    lines.append(" Sections:")
    if not info.sections:
        lines.append("   (none)")
    for s in info.sections:
        ent = f"{s.entropy:5.2f}" if s.entropy is not None else "  n/a"
        flags = ",".join(s.flags)
        lines.append(f"   {s.name:<10} VA {s.vrva:#08x}  VSize {s.vsize:#08x}  "
                     f"Raw {s.rawsize:#08x}@{s.rawptr:#08x}  Ent {ent}  {flags}")
    lines.append("")

    lines.append(f" Imports: {sum(len(v) for v in info.imports.values())} API(s) "
                 f"from {len(info.imports)} DLL(s)")
    for dll in sorted(info.imports):
        lines.append(f"   {dll}:")
        for api in info.imports[dll]:
            lines.append(f"     - {api}")
    lines.append("")
    lines.append(f" Exports: {len(info.exports)}"
                 + (f" ({', '.join(info.exports[:12])})" if info.exports else ""))
    lines.append("")

    lines.append(f" Resources: {len(info.resources)} leaf(s), "
                 f"{info.resource_bytes} bytes inspected")
    for res in info.resources[:32]:
        label = res.type_name or str(res.type_id)
        extra = f"  markers: {', '.join(res.markers)}" if res.markers else ""
        lines.append(f"   [{label}/{res.name_id}] {res.size} bytes{extra}")
    lines.append("")

    lines.append(f" Relocations: {info.reloc_blocks} block(s), {info.reloc_entries} entries")
    lines.append(f" TLS: {'yes' if info.has_tls else 'no'}   "
                 f"Debug dirs: {info.debug_dirs}   "
                 f"Delay imports: {info.delay_imports}   "
                 f".NET: {'yes' if info.is_dotnet else 'no'}")
    if info.data_dirs:
        dd = ", ".join(f"{n}={rva:#x}/{size}" for n, rva, size in info.data_dirs)
        lines.append(f" Data dirs: {dd}")
    lines.append("")

    lines.append(" Debug indicators:")
    if not indicators:
        lines.append("   (none – no suspicious characteristics)")
    for ind in indicators:
        lines.append(f"   [{ind.severity.upper():<8}] {ind.name}")
        lines.append(f"              {ind.message}")
    lines.append(bar)
    return "\n".join(lines) + "\n"
