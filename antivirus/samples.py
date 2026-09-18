"""Builders for the bundled demo samples.

Everything produced here is **inert** – it exists so the detection layers
can be demonstrated safely.  The sample PE in particular is a minimal,
hand-assembled PE32 image whose *import table* advertises dangerous APIs;
it has no code, is not loadable by a real loader and can never execute.
"""
from __future__ import annotations

import struct
from typing import Dict, List, Tuple


def build_sample_pe(dlls: Dict[str, List[str]],
                    section_name: bytes = b".text") -> bytes:
    """Assemble a minimal PE32 file importing *dlls* (dll -> [API, ...]).

    Layout (all offsets fixed, one .text section holding the import dir):
      0x000 DOS header (e_lfanew = 0x80)
      0x080 PE signature + COFF header
      0x098 optional header (PE32, 224 bytes, import dir = entry 2)
      0x178 section header (.text)
      0x200 import directory, then DLL name strings, then import name tables
    """
    import_dir_off = 0x200
    n_entries = len(dlls) + 1  # + terminating zero entry
    name_str_off = import_dir_off + n_entries * 20

    dll_name_offs: Dict[str, int] = {}
    off = name_str_off
    for dll in dlls:
        dll_name_offs[dll] = off
        off += len(dll) + 1

    # Table layout (as in real PEs): a contiguous array of 4-byte thunks
    # terminated by a zero, followed by the hint+name entries.
    tables: Dict[str, Tuple[int, bytearray, List[Tuple[int, int]]]] = {}
    for dll, apis in dlls.items():
        entry_sizes = [2 + len(api) + 1 for api in apis]
        thunk_area = (len(apis) + 1) * 4
        data = bytearray(thunk_area)  # thunks + terminating zero
        thunks: List[Tuple[int, int]] = []
        pos = thunk_area
        for k, api in enumerate(apis):
            thunks.append((k * 4, pos))
            data += struct.pack("<H", 0) + api.encode("ascii") + b"\0"
            pos += entry_sizes[k]
        tables[dll] = (off, data, thunks)
        off += len(data)

    total = max(off, import_dir_off + 0x200)
    buf = bytearray(total)

    # DOS header.
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)

    # PE signature + COFF header.
    buf[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", buf, 0x84,
                     0x014C,          # Machine: i386
                     1,               # NumberOfSections
                     0x60000000,      # TimeDateStamp
                     0,               # PointerToSymbolTable
                     0,               # NumberOfSymbols
                     224,             # SizeOfOptionalHeader
                     0x0102)          # EXECUTABLE_IMAGE | 32BIT_MACHINE

    # Optional header (PE32).
    opt = 0x98
    struct.pack_into("<H", buf, opt, 0x10B)  # PE32 magic
    # Data directory #2 (imports): RVA + size.
    struct.pack_into("<II", buf, opt + 96 + 8, 0x1000, n_entries * 20)

    # Section header (.text).
    sec = 0x178
    buf[sec:sec + 8] = section_name[:8].ljust(8, b"\0")
    struct.pack_into("<II", buf, sec + 8, total - import_dir_off, 0x1000)
    struct.pack_into("<II", buf, sec + 16, total - import_dir_off, import_dir_off)

    # Import directory entries:
    # (OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk)
    for i, (dll, (toff, _data, _thunks)) in enumerate(tables.items()):
        struct.pack_into("<IIIII", buf, import_dir_off + i * 20,
                         toff + 0xE00, 0, 0, dll_name_offs[dll] + 0xE00,
                         toff + 0xE00)
    # Entry n_entries is already zero (terminator).

    # DLL name strings.
    for dll, off in dll_name_offs.items():
        buf[off:off + len(dll) + 1] = dll.encode("ascii") + b"\0"

    # Import name tables (thunks point at hint+name entries).
    for dll, (toff, data, thunks) in tables.items():
        buf[toff:toff + len(data)] = data
        for thunk_pos, name_pos in thunks:
            struct.pack_into("<I", buf, toff + thunk_pos,
                             toff + name_pos + 0xE00)

    return bytes(buf)


#: Import sets used by the bundled ``samples/behavior/suspicious.exe``.
SUSPICIOUS_PE_DLLS: Dict[str, List[str]] = {
    "wininet.dll": ["URLDownloadToFileA"],
    "kernel32.dll": [
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "ShellExecuteA",
    ],
    "advapi32.dll": ["RegSetValueExA"],
    "crypt32.dll": ["CryptDecrypt"],
}

#: A harmless import set (used in tests to prove no false positives).
BENIGN_PE_DLLS: Dict[str, List[str]] = {
    "kernel32.dll": ["ExitProcess", "GetStdHandle"],
}
