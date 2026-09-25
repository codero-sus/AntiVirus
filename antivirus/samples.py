"""Builders for the bundled demo samples.

Everything produced here is **inert** – it exists so the detection layers
can be demonstrated safely.  The sample PE images are hand-assembled
structures with *no code at all*: they can be dissected but can never be
loaded or executed by a real loader.
"""
from __future__ import annotations

import random
import struct
from typing import Dict, List, Optional, Tuple

TEXT_RAW = 0x400        # .text file offset (0x400-byte header zone)
TEXT_VRVA = 0x1000      # .text virtual address
R_RSRC_VRVA = 0x2000    # .rsrc virtual address

_MACHINE_32 = 0x014C
_MACHINE_64 = 0x8664


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def _rsrc_section(payload: bytes, base_vrva: int = R_RSRC_VRVA) -> bytes:
    """Build a minimal 3-level resource tree (type 16/RCDATA, id 1, lang 1033).

    Layout (offsets in section bytes):
      0   top dir header      16  top entry  -> name dir @24
      24  name dir header     40  name entry -> lang dir @48
      48  lang dir header     64  lang entry -> data entry @72
      72  IMAGE_RESOURCE_DATA_ENTRY (data RVA is absolute)
      88  payload
    """
    TOP, TOP_E = 0, 16
    NAME, NAME_E = 24, 40
    LANG, LANG_E = 48, 64
    LEAF, DATA = 72, 88
    buf = bytearray(DATA + len(payload))
    struct.pack_into("<IIHHHH", buf, TOP, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", buf, TOP_E, 16, 0x80000000 | NAME)
    struct.pack_into("<IIHHHH", buf, NAME, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", buf, NAME_E, 1, 0x80000000 | LANG)
    struct.pack_into("<IIHHHH", buf, LANG, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", buf, LANG_E, 1033, LEAF)
    struct.pack_into("<IIII", buf, LEAF, base_vrva + DATA, len(payload), 0, 0)
    buf[DATA:] = payload
    return bytes(buf)


def build_sample_pe(
    dlls: Optional[Dict[str, List[str]]] = None,
    *,
    exports: Tuple[str, ...] = (),
    rsrc_payload: Optional[bytes] = None,
    sections: Optional[Dict[str, bytes]] = None,
    characteristics: int = 0x0102,
    dll_characteristics: int = 0x0160,   # HIGH_ENTROPY_VA|DYNAMIC_BASE|NX
    subsystem: int = 7,                  # windows CUI (console)
    machine: int = _MACHINE_32,
    entry_point: Optional[int] = 0x1010,
    reloc_rva: Optional[int] = None,
    debug_dir: bool = False,
    tls_rva: Optional[int] = None,
) -> bytes:
    """Assemble an inert PE32/PE32+ image with a standard layout.

    ``dlls``: {dll: [api, ...]} import table (None = no imports).
    ``sections``: extra raw sections, e.g. ``{"UPX0": random bytes}``.
    """
    pe32plus = machine == _MACHINE_64
    magic = 0x20B if pe32plus else 0x10B
    opt_size = 240 if pe32plus else 224
    dd_off_in_opt = 112 if pe32plus else 96
    thunk_size = 8 if pe32plus else 4
    entry_fmt = "<Q" if pe32plus else "<I"

    # ------------------------------------------------------- .text contents
    text = bytearray()

    def add(data: bytes, align: int = 4) -> int:
        pad = (align - len(text) % align) % align
        if pad:
            text.extend(b"\0" * pad)
        off = len(text)
        text.extend(data)
        return off

    import_dir_off: Optional[int] = None
    if dlls:
        import_dir_off = add(b"\0" * ((len(dlls) + 1) * 20))
        dll_name_offs: Dict[str, int] = {}
        for dll in dlls:
            dll_name_offs[dll] = add(dll.encode("ascii") + b"\0", 2)
        table_offs: Dict[str, int] = {}
        for dll, apis in dlls.items():
            t = bytearray((len(apis) + 1) * thunk_size)  # thunks + zero
            pos = 0
            for api in apis:
                t += struct.pack("<H", 0) + api.encode("ascii") + b"\0"
                pos += 2 + len(api) + 1
            table_offs[dll] = add(bytes(t), 4)
        for i, (dll, apis) in enumerate(dlls.items()):
            toff = table_offs[dll]
            struct.pack_into("<IIIII", text, import_dir_off + i * 20,
                             TEXT_VRVA + toff, 0, 0,
                             TEXT_VRVA + dll_name_offs[dll], TEXT_VRVA + toff)
            pos = (len(apis) + 1) * thunk_size  # names start after thunks
            for k in range(len(apis)):
                struct.pack_into(entry_fmt, text, toff + k * thunk_size,
                                 TEXT_VRVA + toff + pos)
                pos += 2 + len(apis[k]) + 1

    export_dir_off: Optional[int] = None
    if exports:
        n = len(exports)
        export_dir_off = add(b"\0" * 40, 4)
        table_name_off = add(b"antivirus_sample" + b"\0", 2)
        export_name_offs = {nm: add(nm.encode("ascii") + b"\0", 2)
                            for nm in exports}
        names_rvas_off = add(b"\0" * (n * 4), 4)
        name_ords_off = add(b"\0" * (n * 2), 2)
        funcs_rvas_off = add(struct.pack(f"<{n}I",
                                         *(TEXT_VRVA + 0x10 for _ in range(n))), 4)
        struct.pack_into("<II", text, export_dir_off + 12,
                         TEXT_VRVA + table_name_off, 1)
        struct.pack_into("<IIIII", text, export_dir_off + 20, n, n,
                         TEXT_VRVA + funcs_rvas_off, TEXT_VRVA + names_rvas_off,
                         TEXT_VRVA + name_ords_off)
        for i, nm in enumerate(exports):
            struct.pack_into("<I", text, names_rvas_off + i * 4,
                             TEXT_VRVA + export_name_offs[nm])
            struct.pack_into("<H", text, name_ords_off + i * 2, i)

    reloc_dir_off: Optional[int] = None
    reloc_block_size = 0
    if reloc_rva is not None:
        if pe32plus:
            entry = struct.pack("<Q", (3 << 12) | (reloc_rva & 0xFFFF))
            reloc_block_size = 16
            reloc_dir_off = add(struct.pack("<II", reloc_rva & ~0xFFF,
                                            reloc_block_size) + entry, 4)
        else:
            entry = struct.pack("<H", (3 << 12) | (reloc_rva & 0xFFF))
            reloc_block_size = 12
            reloc_dir_off = add(struct.pack("<II", reloc_rva & ~0xFFF,
                                            reloc_block_size) + entry, 4)

    debug_dir_off: Optional[int] = None
    if debug_dir:
        # one zeroed CODEVIEW IMAGE_DEBUG_DIRECTORY (28 bytes)
        debug_dir_off = add(struct.pack("<IIIIIIII", 0xFFFFFFFF, 0, 0, 0,
                                        2, 4, 0, 0), 4)

    tls_dir_off: Optional[int] = None
    tls_size = 0
    if tls_rva is not None:
        if pe32plus:
            tls_size = 32 + 16
            tls_dir_off = add(struct.pack("<QQQII", 0, 0, tls_rva, 0, 0)
                              + struct.pack("<Q", tls_rva)
                              + struct.pack("<Q", 0), 8)
        else:
            tls_size = 20 + 8
            tls_dir_off = add(struct.pack("<IIIII", 0, 0, tls_rva, 0, 0)
                              + struct.pack("<I", tls_rva)
                              + struct.pack("<I", 0), 4)

    # -------------------------------------------------------- file assembly
    rsrc_blob: Optional[bytes] = None
    if rsrc_payload is not None:
        rsrc_blob = _rsrc_section(rsrc_payload)

    file = bytearray(TEXT_RAW)
    text_raw = bytes(text).ljust(max(_align(len(text), 0x200), 0x200), b"\0")
    file += text_raw

    extra: List[Tuple[bytes, bytes]] = []
    if rsrc_blob is not None:
        extra.append((b".rsrc", rsrc_blob))
    for name, blob in (sections or {}).items():
        extra.append((name.encode("latin1"), blob))

    extra_raws: List[Tuple[bytes, bytes, bytes]] = []
    for name, blob in extra:
        padded = blob.ljust(_align(len(blob), 0x200), b"\0")
        extra_raws.append((name, blob, padded))
        file += padded

    n_sections = 1 + len(extra)
    size_of_image = 0x1000 * n_sections

    # DOS + PE headers.
    file[0:2] = b"MZ"
    struct.pack_into("<I", file, 0x3C, 0x80)
    file[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", file, 0x84, machine, n_sections,
                     0x60000000, 0, 0, opt_size, characteristics)
    opt = 0x98
    struct.pack_into("<H", file, opt, magic)
    struct.pack_into("<I", file, opt + 16,
                     0 if entry_point is None else entry_point)
    if pe32plus:
        struct.pack_into("<Q", file, opt + 24, 0x140000000)
    else:
        struct.pack_into("<I", file, opt + 28, 0x400000)
    struct.pack_into("<II", file, opt + 32, 0x1000, 0x200)
    struct.pack_into("<HH", file, opt + 40, 6, 0)
    struct.pack_into("<IIII", file, opt + 56, size_of_image, TEXT_RAW, 0, 0)
    struct.pack_into("<HH", file, opt + 68, subsystem, dll_characteristics)

    # Data directories.
    dd = opt + dd_off_in_opt
    dirs: Dict[int, Tuple[int, int]] = {}
    if import_dir_off is not None:
        dirs[1] = (TEXT_VRVA + import_dir_off, (len(dlls) + 1) * 20)
    if export_dir_off is not None:
        dirs[0] = (TEXT_VRVA + export_dir_off, 40)
    if rsrc_blob is not None:
        dirs[2] = (R_RSRC_VRVA, len(rsrc_blob))
    if reloc_dir_off is not None:
        dirs[5] = (TEXT_VRVA + reloc_dir_off, reloc_block_size)
    if debug_dir_off is not None:
        dirs[6] = (TEXT_VRVA + debug_dir_off, 28)
    if tls_dir_off is not None:
        dirs[9] = (TEXT_VRVA + tls_dir_off, tls_size)
    for idx, (rva, size) in dirs.items():
        struct.pack_into("<II", file, dd + idx * 8, rva, size)

    # Section table.
    sect_off = opt + opt_size
    secdefs = [(b".text", len(text), TEXT_VRVA, len(text_raw), TEXT_RAW,
                0x60000020)]  # CODE|EXECUTE|READ
    va, foff = 0x2000, TEXT_RAW + len(text_raw)
    for name, blob, padded in extra_raws:
        secdefs.append((name, len(blob), va, len(padded), foff,
                        0x40000040))  # READ|INITIALIZED_DATA
        va += 0x1000
        foff += len(padded)
    for i, (name, vsize, vrva, rawsize, rawptr, chars) in enumerate(secdefs):
        s = sect_off + i * 40
        file[s:s + 8] = name[:8].ljust(8, b"\0")
        struct.pack_into("<II", file, s + 8, vsize, vrva)
        struct.pack_into("<II", file, s + 16, rawsize, rawptr)
        struct.pack_into("<HHI", file, s + 32, 0, 0, chars)

    return bytes(file)


# --------------------------------------------------------------- sample set
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

#: A harmless import set (proves no false positives on well-formed PEs).
BENIGN_PE_DLLS: Dict[str, List[str]] = {
    "kernel32.dll": ["ExitProcess", "GetStdHandle", "WriteFile"],
}

#: Payload hidden in the suspicious sample's resources (inert script text).
_SUSPICIOUS_RSRC = (
    b"Set wsh = CreateObject(\"WScript.Shell\")\r\n"
    b"wsh.Run \"cmd.exe /c powershell -enc SQBFAFc9c2gA\r\n"
    b"Set wsh = Nothing\r\n"
)


def build_suspicious_pe() -> bytes:
    """Loader-style sample: dangerous imports, ASLR/DEP off, no EP, no
    relocations, no debug info, VBScript hidden in the resources."""
    return build_sample_pe(
        SUSPICIOUS_PE_DLLS,
        exports=("run_payload",),
        rsrc_payload=_SUSPICIOUS_RSRC,
        characteristics=0x0102,
        dll_characteristics=0x0000,
        entry_point=0,
        reloc_rva=None,
        debug_dir=False,
    )


def build_packed_pe() -> bytes:
    """Packer-style sample: RELOCS_STRIPPED, UPX0 section full of entropy,
    no import table, no relocations, no debug info."""
    return build_sample_pe(
        None,
        characteristics=0x0003,  # RELOCS_STRIPPED | EXECUTABLE_IMAGE
        dll_characteristics=0x0000,
        sections={"UPX0": random.Random(1337).randbytes(16 * 1024)},
    )


def build_clean_pe() -> bytes:
    """Well-formed sample: benign imports, ASLR + DEP on, entry point,
    relocations and debug info present – must produce zero findings."""
    return build_sample_pe(
        BENIGN_PE_DLLS,
        characteristics=0x0102,
        dll_characteristics=0x0160,
        entry_point=0x1010,
        reloc_rva=0x1010,
        debug_dir=True,
    )


#: The standard, harmless EICAR antivirus test string (not malware).
EICAR_TEST_STRING = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


def build_zip_sample() -> bytes:
    """``sneaky.zip`` – an inert archive demonstrating the archive layer:

    * ``eicar-test.txt`` – the harmless EICAR test string (signature hit
      inside the archive, reported as ``sneaky.zip!eicar-test.txt``);
    * ``notes.txt`` – benign text;
    * ``../outside.txt`` – a zip-slip entry name (path traversal flag).
    """
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("eicar-test.txt", EICAR_TEST_STRING)
        zf.writestr("notes.txt", "Just some harmless notes.\n")
        zf.writestr("../outside.txt", "I should never be written outside.\n")
    return buf.getvalue()
