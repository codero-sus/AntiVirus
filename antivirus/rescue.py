"""Rescue disk: a self-contained kit + ISO image for scanning from a live system.

Like the rescue disks of full antivirus products (Kaspersky, Avast, Dr.Web),
the idea is to scan a system *from outside the infected OS*:

1. ``antivirus rescue build`` writes a **rescue kit** — a directory that
   carries its own copy of this package, the current signature database,
   a bootstrap script and a hash manifest — plus a **rescue.iso**
   (ISO 9660, written here in pure Python) that holds the same kit.
2. Copy the kit (or the ISO) to a USB stick, boot any live system (a
   live Linux USB, a rescue VM, …), mount the infected volume and run
   ``bootstrap.sh /mnt/infected-volume``.
3. Threats are quarantined **to the rescue media** (the live side),
   never back into the scanned tree, so the infected system is not
   relied on to hold the evidence. The scan cache is always disabled
   for rescue runs — a cache on foreign media is untrusted.

The ISO is a standard, mountable ISO 9660 image (``mount -o loop
rescue.iso /mnt`` on Linux, auto-mount on macOS). It is *not* a bootable
OS — a pure-Python project cannot ship one — so the workflow is
"live system + this kit", which is how the images of several rescue
distributions are meant to be used from a rescue shell anyway.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import Dict, List, Optional

from .config import Config
from .quarantine import Quarantine
from .report import ReportWriter
from .scanner import Scanner
from .signatures import SignatureDB

#: Files the kit always contains (besides the ``antivirus/`` package dir).
KIT_FILES = ("run-rescue.py", "bootstrap.sh", "bootstrap.bat",
             "signatures.json", "threat_intel.json", "antivirus.zip",
             "rescue-manifest.json", "README-RESCUE.txt")

RUN_RESCUE_SCRIPT = '''#!/usr/bin/env python3
"""AntiVirus rescue runner — scan a mounted system volume from a live system.

Usage (run from anywhere; the kit is located next to this script):

    python3 run-rescue.py /mnt/infected-disk [--action detect|quarantine|delete]
                          [--fast] [--since 2h] [--exclude GLOB] [--json]
    python3 run-rescue.py --selftest      # verify the rescue media itself
    python3 run-rescue.py --verify        # check the kit against its manifest
"""
import argparse
import json
import sys
from pathlib import Path

KIT_DIR = Path(__file__).resolve().parent
if (KIT_DIR / "antivirus").is_dir():
    sys.path.insert(0, str(KIT_DIR))          # kit directory
else:
    sys.path.insert(0, str(KIT_DIR / "antivirus.zip"))  # mounted ISO


def main() -> int:
    from antivirus import __version__
    from antivirus.rescue import verify_kit

    argv = sys.argv[1:]
    if "--selftest" in argv:
        from antivirus.selftest import run_selftest
        sig = KIT_DIR / "signatures.json"
        return run_selftest(signatures_file=str(sig) if sig.is_file() else None)
    if "--verify" in argv:
        problems = verify_kit(KIT_DIR)
        if problems:
            for p in problems:
                print(f"FAIL: {p}")
            print(f"Rescue kit verification FAILED ({len(problems)} problem(s)).")
            return 1
        print("Rescue kit OK — every file matches the manifest.")
        return 0

    from antivirus.rescue import run_rescue

    parser = argparse.ArgumentParser(
        prog="antivirus-rescue",
        description="Rescue scan of a mounted volume (AntiVirus "
                    + __version__ + ", self-contained kit)")
    parser.add_argument("target", nargs="?",
                        help="mounted system volume to scan (e.g. /mnt/sda1)")
    parser.add_argument("--action",
                        choices=("detect", "quarantine", "kill", "delete"),
                        default="detect",
                        help="kill = obfuscate in place (key/IV on the "
                             "rescue media)")
    parser.add_argument("--fast", action="store_true",
                        help="hash + pattern layers only")
    parser.add_argument("--since", default="",
                        help="only files modified within DURATION (30m/2h/1d)")
    parser.add_argument("--exclude", action="append", default=[],
                        help="skip matching files (repeatable)")
    parser.add_argument("--quarantine-dir",
                        default=str(KIT_DIR / "rescue-quarantine"),
                        help="where threats are quarantined (default: the "
                             "rescue media itself)")
    parser.add_argument("--report-dir",
                        default=str(KIT_DIR / "rescue-reports"),
                        help="where the rescue report is written")
    parser.add_argument("--rescue-registry",
                        default=str(KIT_DIR / "rescue-registry"),
                        help="kill registry (key/IV store) — stays on the "
                             "rescue media")
    parser.add_argument("--signatures", default=None,
                        help="signature database (default: the kit's copy)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if not args.target:
        parser.error("a target (mounted volume) is required, or use --selftest")

    sig = args.signatures or (str(KIT_DIR / "signatures.json")
                              if (KIT_DIR / "signatures.json").exists() else None)
    info = run_rescue(
        args.target, action=args.action, fast=args.fast, since=args.since,
        exclude=tuple(args.exclude), signatures_file=sig,
        quarantine_dir=args.quarantine_dir, report_dir=args.report_dir,
        registry_dir=args.rescue_registry)
    result = info["result"]
    if args.json:
        data = result.to_dict()
        data["action"] = args.action
        data["actions_taken"] = info["notes"]
        data["rescue"] = {
            "quarantine_dir": info["quarantine_dir"],
            "registry_dir": info["registry_dir"],
            "report": str(info["report"]) if info["report"] else None,
            "signatures": info["signatures_file"],
        }
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        from antivirus.output import BOLD, GREEN, RED, paint
        worst = result.worst_severity
        state = paint("INFECTED" if result.findings else "CLEAN",
                      RED if result.findings else GREEN)
        print(paint("=" * 62, BOLD))
        print(paint(" AntiVirus rescue scan", BOLD) + f"  |  {result.target}")
        print(paint("=" * 62, BOLD))
        print(f" Files scanned: {result.files_scanned}   "
              f"findings: {len(result.findings)}")
        for f in result.findings:
            note = info["notes"].get(f.path, "")
            print(f"  [{f.severity.upper()}] {f.name}  {f.path}"
                  + (f"  -> {note}" if note else ""))
        print(f" Quarantine (rescue media): {info['quarantine_dir']}")
        if info.get("registry_dir"):
            print(f" Kill registry (rescue media): {info['registry_dir']}")
        if info["report"]:
            print(f" Report: {info['report']}")
        print(f" Result: {state}")
        print(paint("=" * 62, BOLD))
    return 0 if result.clean else 1


if __name__ == "__main__":
    sys.exit(main())
'''

BOOTSTRAP_SCRIPT = """#!/bin/sh
# AntiVirus rescue bootstrap — run from the rescue kit (USB stick or a
# mounted ISO).
#
#   ./bootstrap.sh /mnt/infected-volume [--action quarantine] [options]
#   ./bootstrap.sh --selftest        # verify the rescue media itself
#
# The kit is self-contained; the only requirement is python3 (3.9+) on
# the live system.
set -e
KIT="$(cd "$(dirname "$0")" && pwd)"
PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
    echo "error: python3 (3.9+) not found on the live system" >&2
    exit 2
fi
exec "$PY" "$KIT/run-rescue.py" "$@"
"""

BOOTSTRAP_BATCH = """@echo off
rem AntiVirus rescue bootstrap (Windows) - run from the rescue kit.
rem
rem   bootstrap.bat D:\\ [options]     scan the infected volume, e.g. D:\\
rem   bootstrap.bat --selftest        verify the rescue media itself
rem
rem The kit is self-contained; the only requirement is Python 3.9+
rem on the live system (the py launcher or python on the PATH).
setlocal
set "KIT=%~dp0"
set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY (
    echo error: Python 3.9+ not found on the live system 1>&2
    exit /b 2
)
%PY% "%KIT%run-rescue.py" %*
"""

KIT_README = """ANTI-VIRUS RESCUE KIT
=====================
A self-contained rescue kit for scanning a system from a live
environment (the pure-Python companion to classic rescue disks).

CONTENTS
  antivirus/            a full copy of the AntiVirus package
  antivirus.zip         the same package as a zip (used from the ISO)
  signatures.json       the signature database at build time
  run-rescue.py         the rescue scanner (Python 3.9+ is the only
                        dependency)
  bootstrap.sh          convenience wrapper (Linux / macOS / BSD)
  bootstrap.bat         convenience wrapper (Windows)
  rescue-manifest.json  SHA-256 of every kit file (integrity check)

HOW TO USE (any OS, including Windows)
  1. Get the kit onto the live side: copy the directory (or rescue.iso)
     to a USB stick. For the ISO: mount -o loop rescue.iso /mnt/iso
     (Windows/macOS mount it like any disc - drive letters work too,
     e.g. E:\\).
  2. Boot a live system (a Linux live USB, a rescue VM, or a second
     Windows environment) and make the infected volume visible
     (Linux:  sudo mount /dev/sda1 /mnt/disk).
  3. Verify the media:
       Linux/macOS:  ./bootstrap.sh --selftest
       Windows:      bootstrap.bat --selftest
     Verify the manifest:  python run-rescue.py --verify
  4. Rescue scan:
       Linux/macOS:  ./bootstrap.sh /mnt/disk --action quarantine
       Windows:      bootstrap.bat D:\\ --action quarantine
     Threats are moved to the rescue media (this kit), the report is
     written here, and the scanned volume is left untouched except for
     the removed threats.

NOT A BOOTABLE OS
  The ISO is a mountable ISO 9660 image, not a bootable system: a
  pure-Python project cannot ship an operating system. The workflow is
  "any live OS + this kit", which covers the rescue use case (scan and
  quarantine from outside the infected OS).
"""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _default_signature_db() -> Dict:
    """A minimal database (the standard EICAR entry) used when no
    signature file can be found — a rescue disk without any signatures
    would be useless."""
    from .signatures import Signature
    from .utils import md5_new

    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    h = md5_new()
    h.update(eicar)
    sig = Signature(
        id="EICAR-STD-2014",
        name="EICAR-Test-File",
        category="test",
        severity="critical",
        description="Standard antivirus industry test string (harmless).",
        sha256=hashlib.sha256(eicar).hexdigest(),
        md5=h.hexdigest(),
        pattern=__import__("re").escape(eicar.decode("ascii")),
    )
    return {
        "version": 1,
        "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "signatures": [vars(sig)],
    }


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------- kit
def _package_zip_bytes() -> bytes:
    """The antivirus package as an in-memory zip (for the ISO + zipimport)."""
    pkg = Path(__file__).resolve().parent
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for py in sorted(pkg.glob("*.py")):
            zf.write(py, f"antivirus/{py.name}")
    return buf.getvalue()


def build_rescue_kit(out_dir: Path,
                     signatures_file: Optional[Path] = None) -> Dict:
    """Build a self-contained rescue kit directory; returns its manifest.

    *signatures_file* is the database to snapshot (default: the bundled
    one, or ``./data/signatures.json`` when it exists).
    """
    from . import __version__

    kit = Path(out_dir)
    if kit.exists():
        shutil.rmtree(kit)
    kit.mkdir(parents=True)
    pkg_dst = kit / "antivirus"
    pkg_dst.mkdir()
    pkg_src = Path(__file__).resolve().parent
    for py in sorted(pkg_src.glob("*.py")):
        shutil.copyfile(py, pkg_dst / py.name)

    sig_candidates = [Path(signatures_file)] if signatures_file else []
    sig_candidates += [Path.cwd() / "data" / "signatures.json",
                       pkg_src.parent / "data" / "signatures.json"]
    sig_src = next((p for p in sig_candidates if p.is_file()), None)
    sig_dst = kit / "signatures.json"
    if sig_src is None:
        sig_dst.write_text(json.dumps(_default_signature_db(), indent=2,
                                      ensure_ascii=False) + "\n",
                           encoding="utf-8")
    else:
        shutil.copyfile(sig_src, sig_dst)
    sig_count = len(SignatureDB(sig_dst).list())

    # Threat-intel snapshot (web shield + firewall), same fallback chain.
    intel_candidates = [Path.cwd() / "data" / "threat_intel.json",
                        pkg_src.parent / "data" / "threat_intel.json"]
    intel_src = next((p for p in intel_candidates if p.is_file()), None)
    intel_dst = kit / "threat_intel.json"
    if intel_src is not None:
        shutil.copyfile(intel_src, intel_dst)
    else:  # pragma: no cover - the bundled file always exists
        intel_dst.write_text(
            json.dumps({"version": 1, "domains": [], "ips": [],
                        "ports": {}, "listen_ports": {},
                        "shorteners": []}, indent=2) + "\n",
            encoding="utf-8")

    zip_bytes = _package_zip_bytes()
    (kit / "antivirus.zip").write_bytes(zip_bytes)
    (kit / "run-rescue.py").write_text(RUN_RESCUE_SCRIPT, encoding="utf-8")
    (kit / "bootstrap.sh").write_text(BOOTSTRAP_SCRIPT, encoding="utf-8")
    (kit / "bootstrap.sh").chmod(0o755)  # no-op on Windows, harmless
    (kit / "bootstrap.bat").write_text(BOOTSTRAP_BATCH, encoding="utf-8")
    (kit / "README-RESCUE.txt").write_text(KIT_README, encoding="utf-8")

    manifest = {
        "version": 1,
        "antivirus": __version__,
        "built": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "signatures": {"file": "signatures.json",
                       "sha256": _sha256_file(sig_dst),
                       "count": sig_count},
        "files": {},
    }
    for name in KIT_FILES:
        if name == "rescue-manifest.json":
            continue  # the manifest cannot hash itself
        manifest["files"][name] = _sha256_file(kit / name)
    for py in sorted(p.name for p in pkg_dst.glob("*.py")):
        manifest["files"][f"antivirus/{py}"] = _sha256_file(pkg_dst / py)
    (kit / "rescue-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    manifest["kit"] = str(kit)
    return manifest


def build_rescue_disk(out_dir: Path, iso_path: Optional[Path] = None,
                      signatures_file: Optional[Path] = None) -> Dict:
    """Build the kit directory *and* the ISO image; returns kit + iso info."""
    kit = Path(out_dir)
    manifest = build_rescue_kit(kit, signatures_file)
    iso = Path(iso_path) if iso_path else kit.parent / "rescue.iso"
    files = {}
    for name in KIT_FILES:
        files[name] = (kit / name).read_bytes()
    size = build_iso9660(iso, files)
    manifest["iso"] = str(iso)
    manifest["iso_size"] = size
    return manifest


def verify_kit(kit_dir: Path) -> List[str]:
    """Check a kit against its manifest; returns a list of problems."""
    kit = Path(kit_dir)
    manifest_file = kit / "rescue-manifest.json"
    problems: List[str] = []
    if not kit.is_dir():
        return [f"no such kit directory: {kit}"]
    if not manifest_file.exists():
        return [f"missing {manifest_file.name} (not a rescue kit?)"]
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"manifest is not valid JSON: {exc}"]

    zip_mode = not (kit / "antivirus").is_dir() and \
        (kit / "antivirus.zip").is_file()
    for name, expected in sorted(manifest.get("files", {}).items()):
        if name.startswith("antivirus/") and zip_mode:
            continue  # validated from antivirus.zip below
        p = kit / name
        if not p.is_file():
            problems.append(f"missing file: {name}")
            continue
        actual = _sha256_file(p)
        if actual != expected:
            problems.append(f"hash mismatch: {name} "
                            f"({actual[:12]}… != {expected[:12]}…)")
    if (kit / "antivirus").is_dir():
        if not (kit / "antivirus" / "__init__.py").exists():
            problems.append("antivirus/__init__.py missing")
    elif zip_mode:
        # ISO variant: the package ships as a zip (zipimportable).
        try:
            with zipfile.ZipFile(kit / "antivirus.zip") as zf:
                for name, expected in sorted(
                        manifest.get("files", {}).items()):
                    if not name.startswith("antivirus/"):
                        continue
                    try:
                        data = zf.read(name)
                    except KeyError:
                        problems.append(f"missing in zip: {name}")
                        continue
                    if _sha256_bytes(data) != expected:
                        problems.append(f"hash mismatch in zip: {name}")
        except (OSError, zipfile.BadZipFile) as exc:
            problems.append(f"antivirus.zip unreadable: {exc}")
    else:
        problems.append("neither an antivirus/ directory nor "
                        "antivirus.zip found")
    return problems


def run_rescue_selftest(kit_dir: Path) -> "tuple[int, str]":
    """Run the kit's own self test in a fresh interpreter (media check).

    Sets ``AV_RESCUE_NESTED_SELFTEST`` so the child's own rescue media
    check is skipped — otherwise every self test would spawn another one
    forever.
    """
    import os

    runner = Path(kit_dir) / "run-rescue.py"
    if not runner.exists():
        return 2, f"no such runner: {runner}"
    env = dict(os.environ, AV_RESCUE_NESTED_SELFTEST="1")
    proc = subprocess.run([sys.executable, str(runner), "--selftest"],
                          capture_output=True, text=True, timeout=300,
                          env=env)
    tail = (proc.stdout or "")[-2000:]
    return proc.returncode, tail


# ------------------------------------------------------------------ rescue
def run_rescue(target, action: str = "detect", fast: bool = False,
               since: str = "", exclude: tuple = (),
               signatures_file: Optional[str] = None,
               quarantine_dir: Optional[str] = None,
               report_dir: Optional[str] = None,
               registry_dir: Optional[str] = None,
               threads: "str | int" = "auto") -> Dict:
    """Scan a *foreign* tree (a mounted volume) as a rescue operation.

    Unlike a regular scan, the defaults live **outside the target**:
    quarantine, the kill registry and reports go to ``rescue-quarantine`` /
    ``rescue-registry`` / ``rescue-reports`` under the CWD (the live
    media), and the scan cache is always disabled — a cache sitting on the
    scanned system is untrusted.
    """
    if action not in ("detect", "quarantine", "kill", "delete"):
        raise ValueError(f"invalid action: {action}")
    from .api import apply_actions
    from .utils import parse_since

    config = Config()
    config.cache_enabled = False
    if since:
        config.since_ts = time.time() - parse_since(since)
    if fast:
        config.fast_mode = True
    if exclude:
        config.exclude_patterns = tuple(exclude)
    if signatures_file:
        config.signatures_file = Path(signatures_file)
    config.quarantine_dir = (Path(quarantine_dir) if quarantine_dir
                             else Path.cwd() / "rescue-quarantine")
    config.report_dir = (Path(report_dir) if report_dir
                         else Path.cwd() / "rescue-reports")
    config.registry_dir = (Path(registry_dir) if registry_dir
                           else Path.cwd() / "rescue-registry")
    config.resolve_paths(Path.cwd())

    if not config.signatures_file.exists():
        bundled = Path(__file__).resolve().parent.parent / "data" / \
            "signatures.json"
        if bundled.exists():
            config.signatures_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(bundled, config.signatures_file)

    from .api import neutralized_map
    from .kill import KillRegistry

    db = SignatureDB(config.signatures_file)
    scanner = Scanner(config, db, threads=threads)
    quarantine = Quarantine(config.quarantine_dir)
    kill_registry = KillRegistry(config.registry_dir)
    scanner.neutralized = neutralized_map(kill_registry)
    target_path = Path(target)
    if not target_path.exists():
        raise FileNotFoundError(f"no such file or directory: {target}")
    result = scanner.scan_path(target_path)
    notes = apply_actions(result, quarantine, action,
                          kill_registry=kill_registry)
    report_path = ReportWriter(config.report_dir).save(result, action, notes)
    return {
        "result": result,
        "notes": notes,
        "report": report_path,
        "quarantine_dir": str(config.quarantine_dir),
        "registry_dir": str(config.registry_dir),
        "signatures_file": str(config.signatures_file),
    }


# ------------------------------------------------------------- ISO 9660
_SECTOR = 2048


def _bcd_date() -> bytes:
    """ISO 9660's 7-byte BCD date/time (UTC, years 1900-2099).

    The year is stored as the BCD of its last two digits: 2026 -> 0x26.
    """
    ts = time.gmtime()
    y = (ts.tm_year - 1900) % 100
    return bytes([((y // 10) << 4) | (y % 10), ts.tm_mon, ts.tm_mday,
                  ts.tm_hour, ts.tm_min, ts.tm_sec, 0])


def _padded(name: str, field_len: int) -> bytes:
    """Space-padded fixed-length identifier field (ISO 9660 descriptors)."""
    b = name.encode("ascii")[:field_len]
    return b + b" " * (field_len - len(b))


def _directory_record(extent: int, size: int, flags: int, name: str,
                      file_number: int, pad_to: int = 0) -> bytes:
    rec = bytearray()
    rec.append(0)                       # record length (patched below)
    rec.append(0)                       # extended attribute length
    rec += extent.to_bytes(4, "little") + extent.to_bytes(4, "big")
    rec += size.to_bytes(4, "little") + size.to_bytes(4, "big")
    rec += _bcd_date()
    rec.append(flags)
    rec += bytes([0, 0])                # file unit size, interleave
    rec += file_number.to_bytes(2, "little") + \
        file_number.to_bytes(2, "big")
    rec.append(len(name))
    rec += name.encode("ascii")
    if len(rec) % 2:
        rec.append(0)
    rec[0] = len(rec)
    if pad_to:
        rec += b"\x00" * (pad_to - len(rec))
    return bytes(rec)


def _path_entry(parent: int, extent: int, size: int, flags: int,
                name: str, file_number: int) -> bytes:
    e = bytearray()
    e.append(0)                         # entry length (patched below)
    e.append(parent)
    e += extent.to_bytes(2, "little") + extent.to_bytes(2, "big")
    e += bytes([0, 0])                  # file attribute size (l + b)
    e += _bcd_date()
    e.append(flags)
    e += bytes([0, 0])                  # file unit size, interleave
    e += file_number.to_bytes(2, "little") + file_number.to_bytes(2, "big")
    e.append(len(name))
    e += name.encode("ascii")
    if len(e) % 2:
        e.append(0)
    e[0] = len(e)
    return bytes(e)


def build_iso9660(out_path: Path, files: Dict[str, bytes],
                  volume_id: str = "ANTIVIRUS-RESCUE") -> int:
    """Write a minimal, standard ISO 9660 (level 1/2) image.

    Pure Python, 2048-byte sectors: system area, PVD, SVD, root
    directory, primary + secondary path tables, then the file data.
    No Rock Ridge / Joliet / El Torito — plain ISO 9660 that Linux
    (``mount -o loop``), macOS and Windows mount out of the box.
    Returns the image size in bytes.
    """
    out_path = Path(out_path)
    vol = volume_id.upper().encode("ascii")[:32]

    entries: List[tuple] = []          # (iso_name, bytes)
    for name, data in files.items():
        iso_name = name.upper()
        if not iso_name.replace(".", "").replace("-", "").replace("_",
                                                                "").isalnum():
            raise ValueError(f"not a valid ISO 9660 name: {name!r}")
        if len(iso_name) > 32:
            raise ValueError(f"ISO 9660 name too long: {name!r}")
        entries.append((iso_name, bytes(data)))
    if not entries:
        raise ValueError("refusing to build an empty ISO")
    if len(entries) > 60:
        raise ValueError("too many root-level files for the minimal "
                         "ISO writer (max 60)")

    # ---- layout ----------------------------------------------------------
    # 0: system area   1: PVD   2: SVD   3: root directory
    # 4: primary path table   5: secondary path table   6..: file data
    data_sectors: List[tuple] = []     # (name, extent, size, data)
    extent = 6
    for name, data in entries:
        data_sectors.append((name, extent, len(data), data))
        extent += max(1, (len(data) + _SECTOR - 1) // _SECTOR)
    total_sectors = extent

    # ---- PVD -------------------------------------------------------------
    pvd = bytearray(_SECTOR)
    pvd[0:5] = b"CD001"
    pvd[5] = 1                                  # descriptor version
    pvd[6] = 1                                  # type: PVD
    pvd[7:39] = _padded("ANTIVIRUS-RESCUE", 32)  # system identifier
    pvd[39:71] = _padded(vol.decode(), 32)       # volume identifier
    space = total_sectors.to_bytes(4, "little") + total_sectors.to_bytes(4, "big")
    pvd[71:79] = space                          # volume space size
    pvd[80:112] = _padded("ANTIVIRUS-RESCUE-SET", 32)
    pvd[176:208] = _padded("ANTIVIRUS", 32)      # application identifier
    # 17-byte timestamps here (7-byte BCD date + 10 reserved bytes)
    pvd[304:321] = _bcd_date() + b"\x00" * 10
    pvd[321:338] = _bcd_date() + b"\x00" * 10
    pvd[338] = 1                                # volume version
    pvd[339] = 1                                # file structure version
    pvd[340] = 0                                # escape sequence count
    seq = (1).to_bytes(2, "little") + (1).to_bytes(2, "big")
    pvd[373:377] = seq
    pvd[377] = 1                                # volume attributes
    pvd[379:383] = (4).to_bytes(4, "little")    # primary path table
    pvd[383:417] = _directory_record(3, _SECTOR, 0x02, "", 2, pad_to=34)
    pvd[417:421] = (5).to_bytes(4, "big")       # secondary path table

    # ---- SVD -------------------------------------------------------------
    svd = bytearray(_SECTOR)
    svd[0:5] = b"CD001"
    svd[5] = 1
    svd[6] = 255                                # type: termination

    # ---- root directory (sector 3) ---------------------------------------
    root = bytearray()
    root += _directory_record(3, _SECTOR, 0x02, ".", 2)
    root += _directory_record(3, _SECTOR, 0x02, "..", 2)
    for i, (name, ext, size, _data) in enumerate(data_sectors, start=3):
        root += _directory_record(ext, size, 0x00, name, i)
    root += b"\x00" * (_SECTOR - len(root))

    # ---- path tables (both tables are byte-identical) ---------------------
    table = b""
    table += _path_entry(2, 3, _SECTOR, 0x02, "", 2)
    for i, (name, ext, size, _data) in enumerate(data_sectors, start=3):
        table += _path_entry(2, ext, size, 0x00, name, i)
    table += b"\x00" * (_SECTOR - len(table))

    image = io.BytesIO()
    image.write(b"\x00" * _SECTOR)            # sector 0: system area
    image.write(bytes(pvd))
    image.write(bytes(svd))
    image.write(bytes(root))
    image.write(table)
    image.write(table)
    for _name, _ext, size, data in data_sectors:
        image.write(data)
        image.write(b"\x00" * ((-size) % _SECTOR))  # pad to sector end
    image.seek(0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(image.read())
    return out_path.stat().st_size


# ---------------------------------------------------------- kit validation
def read_kit_manifest(kit_dir: Path) -> Optional[Dict]:
    p = Path(kit_dir) / "rescue-manifest.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
