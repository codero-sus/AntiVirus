"""Tests for the AntiVirus package.

Run with either:
    python3 -m unittest discover -s tests -v
    python3 -m pytest -v        # if pytest is installed
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from antivirus.config import Config
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
