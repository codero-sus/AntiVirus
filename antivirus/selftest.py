"""Built-in self test.

Proves that every detection layer, the quarantine and the signature editor
work — using the standard, *harmless* EICAR antivirus test string (a plain
text marker that antivirus vendors agree to detect; it is not malware).
"""
from __future__ import annotations

import hashlib
import random
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import List

from .config import Config
from .quarantine import Quarantine
from .scanner import Scanner
from .signatures import Signature, SignatureDB
from .utils import md5_new

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def run_selftest() -> int:
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

        # Work on a private copy of the bundled database, never the repo one.
        bundled = Path(__file__).resolve().parent.parent / "data" / "signatures.json"
        if bundled.exists():
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

    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    passed = sum(results)
    print("-" * 62)
    print(f"Self test: {passed}/{len(results)} checks passed")
    return 0 if passed == len(results) else 1
