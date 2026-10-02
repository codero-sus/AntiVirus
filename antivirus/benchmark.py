"""Detection benchmark: how does the engine do on the sample corpus? (v2.4)

The bundled ``samples/`` tree is a small, fully-labelled corpus: every file
is either a *known threat* (EICAR string, behavioural scripts, code-less
PE/ELF images, sneaky archives, disguised/bloated drops, malicious links)
or *known clean*.  ``antivirus benchmark`` runs the full scanner over each
file and reports:

* **recall**   – what fraction of the known threats is detected
* **precision** – how many clean files were falsely flagged
* a per-file table with the findings each file produced

This is an *educational* benchmark: it proves the layers work together and
lets you see the effect of signature / intel changes.  It is not a
substitute for real-world malware corpora (like the EICAR-based checks
commercial engines publish) - the honest framing is in the CLI output.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Dict, List, Optional

from .config import Config
from .quarantine import Quarantine  # noqa: F401  (import surface parity)
from .scanner import Scanner
from .signatures import SignatureDB

#: Relative path -> expected class.  Files present on disk but not listed
#: here are reported as "unlabelled" and excluded from the scores.
EXPECTED: Dict[str, str] = {
    "eicar-test.txt": "bad",
    "clean.txt": "clean",
    "behavior/README.txt": "clean",
    "behavior/clean.elf": "clean",
    "behavior/clean.exe": "clean",
    "behavior/dropper.bat": "bad",
    "behavior/dropper.vbs": "bad",
    "behavior/harmless-py.py": "clean",
    "behavior/harmless-vbs.vbs": "clean",
    "behavior/harmless.sh": "clean",
    "behavior/packed-upx.exe": "bad",
    "behavior/payload-py.py": "bad",
    "behavior/pipe-shell.sh": "bad",
    "behavior/reverse-ps1.ps1": "bad",
    "behavior/sneaky.tar.gz": "bad",
    "behavior/sneaky.zip": "bad",
    "behavior/suspicious.elf": "bad",
    "behavior/suspicious.exe": "bad",
    "suspicious/invoice.pdf.exe": "bad",
    "suspicious/blob_7f3a9c2b.exe": "bad",
    "suspicious/win-update-notes.txt": "bad",
    "suspicious/backdoor-link.txt": "bad",
    "clean/photo.jpg": "clean",
    "clean/report.csv": "clean",
    "clean/notes.txt": "clean",
    "clean/script.py": "clean",
}


def run(samples_dir: Path, config: Optional[Config] = None,
        signatures_file: Optional[Path] = None) -> Dict:
    """Run the benchmark.  Returns a result dict (JSON friendly).

    When *samples_dir* does not exist, the shipped corpus is built in a
    scratch directory instead (so the command works from any checkout).
    """
    samples_dir = Path(samples_dir)
    if not samples_dir.is_dir():
        import tempfile

        from .samples import build_all_samples
        samples_dir = Path(tempfile.mkdtemp(prefix="av-benchmark-"))
        build_all_samples(samples_dir)

    config = config or Config()
    if signatures_file:
        config.signatures_file = signatures_file
    db = SignatureDB(config.signatures_file)
    scanner = Scanner(config, db)

    rows: List[Dict] = []
    detected_bad = missed_bad = false_pos = 0
    t0 = time.time()
    for rel, expected in sorted(EXPECTED.items()):
        p = samples_dir / rel
        if not p.exists():
            rows.append({"file": rel, "expected": expected,
                         "verdict": "missing", "findings": []})
            if expected == "bad":
                missed_bad += 1
            continue
        findings = scanner.scan_file(p)
        flagged = bool(findings)
        if expected == "bad":
            if flagged:
                detected_bad += 1
                verdict = "detected"
            else:
                missed_bad += 1
                verdict = "MISSED"
        else:
            if flagged:
                false_pos += 1
                verdict = "FALSE POSITIVE"
            else:
                verdict = "clean"
        rows.append({
            "file": rel, "expected": expected, "verdict": verdict,
            "findings": [{"kind": f.kind, "name": f.name,
                          "severity": f.severity} for f in findings],
        })
    elapsed = time.time() - t0

    bad_total = sum(1 for v in EXPECTED.values() if v == "bad")
    clean_total = sum(1 for v in EXPECTED.values() if v == "clean")
    return {
        "samples_dir": str(samples_dir),
        "signatures": len(db.list()),
        "bad_total": bad_total,
        "bad_detected": detected_bad,
        "recall": round(detected_bad / bad_total, 3) if bad_total else 0.0,
        "clean_total": clean_total,
        "clean_flagged": false_pos,
        "elapsed_seconds": round(elapsed, 3),
        "rows": rows,
    }


def verdict_line(result: Dict) -> str:
    recall_ok = result["bad_detected"] == result["bad_total"]
    fp_ok = result["clean_flagged"] == 0
    if recall_ok and fp_ok:
        return (f"{result['bad_detected']}/{result['bad_total']} threats "
                f"detected, 0 false positives")
    parts = []
    if not recall_ok:
        parts.append(f"{result['bad_detected']}/{result['bad_total']} "
                     f"threats detected")
    if not fp_ok:
        parts.append(f"{result['clean_flagged']} false positive(s)")
    return ", ".join(parts)
