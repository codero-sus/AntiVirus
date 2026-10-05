"""Real-world detection pack: scoreboard against real, named malware (v2.6).

This module ships *detection capability* for real malware families -
WannaCry, Ryuk, LockBit, Stuxnet, Cobalt Strike, Emotet, TrickBot, Dridex,
Mirai, XMRig and more - via the sourced IOC signatures in
``data/signatures.json`` (category ``realworld``; each entry carries a
``source`` pointing at the public research it came from).

``antivirus realworld`` builds a corpus of **inert** samples - each one
contains only the publicly documented indicator of its family (ransom-note
text, config markers, leaked build paths, TLS fingerprints).  No live
malware is ever created, downloaded or executed.  The scoreboard then
answers, measured: how many of the 15 documented families does this engine
catch, and does it keep a clean file clean?

Honest framing: these signatures catch the *documented* forms of these
families (known samples by hash, known IOCs by pattern).  Commercial
engines additionally catch millions of unseen variants via continuously
updated databases, cloud and ML.  The gap is stated plainly by the command.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .config import Config
from .scanner import Scanner
from .signatures import SignatureDB

_EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
_HEADER = b"INERT DEMO - contains only publicly documented IOCs, no live malware\n"

#: The exact Stuxnet OS-check byte sequence with the documented wildcards
#: filled (wildcard bytes -> 0x41); matches RW-STUXNET-OSCHECK.
_STUXNET_FILL = (
    b"\x10\xf7\xd8\x1b\xc0\x83\xc0" b"\x41" b"\xe9" b"\x41"
    b"\x01\x00\x00\x39\x85\x7c\xff\xff\xff\x0f\x85" b"\x41"
    b"\x01\x00\x00\x83\xbd\x70\xff\xff\xff\x04\x8b\x8d\x74\xff\xff\xff"
    b"\x75\x0b\x85\xc9\x0f\x85" b"\x41" b"\x01\x00\x00\x6a\x05\x5e"
)


def _corpus_files() -> Dict[str, bytes]:
    """name -> content for every inert sample in the realworld corpus."""
    return {
        "wannacry-sample.bin": (
            _HEADER
            + b"msg/m_english.wnry\nmsg/m_spanish.wnry\n"
            + b"iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com\n"
        ),
        "petya-note.txt": (
            _HEADER
            + b"If you see this text, then your files are no longer "
              b"accessible, because they have been encrypted.\n"
        ),
        "ryuk-note.txt": (
            _HEADER
            + b"Your network has been penetrated.\nRyuk\nNo system is safe\n"
        ),
        "lockbit-note.txt": _HEADER + b"Restore-My-Files.txt\n",
        "doppelpaymer-sample.bin": (
            _HEADER + "setup runn".encode("utf-16-le") + b"\x00\x00"
        ),
        "bitpaymer-sample.bin": _HEADER + b"wp_encrypt\x00",
        "stuxnet-sample.bin": _HEADER + _STUXNET_FILL,
        "mirai-bot.bin": (
            _HEADER + b"kill competing botnets:\nHajime\nAnarchy\nMozi\n"
        ),
        "mirai-2026.bin": (
            _HEADER + b"DatasurgeOnTop\n/device.rsp S_O_S_T_R_E_A_MAX\n"
        ),
        "cobaltstrike-config.txt": (
            _HEADER
            + b"pipeame: msagent_1f\nMSSE-2024-server\npostex_abcd\n"
            + b"DserNamePipe1234567890\n"
            + b"JA3 a0e9f5d64349fb13191bc781f81f42e1\n"
            + b"JARM 07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2\n"
        ),
        "meterpreter-payload.bin": (
            _HEADER + b"MZ\x90\x00 ApacheBench\nmsfvenom\n"
        ),
        "dridex-loader.bin": (
            _HEADER + b"S:\Work\_bin\Release-Win32\ldr.pdb\n"
        ),
        "xmrig-config.json": (
            b'{"pools": [{"url": "pool.minexmr.com:443", "tls": true}],\n'
            b' "donate-level": 1, "cpu": true}\n'
        ),
        "redline-stealer.bin": (
            _HEADER
            + b"key: Raves\n"
            + b"AppData\\Roaming\\discord\\Local Storage\\leveldb\n"
            + b"Login Data\n"
        ),
        "clean-note.txt": b"Just a plain note. Nothing to see here.\n",
        "clean-poem.txt": (
            b"Two things filled the mind with wonder,\n"
            b"the starry sky above and the moral law within.\n"
        ),
        "eicar-test.txt": _EICAR,
    }


def build_corpus(root: Path) -> List[Path]:
    """(Re)write the inert corpus under *root*; returns the files."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    for name, content in sorted(_corpus_files().items()):
        p = root / name
        p.write_bytes(content)
        written.append(p)
    return written


@dataclass
class FamilyRow:
    family: str
    kind: str                    # "pattern" | "hash" | "pattern+hash"
    status: str                  # "detected" | "hash-only"
    matched_file: str = ""
    source: str = ""
    signatures: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "family": self.family, "kind": self.kind, "status": self.status,
            "matched_file": self.matched_file, "source": self.source,
            "signatures": self.signatures,
        }


def realworld_signatures(db: SignatureDB) -> List:
    """All sourced real-world signatures, ordered by family."""
    return sorted((s for s in db.list() if s.category == "realworld"),
                  key=lambda s: (s.family or "", s.id))


def run(config: Optional[Config] = None, corpus_dir: Optional[Path] = None,
        rebuild: bool = False) -> Dict:
    """Build the inert corpus (if needed) and score the engine against it."""
    config = config or Config()
    import dataclasses as _dc

    scan_config = _dc.replace(config, cache_enabled=False)
    corpus = Path(corpus_dir) if corpus_dir else Path("samples/realworld")
    if rebuild or not corpus.is_dir() or not any(corpus.iterdir()):
        build_corpus(corpus)

    db = SignatureDB(config.signatures_file)
    scanner = Scanner(scan_config, db, threads=1)
    result = scanner.scan_path(corpus)

    name_to_sig = {s.name: s for s in db.list()}
    found = {f.name for f in result.findings if f.name in name_to_sig}
    found_by_file: Dict[str, str] = {}
    for f in result.findings:
        if f.name in name_to_sig:
            found_by_file.setdefault(f.name, f.path)

    clean_files = {p.name for p in corpus.iterdir()
                   if p.name.startswith("clean-")}
    clean_fp = [f for f in result.findings
                if Path(f.path).name in clean_files]

    by_family: Dict[str, List] = {}
    for s in realworld_signatures(db):
        by_family.setdefault(s.family, []).append(s)

    rows: List[FamilyRow] = []
    detected = 0
    for family, sigs in by_family.items():
        kinds = {s.indicator for s in sigs if s.indicator}
        if "pattern" in kinds:
            kind = "pattern+hash" if (kinds & {"sha256", "md5"}) else "pattern"
        else:
            kind = "hash"
        matched = [s for s in sigs if s.name in found]
        source = "; ".join(dict.fromkeys(s.source for s in sigs))
        ids = [s.id for s in sigs]
        if matched:
            detected += 1
            rows.append(FamilyRow(family, kind, "detected",
                                  found_by_file.get(matched[0].name, ""),
                                  source, ids))
        else:
            rows.append(FamilyRow(family, kind, "hash-only", "", source, ids))

    pattern_families = [r for r in rows if "pattern" in r.kind]
    return {
        "corpus": str(corpus),
        "files": len(list(corpus.iterdir())),
        "families_total": len(rows),
        "families_pattern": len(pattern_families),
        "families_detected": detected,
        "clean_false_positives": len(clean_fp),
        "clean_findings": [
            {"path": f.path, "name": f.name, "severity": f.severity}
            for f in clean_fp],
        "rows": [r.to_dict() for r in rows],
        "note": (
            "Inert samples contain only publicly documented IOCs - no live "
            "malware. 'hash-only' families match real samples by SHA-256 "
            "(documented sample hashes); the corpus cannot exercise them. "
            "Commercial engines additionally catch unseen variants via "
            "continuously updated databases, cloud and ML - this pack is a "
            "sourced, auditable starting point you can extend with "
            "`sig import`."),
    }


def verdict_line(result: Dict) -> str:
    fp = result["clean_false_positives"]
    return (f"{result['families_total']} real-world families "
            f"({result['families_pattern']} pattern, "
            f"{result['families_total'] - result['families_pattern']} hash) - "
            f"{result['families_detected']}/{result['families_pattern']} "
            f"pattern families detected, {fp} false positives")
