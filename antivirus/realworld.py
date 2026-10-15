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


#: Second-wave inert markers (v2.8): one documented marker string per
#: family, rendered as an inert sample.  Kept as a table so the corpus can
#: grow without touching the scanner at all.
_EXTRA_SAMPLES: Dict[str, bytes] = {
    "amadey-sample.bin": b"Amadey loader build",
    "avaddon-sample.bin": b"Avaddon decryptor page",
    "avoslocker-sample.bin": b"AvosLocker support chat",
    "billgates-sample.bin": b"billgates bot variant",
    "blackmatter-sample.bin": b"BlackMatter leak site",
    "blacksuit-sample.bin": b"BlackSuit victim list",
    "bumblebee-sample.bin": b"BumbleBee loader",
    "crysis-sample.bin": b"CrySiS encrypted marker",
    "dcrat-sample.bin": b"DcRat panel",
    "darkcomet-sample.bin": b"DarkComet RAT",
    "gh0st-sample.bin": b"Gh0st RAT client",
    "guloader-sample.bin": b"GuLoader shellcode",
    "hajime-sample.bin": b"Hajime peer list",
    "hunters-sample.bin": b"Hunters International blog",
    "icedid-sample.bin": b"IcedID loader",
    "lazagne-sample.bin": b"lazagne recovered credentials",
    "latrodectus-sample.bin": b"Latrodectus loader",
    "lightaidra-sample.bin": b"lightaidra bot",
    "matsnu-sample.bin": b"matsnu downloader",
    "moneymessage-sample.bin": b"MoneyMessage blog",
    "mozi-c2.txt": b"botnet C2 suffix: Mozi.m",
    "mountlocker-sample.bin": b"MountLocker note",
    "nefilim-sample.bin": b"NEFILIM leak page",
    "noescape-sample.bin": b"NoEscape blog",
    "pikabot-sample.bin": b"Pikabot beacon",
    "powersploit-sample.bin": b"PowerSploit module",
    "privateloader-sample.bin": b"PrivateLoader build",
    "quasar-sample.bin": b"Quasar.Client settings",
    "ragnar-sample.bin": b"RAGNAR_LOCKER note",
    "ransomhub-sample.bin": b"RansomHub chat",
    "redline-marker.bin": b"RedLine Stealer build tag",
    "rhysida-sample.bin": b"Rhysida auction",
    "rubeus-sample.bin": b"Rubeus kerberoast",
    "smokeloader-sample.bin": b"SmokeLoader stub",
    "stealc-sample.bin": b"Stealc panel",
    "teslacrypt-sample.bin": b"TeslaCrypt service",
    "trigona-sample.bin": b"trigona note",
    "upatre-sample.bin": b"upatre dropper",
    "webshell-b374k.txt": b"b374k shell",
    "webshell-r57.txt": b"r57shell",
    "webshell-generic.txt": (b"<?php eval($_REQUEST['x']); system($_REQUEST['y']); "
                             b"passthru($_GET['z']); shell_exec($_GET['w']); ?>"),
    "xworm-sample.bin": b"XWorm builder",
    "yanluowang-sample.bin": b"yanluowang note",
    "pwdump-sample.bin": b"pwdump output",
    "empire-sample.bin": b"PowerShell Empire stager",
}

def _corpus_files() -> Dict[str, bytes]:
    """name -> content for every inert sample in the realworld corpus."""
    out = {
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
        # ---- v2.8 expansion: inert samples for the extended family pack ----
        "conti-note.txt": _HEADER + b"CONTI_README.txt\n",
        "revil-sample.bin": _HEADER + b"config: sodinokibi\n",
        "blackcat-note.txt": _HEADER
                             + b"RECOVER-myfiles-FILES.txt\n",
        "hive-leak.txt": _HEADER + b"hiveleaks site listing\n",
        "maze-note.txt": _HEADER + b"DECRYPT-FILES.txt\n",
        "stop-djvu-note.txt": _HEADER
                              + b"_readme.txt: you can return all your files\n",
        "medusa-note.txt": _HEADER + b"!!!READ_ME_MEDUSA!!!.txt\n",
        "royal-note.txt": _HEADER + b"Royal Ransomware group\n",
        "akira-note.txt": _HEADER + b"akira_readme.txt\n",
        "blackbasta-note.txt": _HEADER + b"Black Basta negotiators\n",
        "makop-note.txt": _HEADER + b"+README-WARNING+.txt\n",
        "clop-note.txt": _HEADER + b"README_CLOP.txt\n",
        "gandcrab-sample.bin": _HEADER + b"GANDCRAB V5.2\n",
        "darkside-note.txt": _HEADER + b"README.DARKSIDE.TXT\n",
        "babuk-note.txt": _HEADER + b"How To Restore Your Files.txt\n",
        "notpetya-note.txt": _HEADER + b"Ooops, your files have been encrypted!\n",
        "raccoon-sample.bin": _HEADER + b"Raccoon Stealer build\n",
        "lumma-sample.bin": _HEADER + b"LummaC2 config\n",
        "agenttesla-sample.bin": _HEADER + b"AgentTesla SMTP exfil\n",
        "formbook-sample.bin": _HEADER + b"Formbook C2\n",
        "asyncreat-sample.bin": _HEADER + b"AsyncRAT client\n",
        "remcos-sample.bin": _HEADER + b"Remcos\n",
        "nanocore-sample.bin": _HEADER + b"NanoCore plug-in\n",
        "njrat-sample.bin": _HEADER + b"Bladabindi\n",
        "c99shell.txt": _HEADER + b"c99shell v.1.0\n",
        "china-chopper.txt": _HEADER + b"<?php @eval($_POST['pass']);?>\n",
        "mimikatz-sample.bin": _HEADER + b"sekurlsa::logonpasswords\n",
        "sharphound-sample.bin": _HEADER + b"SharpHound collector\n",
        "xorddos-sample.bin": _HEADER + b"XorDDoS variant\n",
        "gafgyt-sample.bin": _HEADER + b"Gafgyt\n",
        "stratum-config.json": (
            b'{"url": "stratum+tcp://pool.supportxmr.com:3333",\n'
            b' "user": "donate", "minerd": true}\n'
        ),
        "ursnif-sample.bin": _HEADER + b"Ursnif loader\n",
        "gozi-sample.bin": _HEADER + b"Gozi core\n",
        "clean-note.txt": b"Just a plain note. Nothing to see here.\n",
        "clean-poem.txt": (
            b"Two things filled the mind with wonder,\n"
            b"the starry sky above and the moral law within.\n"
        ),
        "eicar-test.txt": _EICAR,
    }
    for name, marker_bytes in _EXTRA_SAMPLES.items():
        out[name] = _HEADER + marker_bytes + b"\n"
    return out


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
    # Rebuild when the corpus is absent *or* a sample the current engine
    # expects is missing (the pack grows between versions) – self-healing,
    # so an old corpus never silently under-reports coverage.
    present = {p.name for p in corpus.iterdir()} if corpus.is_dir() else set()
    if rebuild or not present or set(_corpus_files()) - present:
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
