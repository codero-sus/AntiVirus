"""AntiVirus — a lightweight, dependency-free antivirus written in pure Python.

Features
--------
* Signature-based scanning (SHA-256 / MD5 hashes and regex patterns)
* Behavioural analysis (Python AST, shell/PowerShell/batch/VBScript,
  PE/ELF imports)
* PE "debug report" dissection (headers, sections, imports, resources)
* Archive scanning (ZIP / TAR / GZIP, in memory, zip-slip / tar-slip)
* Heuristic scanning (Shannon-entropy check for packed / encrypted files)
* File-integrity baselines (manifests + changed/missing/new detection)
* Scan cache, fast mode, incremental ``--since`` scans
* Quarantine with manifest: list, restore and purge
* Directory monitoring (polling based, no external dependencies)
* JSON + human readable scan reports, report diff & summary, CSV/JSONL export
* Fast integrity checks (verify), plain-text IOC imports, engine statistics
* Kill engine: neutralize threats *in place* (std-only keystream
  obfuscation) with the key/IV stored in the AntiVirus registry —
  revivable, auditable, and rescan-aware (killed files stay inert)
* Rescue disk: self-contained kit + ISO 9660 image for scanning a system
  from a live environment (quarantine stays on the rescue side)
* Background guard: detached, lightweight real-time watch that auto-scans
  new/changed files (stat-only incremental walk, no external deps)
* Suspicion engine: 0-100 risk score per file from what it *looks* like
  (double extensions, document-disguised binaries, name words, entropy,
  location) - the guard quarantines suspicious drops with no known
  signature
* Web shield: every scanned file is read for URLs and each URL is scored
  (threat-intel blocklist, shorteners, IP hosts, backdoor ports,
  credentials) - plus `urlcheck` / `webshield add|show`
* Firewall: live connection-table audit (no root needed) flagging backdoor
  ports, blocklisted IPs, risky listeners - `firewall scan|monitor`
* Benchmark: `antivirus benchmark` runs the labelled sample corpus and
  reports recall / false positives (100% / 0 on the bundled set)
* Engine report: `antivirus engine FILE` - a VirusTotal-style table of each
  detection layer's verdict (hash / pattern / behaviour / url / risk /
  entropy / archive) with a "detected by N of M engines" consensus
* Performance: `antivirus perf` - measured cold/warm throughput (files/s,
  MB/s), cache speedup and per-file latency (p50/p99) on a synthetic corpus
* Comparison: `antivirus compare` - honest feature + positioning comparison
  vs AVG / Avast / Malwarebytes / VirusTotal with live perf numbers
* Multiple front-ends: CLI, Tkinter GUI, curses TUI, web console —
  and a plain-module API for embedding in your own code
* Runs on Windows, Linux and macOS (the curses TUI is Unix-only; the
  web console, GUI and CLI work everywhere)

The project ships with the standard, *harmless* EICAR test string so you can
verify that detection works without touching any real malware.

Using it as a module
--------------------
    import antivirus                    # version, Antivirus, scan, scan_file
    result = antivirus.scan("some/dir") # one-shot scan -> ScanResult
    for f in result.findings:           # Finding objects
        print(f.severity, f.name, f.path)

    from antivirus import Antivirus     # long-lived engine with its own
    av = Antivirus(base="~/.myapp")     # working area
    av.add_signature(id="AV-X", name="X", pattern="MARKER",
                     severity="high")
    av.scan_file("bin.exe")
    av.file_info("bin.exe")["sha256"]
    av.manifest("some/dir")
    av.quarantine.restore("275a021b-...")

Everything is standard library only (Tkinter/curses are optional and used
only by their respective front-ends).
"""

__version__ = "2.5.0"

from .api import (  # noqa: E402
    Antivirus,
    apply_actions,
    rescue_build,
    run_rescue,
    scan,
    scan_file,
)
from .kill import KillItem, KillRegistry  # noqa: E402

__all__ = [
    "Antivirus",
    "KillItem",
    "KillRegistry",
    "apply_actions",
    "rescue_build",
    "run_rescue",
    "scan",
    "scan_file",
    "__version__",
]
