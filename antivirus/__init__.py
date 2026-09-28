"""AntiVirus — a lightweight, dependency-free antivirus written in pure Python.

Features
--------
* Signature-based scanning (SHA-256 / MD5 hashes and regex patterns)
* Behavioural analysis (Python AST, shell/PowerShell/batch, PE/ELF imports)
* PE "debug report" dissection (headers, sections, imports, resources)
* Archive scanning (ZIP / TAR / GZIP, in memory, zip-slip / tar-slip)
* Heuristic scanning (Shannon-entropy check for packed / encrypted files)
* File-integrity baselines (manifests + changed/missing/new detection)
* Scan cache, fast mode, incremental ``--since`` scans
* Quarantine with manifest: list, restore and purge
* Directory monitoring (polling based, no external dependencies)
* JSON + human readable scan reports, report diff & summary, CSV/JSONL export
* Fast integrity checks (verify), plain-text IOC imports, engine statistics
* Rescue disk: self-contained kit + ISO 9660 image for scanning a system
  from a live environment (quarantine stays on the rescue side)
* Multiple front-ends: CLI, Tkinter GUI, curses TUI, web console —
  and a plain-module API for embedding in your own code

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

__version__ = "2.0.0"

from .api import (  # noqa: E402
    Antivirus,
    apply_actions,
    rescue_build,
    run_rescue,
    scan,
    scan_file,
)

__all__ = [
    "Antivirus",
    "apply_actions",
    "rescue_build",
    "run_rescue",
    "scan",
    "scan_file",
    "__version__",
]
