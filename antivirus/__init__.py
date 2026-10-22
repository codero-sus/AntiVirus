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
  detection layer's verdict (hash / pattern / behaviour / polyglot /
  obfuscation / indicators / feeds / url / risk / entropy / archive) with a
  "detected by N of M engines" consensus
* Mutation detection: a standing trust baseline (`trust snapshot/add/...`)
  flags trusted files whose content changed; bulk mutation (>= 5 files in
  one pass) raises a critical "possible ransomware activity" alert
* Polyglot detection: one file valid in 2+ formats (PDF/PE, image/PE,
  text+embedded PE or high-entropy blob) - legitimate containers (a PDF
  with a photo, a ZIP of docs) stay clean
* Obfuscation detection: high-entropy base64/hex payload blobs, double
  encoding, UTF-16 encoded blobs, NOP/int3 junk code, packed PEs with no
  import table (hidden API surface)
* Performance: `antivirus perf` - measured cold/warm throughput (files/s,
  MB/s), cache speedup and per-file latency (p50/p99) on a synthetic corpus
* Comparison: `antivirus compare` - honest feature + positioning comparison
  vs AVG / Avast / Malwarebytes / VirusTotal with live perf numbers
* Real-world detection pack: sourced IOC signatures for 99 real named
  malware families (WannaCry, Ryuk, LockBit, Stuxnet, Cobalt Strike,
  Emotet, TrickBot, Dridex, Mirai, XMRig, ...) - each signature carries its
  public research source; `antivirus realworld` scores the pack against an
  inert sample corpus (92/92 pattern families detected, 0 false positives)
* Public threat-intel feeds (v2.9): `antivirus feeds build` fetches vetted
  public blocklists, hash sets and rule strings, converts what can be
  converted faithfully and stores them as compact sorted indexes
  (4.6 M indicators in ~35 MB); licence-aware, provenance-tracked, and
  git-ignored - local ClamAV databases can be imported with
  `feeds import-clamav`.  Feed hits form their own engine layer
* False-positive allowlist (v3.0): exact hashes, file-name globs, path
  globs and domains that must never be reported - `antivirus allowlist
  list|add|remove|check|export|import|from-findings|audit`, honoured by
  every scan, visible as "Suppressed: N" in the summary and as
  `allowlist_suppressed` in the JSON report (`--no-allowlist` to bypass)
* False-positive audit (v3.0): `antivirus fpcheck` runs the whole indicator
  library against random binary blobs, random text and a corpus of
  realistic clean scripts/docs, and exits non-zero if anything above the
  chosen severity is flagged - the release gate for detection content
* YARA export (v3.0): `antivirus yara --out rules.yar` converts the
  signature database, the technique indicators and (optionally) feed
  literals into a portable ruleset; constructs YARA cannot express are
  skipped and counted, never approximated
* ATT&CK coverage view (v3.0): `antivirus matrix` groups every indicator by
  tactic with severity mix, top tags and gaps
* Technique table, part two (v3.1): 55 more checks - modern LOLBins
  (mavinject, xwizard, wsreset, sqlps, wsl, dllhost, csc, aspnet_compiler),
  MSDT/search-ms URI handlers, Linux and container execution (nsenter,
  /dev/shm, compile-on-host, docker.sock), sandbox and anti-debug evasion,
  AMSI/ETW patching by hand, and injection primitives (APC, section mapping,
  thread hijack).  Every row carries a trigger sample: `indicators --show ID`
  prints it, `indicators --dump-samples DIR` exports the corpus, and the test
  suite proves each check fires on its own sample
* Technique indicators (v2.8): 356 static checks (LOLBins, persistence,
  evasion, credential access, C2, ransomware impact, Office macros,
  file-name tricks) - `antivirus indicators`
* User rules (v2.8): YARA-lite patterns and file-name globs managed with
  `antivirus rules`
* Machine-readable output (v2.8): SARIF 2.1.0 (`scan --sarif`),
  self-contained HTML (`scan --html`), Prometheus metrics, `--fail-on`
* Literal prefilter (v2.8): pattern matching is ~100x faster than the
  merged-alternation approach (6.8 s/MiB -> 69 ms/MiB)
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

__version__ = "3.9.0"

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
