# 🛡️ AntiVirus

A small, **dependency-free antivirus written in pure Python** (3.9+, standard
library only). It scans files and directory trees, quarantines threats,
watches folders for new/changed files, and writes JSON + text reports.

> ⚠️ **Disclaimer** — this project is an **educational exercise**. It is *not*
> a replacement for a real antivirus and must not be relied on for protection.
> It ships with a single, clearly-labelled test signature (the standard,
> **harmless** [EICAR](https://www.eicar.org/) test string). It contains no
> real malware, and none should ever be added to this repository.

## Features

- **Signature detection**
  1. *Hash* — SHA-256 (plus MD5) of each file vs. the signature database
  2. *Pattern* — regular expressions matched against raw file bytes
     (catches renamed/wrapped variants)
- **Behavioural detection** (static — nothing is ever executed):
  * *Python* — AST analysis: `eval`/`exec` on non-constant input,
    `subprocess(..., shell=True)`, `os.system`, sockets to hardcoded
    addresses, dynamic imports, base64 payload blobs
  * *Shell / PowerShell / Batch* — pipe-to-shell downloads, reverse shells,
    crypto-mining C2 endpoints, LOLBin downloaders (certutil/mshta/bitsadmin),
    persistence (cron / services / shell rc), encoded payloads
  * *VBScript / Windows Script Host* (`.vbs` / `.vbe` / `.wsf`) —
    `WScript.Shell` command execution, XMLHTTP downloads, certutil /
    bitsadmin / mshta / scrobj LOLBins, hidden or encoded PowerShell
    launches, WMI process creation, registry writes, `chr()` obfuscation
  * *PE binaries* — import-table analysis (process-injection API sets,
    download+execute combinations, registry persistence, timestamp
    tampering) plus per-section entropy and packer section names
- **PE "debug report"** — a static dissection of `.exe` / PE images, like a
  debugger's module view (headers, characteristics, sections + entropy,
  imports, exports, resources, relocations, TLS, debug directories, .NET
  marker) with **debug-derived indicators**: ASLR/DEP disabled, stripped
  relocations, missing entry point, missing debug info, TLS callbacks,
  missing/obfuscated import table, huge `.rsrc`, and script/LOLBin markers
  hidden in embedded resources
  * *ELF binaries* — import-table analysis of `.dynsym` (ELF32 and ELF64:
    process-execution API sets such as `system`/`execve`/`popen`, dynamic
    library loading `dlopen`/`dlsym`, raw socket APIs, `ptrace`, and
    file-manipulation sets) plus high-entropy loadable segments
  * *File-system* — setuid/setgid executables
- **Archive scanning** — ZIP, TAR and GZIP (including `.tar.gz`) contents
  are inspected *in memory* (never extracted to disk): every entry runs
  through the same signature / behaviour / entropy layers and is reported
  as `archive.tar.gz!entry.py`; the layer also flags path-traversal entry
  names (zip-slip / tar-slip, `../x`), encrypted ZIP entries, entry caps
  and an expansion budget that stops bombs
- **Incremental scans** — `scan --since 2h` only scans files modified
  within the given duration (`30s` / `30m` / `2h` / `1d` / `1w` / bare
  seconds); older files are skipped and counted as such (also works with
  `monitor`)
- **Hash command** — `hash FILE…` prints SHA-256 / MD5 / SHA-1 digests and
  the size of each file
- **Report diff** — `report diff [OLD NEW]` compares two saved reports
  (default: the two newest) and lists what is new, what was cleared, and
  what is unchanged
- **Signature import/export** — `sig export FILE` / `sig import FILE`
  move a signature database to another machine; the import merges and
  skips duplicate ids
- **Scan cache** — a full scan records each file's verdict
  (size + mtime + engine profile) in `.av-cache`; the next scan of
  unchanged files skips disk reads entirely, so rescans are ~20× faster
  (`--no-cache` to force a full re-read)
- **Fast mode** — `--fast` runs the hash + pattern layers only (no
  behaviour analysis, no entropy): a quick rescan for when you mostly
  care about known-bad files
- **Exclude patterns** — `--exclude GLOB` (repeatable) skips files whose
  name or relative path matches, e.g. `--exclude '*.log' --exclude
  'build/*'`
- **Static heuristic** — Shannon-entropy check that flags large
  packed/encrypted files
- **Quarantine** — infected files are moved to a sandboxed directory with a
  JSON manifest; list, restore or purge them later
- **Kill engine** — the `kill` action neutralizes a threat **in place**:
  its bytes are obfuscated with a one-time stdlib-only keystream cipher so
  the binary can no longer run or match its own signatures, while the
  256-bit key + IV are stored in the AntiVirus **registry**
  (`registry/kill.json`) — `kill revive` restores the exact original
  bytes, `kill purge` destroys file + material. Rescans treat killed
  files as *neutralized* (inert, not re-flagged); threats inside archives
  are neutralized by obfuscating the container
- **Directory monitor** — polls a tree and scans every new/changed file
- **Background guard** — `guard start` runs the monitor as a **detached
  background daemon** (no terminal, no console window): it auto-scans every
  new/changed file as it appears and acts on threats (quarantine / kill /
  delete). Lightweight by design: a stat-only **incremental walk** that
  never re-lists an unchanged directory, no report files (a small rotating
  `guard.log` instead), and a single Python process — controlled with
  `guard start | stop | status | log`
- **Suspicion engine** — a signature-independent 0-100 risk score from what
  a file *looks* like (document-disguised binaries, double extensions,
  malware-typical name words, random names, suspicious locations, high
  entropy): suspicious new files are flagged — and the guard quarantines
  them — with no known signature at all
- **Web shield** — every scanned file is read for URLs and each URL is
  scored (threat-intel blocklist, URL shorteners, IP hosts, embedded
  credentials, executable-looking links, backdoor ports); malicious URLs
  in a file are a high-severity finding; `urlcheck` / `webshield add|show`
  manage it, `GET /api/webshield` in the console
- **Firewall** — a live, no-root connection-table audit that flags backdoor
  ports (4444/4431/5555/31337/…), blocklisted remote IPs, risky listeners
  (telnet/FTP/VNC/RDP/SMB) and odd outbound ports; `firewall scan|monitor`,
  `GET /api/firewall`
- **Benchmark** — `benchmark` runs the fully-labelled 25-file sample corpus
  and reports recall + false positives (100% / 0 on the bundled set)
- **Performance benchmark** — `perf` measures real throughput: cold vs
  warm scan (files/s, MB/s), the **cache speedup**, and per-file latency
  (p50/p99) on a synthetic corpus
- **Engine report** — `engine FILE` gives a VirusTotal-style per-layer
  verdict table (hash / pattern / behaviour / url / risk / entropy /
  archive) with a "detected by N of M engines" consensus, in one read pass
- **Comparison** — `compare` prints the honest feature + positioning
  picture vs AVG / Avast / Malwarebytes / VirusTotal, with live `perf`
  numbers (no inflated "beats commercial AV" claims)
- **Reports** — every scan writes a JSON report and a human-readable text
  report
- **Signature editor** — add your own signatures from the CLI (hash or
  pattern)
- **Rescue disk** — `rescue build` packages the engine + signatures into a
  self-contained kit *and* a mountable ISO 9660 image (pure-Python writer)
  for scanning a machine from a live system; `rescue run` scans an infected
  volume with quarantine/reports always sent to the live side and the scan
  cache disabled; `rescue verify` checks the media's SHA-256 manifest
- **Self test** — built-in end-to-end test using the harmless EICAR string
- **Graphical UI** — Tkinter desktop app (standard library, no extra
  packages): pick a target, scan with live progress and a stop button,
  review severity-coloured findings, and manage the quarantine
  (`python3 -m antivirus gui`)
- **Web console** — a browser UI + JSON API on the standard-library
  `http.server` (no packages): scan jobs with **live findings feed**,
  results table with text filter, quick single-file check (type,
  digests, mini-scan), integrity baselines, report history, quarantine
  manager, signature editor and built-in API docs
  (`python3 -m antivirus web --port 8420`)
- **Terminal UI** — a curses TUI with live scan progress, coloured
  findings list, detail view and scan options
  (`python3 -m antivirus tui`)
- **Usable as a module** — `import antivirus` for a one-shot
  `antivirus.scan(target)`, or `from antivirus import Antivirus` for a
  long-lived engine (signatures, quarantine, baselines, file info) in
  your own programs — see [Using it as a module](#using-it-as-a-module)
- **File identification** — `fileinfo FILE…` (and `/api/fileinfo` in the
  web console) reports the file type from magic bytes + extension, size,
  mtime and SHA-256/MD5
- **File-integrity baselines** — `manifest DIR` hashes a tree into a JSON
  baseline; a later `scan DIR --baseline FILE` reports every file that
  changed, appeared or disappeared (classic FIM)
- **Sample generator** — `samples [DIR]` writes the full inert demo sample
  tree (EICAR string, scripts, code-less PE/ELF images, sneaky archives)
  anywhere, for testing the engine
- **Report summary** — `report summary` aggregates all saved reports
  (infected/clean counts, severity breakdown, top indicators)
- **Fast integrity check** — `verify DIR --baseline FILE` re-hashes a tree
  and diffs it against a baseline **without** running any signature /
  behaviour / entropy layers, so it is much cheaper than a full
  `scan --baseline` — the quick "is anything different?" FIM check
  (also `GET /api/verify` and `av.verify(...)` as a module)
- **Report export** — `export [REPORT …]` flattens the findings of saved
  reports (default: all of them) into **CSV** (default) or **JSONL** with
  one row per finding: report, target, timestamp, severity, kind, name,
  file, SHA-256, size, action and message — ready for Excel / SIEM / grep
- **IOC import** — `sig import FILE` also accepts **plain-text IOC files**:
  64-hex lines become SHA-256 signatures, 32-hex lines MD5 signatures,
  `pattern: …` lines are regexes, and anything else is a literal marker.
  `#`/`;` lines are comments; `--source` tags the category and `--severity`
  sets the level. JSON export files still work unchanged
- **Engine statistics** — `stats` (and `GET /api/stats`) summarises the
  engine: signature counts by severity and matcher kind, scan-cache size
  and entry count, quarantine item count, and report totals
- **Scan progress bar** — directory scans print a live `[###····]`
  progress bar on **stderr** (so `--json` stdout stays a pure JSON stream
  for piping), throttled to a smooth update rate
- **Machine-readable monitor** — `monitor --json` emits one JSON object per
  event (`removed` / `clean` / `threat` / `quarantined` / `deleted` /
  `error`) instead of coloured human lines, for piping into a log aggregator

## Requirements

- Python 3.9+ — that's it. No third-party packages.
- For the **GUI** only: Tkinter, which ships with Python on Windows/macOS
  and is packaged separately on Linux
  (`sudo apt install python3-tk` / `sudo dnf install python3-tkinter`).
  Without it, `antivirus gui` prints a hint and the CLI works unchanged.

## Quick start

```bash
# 1. Prove that detection works (uses the harmless EICAR test string)
python3 -m antivirus selftest

# 2. Scan a directory (detect only — nothing is changed)
python3 -m antivirus scan .

# 2b. Scan again — unchanged files are served from the scan cache (~20× faster)
python3 -m antivirus scan .
python3 -m antivirus scan . --fast          # quick rescan: hash + pattern only
python3 -m antivirus scan . --exclude '*.log'

# 3. Scan and quarantine threats
python3 -m antivirus scan . --action quarantine

# 4. See what was quarantined, put it back, or destroy it for good
python3 -m antivirus quarantine list
python3 -m antivirus quarantine restore 275a021bbfb6
python3 -m antivirus quarantine purge 275a021bbfb6

# 5. Watch a folder in (near) real time
python3 -m antivirus monitor . --action quarantine

# 5b. …or run the same protection as a lightweight background daemon
python3 -m antivirus guard start . --action quarantine
python3 -m antivirus guard status
python3 -m antivirus guard stop

# 5c. Score how suspicious a file looks / check URLs / audit the network
python3 -m antivirus risk invoice.pdf.exe
python3 -m antivirus urlcheck http://c2node.evilcorp.invalid/x
python3 -m antivirus firewall scan
python3 -m antivirus benchmark          # 100% recall, 0 false positives

# 6. Look at the reports
python3 -m antivirus report list
python3 -m antivirus report show

# 7. Inspect / extend the signature database
python3 -m antivirus sig show
python3 -m antivirus sig add --id MY-LAB-1 --name "My lab marker" \
    --severity high --pattern "MY-UNIQUE-MARKER-1234"

# 8. Use the graphical interface (needs Tkinter, see Requirements)
python3 -m antivirus gui
```

Optionally install the console script (same thing, nicer name):

```bash
pip install .
antivirus scan .
```

Exit codes: `0` = clean, `1` = threats found, `2` = error.
Add `--json` to `scan` for machine-readable output.

## Try it instantly

`samples/` contains a file with the standard EICAR test string (a 68-byte
text marker — **not** malware) and a clean file:

```bash
python3 -m antivirus scan samples/          # -> detects eicar-test.txt
python3 -m antivirus scan samples/ --action quarantine
```

`samples/behavior/` contains inert scripts and code-less PE images that
demonstrate the behavioural layer and the PE debug report:

```bash
python3 -m antivirus scan samples/behavior
python3 -m antivirus behavior analyze samples/behavior/pipe-shell.sh
python3 -m antivirus behavior analyze samples/behavior/suspicious.exe

# full static "debug report" of a PE image (headers, sections, imports,
# exports, resources, relocations, TLS, debug dirs + red flags)
python3 -m antivirus pe analyze samples/behavior/suspicious.exe
python3 -m antivirus pe analyze samples/behavior/packed-upx.exe
python3 -m antivirus pe analyze samples/behavior/clean.exe   # -> no findings
```

## Windows support

Everything runs on Windows (10/11, 32- or 64-bit) with the stock Python
from python.org — 3.9+, no packages:

```bat
py -3 -m antivirus scan C:\Users\me\Downloads
py -3 -m antivirus scan D:\ --action quarantine --fast
py -3 -m antivirus web            :: dashboard + JSON API in the browser
py -3 -m antivirus gui            :: Tkinter desktop app
```

Works on Windows, unchanged from other platforms: signature + behavioural
scanning (including the **PE dissection** and the **VBScript** layers that
matter most there), archives, entropy heuristics, quarantine with restore,
reports, scan cache, integrity baselines (`manifest` / `verify` /
`scan --baseline`), IOC imports, statistics, the directory monitor, the
web console, the GUI, and the rescue kit — on Windows the kit ships a
`bootstrap.bat` next to `bootstrap.sh`:

```bat
bootstrap.bat D:\ --action quarantine
```

Platform notes:

- **TUI** — the curses terminal UI is Unix-only (CPython does not bundle
  `curses` on Windows). `antivirus tui` explains this and points to the
  web console / GUI / CLI.
- **Console colour** — ANSI colours are enabled automatically on Windows
  10+ consoles (best effort). On an older terminal set `set NO_COLOR=1`
  to get plain output.
- **Baselines** — manifests and baselines store relative paths in
  `/`-style on every OS, so a baseline is readable (and diffable) across
  platforms.
- The setuid/setgid file-system indicator simply never triggers on NTFS
  (the bits do not exist there); everything else is OS-agnostic.
- Scanning system areas (e.g. `C:\Windows`) needs the usual permissions —
  unreadable files are skipped, like on any other OS.

## How detection works

For every regular file (symlinks, build dirs and VCS metadata are skipped):

1. The file is read from disk **exactly once**, streamed in 1 MiB chunks.
   In that single pass the engine computes **SHA-256** and **MD5**, runs
   the **pattern** signatures (with an overlap window so patterns can't
   hide at chunk boundaries) and collects a 256 KiB byte histogram for
   the entropy heuristic. Files larger than `max_file_size` (512 MiB)
   are skipped.
2. If a digest matches a signature, the file is reported as a **definite**
   threat.
3. Otherwise pattern hits are reported.
4. If the file *looks executable* (script extension, shebang, or PE/ELF
   magic), the **behavioural layer** analyses what it appears to do:
   Python sources are parsed with `ast` (never executed), shell/PowerShell/
   batch scripts are checked against indicator regexes, PE images are fully
   dissected (headers, sections, imports, exports, resources, relocations,
   TLS, debug directories) and checked for dangerous API combinations and
   debugger-style red flags, ELF binaries have their dynamic import tables
   (`.dynsym`, both 32- and 64-bit) walked for dangerous API sets, and
   binaries are scanned for reverse-shell / C2 byte markers. Files up to
   2 MiB are analysed (the content was already buffered during the single
   read pass). Run `pe analyze FILE` for the full human-readable
   "debug report".
5. If the file is a **ZIP, TAR or GZIP archive** (up to 32 MiB), each
   entry is read into memory and run through the same layers — a hit is
   reported as `archive.zip!entry` / `archive.tar.gz!member`; suspicious
   entry names (zip-slip / tar-slip), encrypted entries and total
   expansion beyond the 64 MiB budget are flagged. Gzip streams are
   decompressed in memory and, if they contain a TAR, are scanned member
   by member. Nothing is ever extracted to disk.
5b. **Web shield** – the file's bytes are also scanned for `http(s)` /
   `ftp` URLs and each one is scored against the threat-intel blocklist +
   heuristics (shorteners, IP hosts, credentials, executable-looking
   links, backdoor ports). A malicious URL is a high-severity
   `malicious_url` finding, a suspicious one a `suspicious_url`.
5c. **Suspicion engine** – if still nothing matched, the file's risk score
   (document-disguised binaries, double extensions, malware-typical name
   words, random names, suspicious locations, entropy) is computed;
   ≥ 45 is reported as `suspicious` (medium, high at ≥ 70) – the layer
   that lets the guard act on odd new files with no known signature.
6. If still nothing matched, the **heuristic** verdict is made from the
   already-collected histogram: ≥ 7.5 bits/byte on files ≥ 256 KiB is
   reported as "may be packed or encrypted".

   **Scan cache:** before any of the above, a file whose size *and* mtime
   are unchanged since the last scan (and whose engine profile – signature
   DB version, behaviour/entropy/archive/risk/web-shield settings – is the
   same) reuses
   its cached verdict without being read at all. The cache lives in
   `.av-cache` (JSON, atomically written) and is bypassed with
   `--no-cache`; `--fast` runs layers 1–2 only.

### Behavioural indicators (selection)

| Severity | Indicator | Layer |
| --- | --- | --- |
| high | `eval`/`exec` on non-constant (fetched/decoded) input | Python AST |
| high | `socket.connect()` to a hardcoded address | Python AST |
| high | pipe-to-shell: `curl/wget … \| sh`, `base64 -d \| sh` | Shell |
| high | reverse shell: `/dev/tcp`, `nc -e`, `pty.spawn` | Shell / Python |
| high | PowerShell `IEX` + download, `-ExecutionPolicy Bypass` | PowerShell |
| high | LOLBin downloaders: `certutil -urlcache`, `mshta http`, `bitsadmin` | Batch / binary IOC |
| high | PE process-injection API set (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread) | PE imports |
| high | PE imports both download **and** execute APIs | PE imports |
| high | ELF process-execution API set (`system`/`execve`/`popen`) | ELF imports |
| medium | ELF dynamic library loading (`dlopen`/`dlsym`) or raw socket APIs | ELF imports |
| medium | tar-slip entry name (`../x`, absolute) in a TAR/TAR.GZ | archives |
| high | script/LOLBin markers embedded in PE resources (VBScript, PowerShell, `cmd.exe`, `mshta`, …) | PE debug |
| medium | persistence: cron / systemctl / shell rc / registry (`RegSetValue*`) | Shell / PE |
| medium | crypto-mining pool endpoint `stratum+tcp://` | Shell / binary IOC |
| medium | setuid executable | file-system |
| medium | high-entropy PE section / packer section name (UPX0…) | PE sections |
| medium | zip-slip entry name (`../x`, absolute) in a ZIP | archives |
| medium | ZIP total expansion beyond the analysis budget (zip bomb) | archives |
| low | password-protected ZIP entry | archives |
| medium | PE with ASLR off (no `DYNAMIC_BASE`) or DEP off (no `NX_COMPATIBLE`) | PE debug |
| medium | PE with relocations stripped / no base-relocation table, no entry point | PE debug |
| low | PE without debug information, with TLS callbacks, no import table, or huge `.rsrc` | PE debug |
| low | `base64.b64decode`/`pickle.loads`/`CryptDecrypt` payload handling | Python / PE |

Everything in `samples/behavior/` is **inert** demo material (the sample
`.exe` is a code-less, hand-assembled PE whose import table advertises
dangerous APIs – it can never execute).

## Efficiency

The engine is built around one rule: *touch each file once*.

- **Single-pass I/O** – hashing, pattern matching and entropy sampling all
  happen while the file is read once (the previous design re-read files
  2–3 times).
- **One regex for all patterns** – every pattern signature is merged into a
  single compiled alternation, so each 1 MiB buffer is scanned once instead
  of once per signature. (If patterns can't be merged – e.g. clashing
  internal group names – it transparently falls back to per-pattern scans.)
- **One `lstat` per directory entry** – the tree walk is a single
  `os.scandir` pass; the stat result is reused by the scanner and by the
  monitor's snapshot, so nothing is re-stated.
- **Parallel directory scans** – files are scanned in a thread pool
  (`hashlib` releases the GIL while hashing). Use `scan --threads auto`
  (default), `--threads N`, or `--threads 1` for sequential.
- **Cheap monitor polling** – the watcher reuses the same single-`lstat`
  walk and scans bursts of changed files in parallel.
- **Cached signatures** – compiled regexes and hash indexes are cached and
  only rebuilt when the signature database changes.

Measured on a 2 500-file / 266 MiB tree (2-core box, warm page cache):

| Engine | Wall time | Threats found |
| --- | --- | --- |
| v1.0 (2–3 passes per file, sequential) | 0.97 s | 1 of 13* |
| v1.1 sequential (`--threads 1`) | 0.95 s | 13 of 13 |
| v1.1 auto (`--threads auto` → 4 workers) | **0.78 s** | 13 of 13 |

\* v1.0 had a latent bug: the heuristic layer was gated on the tree-wide
findings list, so the first threat silently disabled heuristics for every
later file in a directory scan. Fixed in v1.1.

**Scan cache (v1.5)** — measured on a fresh 1 202-file / 79 MiB tree
(2-core box, Python 3.11):

| Scan | Wall time | Files | Verdicts |
| --- | --- | --- | --- |
| cold full scan (builds the cache) | 4.16 s | 1 202 | 240 |
| **warm rescan (cache hit on every file)** | **0.18 s** | 1 202 (1 202 from cache) | 240 |
| cold `--fast` (hash + pattern only) | 3.04 s | 1 202 | 1 |

A warm rescan is a **~23× speedup** with identical verdicts: unchanged
files are never read from disk (size + mtime + engine-profile check), and
the cache is automatically invalidated when a file changes or the
signature database / engine settings differ.

Quarantine keeps the file under an id like
`275a021bbfb6-20260918-120000-a1b2c3` inside `quarantine/files/`, with the
original path, timestamp and reason recorded in `quarantine/manifest.json`.

## Rescue disk

`antivirus rescue` builds a **self-contained rescue kit** — the whole engine
plus a snapshot of the signature database, shipped as a directory *and* a
standard ISO 9660 image (written by a pure-Python writer — no third-party
disk tooling) — for scanning a machine from outside itself:

```console
$ antivirus rescue build --out ~/usb/kit --iso ~/usb/rescue.iso
==============================================================
 Rescue kit built: /home/user/usb/kit
==============================================================
 Version:        AntiVirus 2.0.0
 Signatures:     51 (signatures.json)
 Files:          29 (SHA-256 manifest)
 ISO image:      /home/user/usb/rescue.iso (136.0 KiB)
```

The kit contains the full `antivirus` package (as `antivirus.zip`, so it
runs from a mounted ISO), its own `signatures.json`, a `run-rescue.py`
runner, a `bootstrap.sh` launcher (Linux/macOS) *and* a `bootstrap.bat`
launcher (Windows), and a `rescue-manifest.json` holding the SHA-256 of
every file — so the media can prove it is not corrupt or tampered with:

```console
$ kit/bootstrap.sh --verify      # "Rescue kit OK"
$ kit/bootstrap.sh --selftest    # the full self test, from the media
$ kit/bootstrap.sh /mnt/disk --action quarantine
```

On Windows the same kit works from a second live Windows environment
(or Windows PE), using the drive letter of the infected volume:

```bat
bootstrap.bat D:\ --action quarantine
```

Typical flow: copy the kit (or burn the ISO) to a USB stick → boot any
live system or VM (Linux or Windows) → make the infected volume visible
→ run the kit against it.

Rescue runs are deliberately different from normal scans:

- **quarantine always goes to the rescue/live side** (CWD or
  `--rescue-quarantine`), never into the volume being scanned;
- **reports always go to the rescue side** (`--rescue-reports`);
- the **scan cache is always disabled** — a rescue must not trust, or
  create, cached state on the suspect machine.

The ISO image is a valid ISO 9660 filesystem (root directory, path
tables, PVD/SVD — verified by the self test), so any OS can mount or burn
it. It is **not** a bootable disc image (that needs a platform
bootloader — out of scope for a stdlib-only package); use it from any
live environment.

```console
$ antivirus rescue build [--out DIR] [--iso FILE | --no-iso]
$ antivirus rescue run TARGET [--action detect|quarantine|kill|delete]
                [--fast] [--since FILE] [--exclude SPEC ...]
                [--rescue-quarantine DIR] [--rescue-reports DIR]
                [--rescue-registry DIR] [--json]
$ antivirus rescue verify KIT
```

Module API: `antivirus.rescue_build(out_dir=..., iso_path=...,
signatures=...)`, `antivirus.run_rescue(target, action=..., ...)` and
`Antivirus.rescue_build(...)`; helpers `antivirus.rescue.verify_kit` and
`build_iso9660`. Web API: `POST /api/rescue/build`, `GET /api/rescue`.

## Kill engine

Beyond **quarantine** (move the file away) and **delete** (destroy it), the
`kill` action **neutralizes a threat in place** — the file stays exactly
where it is, but its bytes are rendered inert:

* **Obfuscation** — the file is XOR-ed with a one-time keystream
  (`SHA-512(key ‖ IV  counter)`, a counter-mode stream cipher built only
  from the standard library). The original binary becomes unreadable,
  non-executable garbage that no longer matches its own SHA-256 signature
  or behavioural patterns.
* **The registry** — the 256-bit **key** and 128-bit **IV** that undo the
  obfuscation are stored in the **AntiVirus registry**
  (`registry/kill.json`), alongside the original hash, the ciphertext hash,
  the path, size, time and the reason it was killed. The registry is the
  single source of recovery material and never touches the scanned volume.

```console
$ antivirus scan C:\downloads --action kill
  [CRITICAL] EICAR-Test-File   (signature-hash)
    file:   C:\downloads\x.txt
    action: killed in place (registry: 275a021bbfb6-…-a1b2c3)

$ antivirus kill list                 # what's neutralized + where its key/IV live
$ antivirus kill revive 275a021bbfb6  # restore the exact original bytes
$ antivirus kill purge 275a021bbfb6   # destroy file + registry entry (final)
```

Because it is built on the same action pipeline as quarantine/delete,
`kill` works everywhere: CLI, module API, web console, TUI, the directory
monitor and rescue runs (where the registry lives on the **live side**,
never on the scanned volume).

Scan improvements that come with it:

* **Registry-aware rescans** — a file that was already killed is counted as
  *neutralized* and is **not re-flagged** (no false positive on the inert
  bytes), so `… | rescan` goes clean.
* **Archive-aware actions** — a threat reported *inside* an archive
  (`bundle.zip!entry`) is neutralized by acting on the **container**, and
  one physical file is acted on only once even if several layers flag it.
* **Per-file threat rollup** — the scan summary adds a ranked
  *Top threats by file* list (worst severity first) on top of the full
  per-finding detail.

> **Security note.** The registry holds the material that *revives* a
> killed file — protect `registry/kill.json` with the same care you'd give
> the key to a safe. Obfuscation here is a neutralization mechanism for a
> detected file, not a general-purpose encryption service.

## Background guard

`antivirus guard` runs continuous protection **in the background**: a
detached daemon watches a directory and scans every file that is created or
modified — no full rescan on demand, nothing to babysit.

```console
$ antivirus guard start ~/downloads --action quarantine
 Guard started in the background (pid 1234)
  target:   ~/downloads
  action:   quarantine   interval: 5s
  state:    guard
  antivirus guard status | antivirus guard log | antivirus guard stop

$ drop suspicious.exe into ~/downloads …

$ antivirus guard status
 Guard running  (pid 1234)
  scanned:  3 new/changed file(s), 1 threat(s)
  last:     quarantined as 9f3c…-20261001-131200-ab12cd

$ antivirus guard log            # recent log lines
[2026-10-01T13:12:00Z] [alert] THREAT [CRITICAL] EICAR-Test-File: …
[2026-10-01T13:12:00Z] [ok] quarantined as 9f3c…

$ antivirus guard stop
```

How it stays lightweight:

* **Stat-only incremental walk** — each poll stats files instead of reading
  them, and a directory whose own timestamp/size is unchanged is *not
  re-listed at all* (its known entries are only stat'ed). A directory is
  re-listed at least every 10 s as a safety net against filesystems with
  coarse or lazily-updated directory timestamps.
* **No initial scan by default** — the first poll only establishes a
  baseline; add `--initial` for one full scan of the tree at startup.
* **No report files** — the daemon keeps a small `guard.log` (rotated at
  1 MiB) and a one-line `guard.json` state; quarantine and the kill registry
  live inside the state dir too, so everything the guard owns is in one
  place (default `./guard`).
* **One detached process** — spawned without a terminal (POSIX: new session
  + `/dev/null` stdio; Windows: `DETACHED_PROCESS | CREATE_NO_WINDOW`), so
  it survives the shell that started it. `guard stop` sends a graceful stop
  sentinel (force-kill only as a last resort); `guard start` refuses while
  a guard is already running for the same state dir.

| Subcommand | What it does |
| --- | --- |
| `guard start [TARGET] [--action detect\|quarantine\|kill\|delete] [--interval 5] [--initial] [--state-dir DIR] [--signatures FILE]` | Start the guard in the background (default target `.`) |
| `guard stop [--state-dir DIR]` | Stop it gracefully (sentinel, then force-kill if stuck) |
| `guard status [--state-dir DIR]` | Running? pid, target, action, counters, last event |
| `guard log [--lines N] [--state-dir DIR]` | Show recent log lines |

## Suspicion engine

Signatures only catch what you already know. The **risk engine** scores how
suspicious a file *looks*, independently of any signature match:

| Signal | Weight |
| --- | --- |
| claims to be a document/image but contains a PE / ZIP / ELF / OLE2 binary | +35 |
| double extension (`invoice.pdf.exe`), +document disguise | +30 (+15) |
| executable / script extension | +12 |
| malware-typical name words (`crack`, `keygen`, `update`, …) | up to +16 |
| random-looking filename (high name entropy) | +8 |
| suspicious parent directory (Downloads, temp, …) | +8 |
| very high entropy ≥ 7.6 bits/byte (packed / encrypted) | +25 |
| executable bit on a "data" file / stub-size `.exe` | +6 |

A file scoring **≥ 45** (`Config.risk_threshold`) produces a `suspicious`
finding (medium, or high at ≥ 70) — and since the scanner emits it like any
other layer, **the background guard quarantines suspicious drops
automatically**, with no known signature involved:

```console
$ antivirus guard start ~/downloads --action quarantine
$ antivirus guard log
[03:09:14Z] [alert] THREAT [HIGH] SuspiciousFile: downloads/invoice.pdf.exe
[03:09:14Z] [ok] quarantined as 7d0d394357eb-…
```

```bash
antivirus risk invoice.pdf.exe
  71/100 [SUSPICIOUS] [##############······]  invoice.pdf.exe
        +30  double extension ('.pdf.exe') - classic disguise
        +15  disguised as a common document type ('.pdf')
        +12  executable/script extension '.exe'
```

## Web shield

The file-scanner half of a web filter: **every file we scan is also read
for URLs** (scripts, notes, PE resource strings – the regex runs on raw
bytes, so it works anywhere), and each URL is scored against a
threat-intel database plus heuristics:

* domain / parent-zone / IP in the **blocklist** → malicious (decisive)
* **URL shorteners** (bit.ly, tinyurl, …) → suspicious
* **IP literal** instead of a domain, **embedded credentials**, `ftp://`
* **executable-looking link** (`…/update.exe`), long random path token
* remote port on a **known backdoor port** (4444, 5555, 31337, …)

Malicious URLs in a file produce a `malicious_url` finding (high),
suspicious ones a `suspicious_url` (medium) — again visible to every
front-end, including the guard.

```bash
antivirus urlcheck http://c2node.evilcorp.invalid/drop/x.exe
  MALICIOUS (100) http://c2node.evilcorp.invalid/drop/x.exe
             - domain 'c2node.evilcorp.invalid' is in the threat-intel blocklist
antivirus urlcheck --from notes.txt    # extract + check every URL in a file
antivirus webshield add my-bad-host.invalid   # extend the blocklist
antivirus webshield show
```

The bundled `data/threat_intel.json` is **educational**: domains use the
reserved `.invalid` / `example` TLDs (RFC 2606 – they can never resolve)
and IPs use reserved documentation ranges. Add real indicators with
`webshield add` (persisted to `intel/user_intel.json`) or a plain-text IOC
import. Web console: `GET /api/webshield?url=…`.

## Firewall

A live **network-connection audit** — a monitor, not a packet filter.
Reading the OS connection table needs no privileges, so it runs as any
user (Linux: `/proc/net/tcp{,6}`; elsewhere: `netstat` fallback):

* **backdoor port** — remote peer on 4444 / 4431 / 5555 / 31337 / 1337 /
  6667 (high)
* **blocklisted IP** — remote peer in the threat-intel IP list (high)
* **risky listener** — telnet, FTP, VNC, RDP, SMB, MS-RPC listening
  (medium)
* **odd outbound port** — established TCP to a non-standard port (low)

```console
$ antivirus firewall scan
Connections:  59 (source: proc)
Intel:        6 domains, 2 IPs, 7 risky ports
Alerts:       none – nothing looks wrong
$ antivirus firewall monitor --interval 5
[14:22:31] [   HIGH]  backdoor_port: remote peer on port 4444 (classic reverse shell / Metasploit default)
             tcp6 10.0.0.5:51234 <-> 192.0.2.10:4444 [ESTABLISHED]
```

Same intel database as the web shield, so `webshield add` feeds both. Web
console: `GET /api/firewall`.

## Performance & comparison

### Detection benchmark (`benchmark`)

`antivirus benchmark` runs the bundled, **fully-labelled sample corpus**
(25 files: EICAR string, behavioural scripts, code-less PE/ELF images,
sneaky archives, disguised doubles, packed blobs, malicious links + clean
documents/images) through the full engine and reports recall and false
positives:

```console
$ antivirus benchmark
 15/15 threats detected, 0 false positives  (0.014 s)
```

The honest framing: on *this* corpus it scores perfectly, which proves the
layers work together and gives you a regression check when you add
signatures or intel. It is **not** a claim of commercial parity — real
detection coverage comes from a large, continuously updated signature and
intelligence base, which this educational engine replaces with *your own*
signatures, IOCs and the heuristic layers above.

### Throughput benchmark (`perf`)

`antivirus perf` measures scan throughput on a synthetic corpus
(three size tiers, 2 KiB / 64 KiB text + 1 MiB binary, plus a few known
threats). It does a **cold** pass (fresh empty cache — every file read +
analysed + recorded) and a **warm** pass (second run, unchanged files
served from the verdict cache), and samples per-file latency:

```console
$ antivirus perf --files 150
 corpus: 455 files / 159.7 MiB
   cold scan :   6.289 s        72.3 files/s      25.39 MB/s   findings 155
   warm scan :   0.037 s     12447.7 files/s    4368.15 MB/s   cached 455
   cache speedup :   172.1x
   per-file latency (single file, cache warm): p50 35.4 ms  p99 42.4 ms  mean 28.2 ms
```

These are real numbers, measured on your machine — use them to tune
`--threads` and to catch regressions. They are **not** a like-for-like
claim against optimized native C++ / kernel antivirus engines, which are a
different category. The headline is the *cache speedup*: rescans of
unchanged files are nearly free, which is exactly what makes the background
`guard` and repeated `verify` runs cheap.

### Per-layer engine report (`engine`)

`antivirus engine FILE` gives a **VirusTotal-style table** for one file:
each detection layer runs as its own "engine" and reports its verdict,
plus a consensus line —

```console
$ antivirus engine eicar-test.txt
 engine     verdict    severity  details
 hash       FLAG       critical  matches 'EICAR-STD-2014' (EICAR-Test-File)
 pattern    FLAG       critical  pattern of 'EICAR-STD-2014' found
 behaviour  clean      info      ...
 url        clean      info      ...
 risk       FLAG       high      score 71/100
 entropy    clean      info      ...
 archive    clean      info      ...
 consensus: detected by 2 of 7 engines
```

The seven "engines" are this tool's layers — `hash`, `pattern`,
`behaviour`, `url` (web shield), `risk` (suspicion engine), `entropy`,
`archive` — shown in the VT style so you can see *which* layers agree. The
file is read once. (They are not 70+ independent third-party AV vendors.)

### How does it stack up? (`compare`)

`antivirus compare` prints the concrete feature set, an honest
positioning table against **AVG (free), Avast (free), Malwarebytes (free)
and VirusTotal**, and live `perf` numbers. Where this tool genuinely
leads: open source & auditable, **zero telemetry** (nothing leaves the
machine), a clean scriptable Python + JSON API, fully offline, and a set
of operational features — guard, kill+revive, FIM baselines, rescue disk,
SIEM-ready export, in-file URL/web shield, no-root firewall audit — in the
free core. Where the commercial engines genuinely lead: **real-world
malware coverage** (huge continuously-updated signature + cloud + ML) and
scale. `antivirus compare` says all of this plainly.

## Command reference

| Command | Description |
| --- | --- |
| `scan TARGET [--action detect\|quarantine\|kill\|delete] [--threads N] [--no-behavior] [--fast] [--no-cache] [--no-archives] [--exclude GLOB] [--since DURATION] [--baseline FILE] [--json]` | Scan a file or directory tree (`--threads`: auto, N, or 1; `--fast`: hash+pattern only; `--exclude` repeatable; `--since 30m/2h/1d`: only recently modified files; `--baseline`: integrity check vs a manifest; `kill`: obfuscate in place, key/IV to the registry) |
| `monitor TARGET [--action ...] [--interval 2] [--no-behavior] [--no-archives] [--exclude GLOB] [--since DURATION] [--json]` | Watch a directory, scan new/changed files (`--json`: one JSON object per event; actions include `kill`) |
| `guard start [TARGET] [--action …] [--interval 5] [--initial] [--state-dir DIR]` | Start the background guard: auto-scan new/changed files, detached, lightweight |
| `guard stop` / `guard status` / `guard log [--lines N]` | Stop / inspect / tail the background guard |
| `risk FILE… [--threshold N] [--json]` | Score how suspicious files *look* (0-100 + reasons, no signatures) |
| `urlcheck URL… [--from FILE] [--json]` | Web shield: check URLs – or every URL found inside a file |
| `webshield show` / `webshield add DOMAIN\|IP\|PORT [--note …]` | View / extend the threat-intel database |
| `firewall scan [--json] [--quiet]` | Live connection audit (no root): backdoor ports, blocklisted IPs, risky listeners |
| `firewall monitor [--interval 5]` | Watch for new suspicious connections |
| `benchmark [--samples DIR] [--json]` | Run the labelled sample corpus: recall + false positives |
| `perf [--files N] [--keep-corpus] [--json]` | Measured throughput: cold vs warm (files/s, MB/s), cache speedup, per-file p50/p99 |
| `engine FILE [--json]` | VirusTotal-style per-layer engine report + "detected by N of M" consensus |
| `compare [--no-perf] [--perf-files N] [--json]` | Honest feature + performance comparison vs AVG / Avast / Malwarebytes / VirusTotal |
| `hash FILE… [--json]` | Print SHA-256 / MD5 / SHA-1 digests + size of each file |
| `behavior analyze FILE [--json]` | Show what one file appears to do (static behavioural analysis) |
| `pe analyze FILE [--json]` | Full static PE dissection ("debug report") + red-flag indicators |
| `gui` | Open the graphical user interface (Tkinter) |
| `quarantine list` | Show everything that is quarantined |
| `quarantine restore ID` | Restore a quarantined file (prefix ok) |
| `quarantine purge ID` | Permanently delete a quarantined file |
| `kill list` | List in-place killed files and their registry entries (key/IV) |
| `kill revive ID` | Restore a killed file's original bytes using the registry's key/IV (prefix ok) |
| `kill purge ID` | Permanently delete a killed file and its registry entry (irreversible) |
| `sig show` | List signatures in the database |
| `sig add --id … --name … [--sha256/--md5/--pattern …]` | Add a signature |
| `sig remove ID` | Remove a signature from the database |
| `sig export FILE` | Write the database to a JSON file |
| `sig import FILE [--source NAME] [--severity LEVEL]` | Merge signatures from a JSON file **or a plain-text IOC file** (hash / `pattern:` / literal lines; skips duplicate ids) |
| `selftest` | Run the built-in end-to-end self test |
| `verify TARGET --baseline FILE [--json]` | Fast integrity check (hash + diff only, no signature scan) vs a manifest |
| `export [REPORT …] [--format csv\|jsonl] [--out FILE]` | Flatten findings from saved reports (default: all) into CSV / JSONL |
| `stats [--no-reports] [--json]` | Engine statistics: signatures, cache, quarantine, reports |
| `report list` / `report show [FILE]` | Inspect saved reports |
| `report diff [OLD NEW] [--json]` | Compare two reports (default: the two newest): new / cleared / unchanged |
| `report summary` | Aggregate all saved reports (counts, severities, top indicators) |
| `manifest TARGET [--out FILE]` | Build a file-integrity baseline (SHA-256 of every file) |
| `samples [DIR]` | Write the inert demo sample tree (safe test material) |
| `web [--host 0.0.0.0] [--port 8420]` | Open the web console (dashboard + JSON API) |
| `tui [TARGET]` | Terminal UI (curses): live scan, findings, options |
| `fileinfo FILE…` | Identify files: type (magic), size, mtime, SHA-256/MD5 |

Common options (most commands): `--signatures FILE`, `--quarantine-dir DIR`,
`--report-dir DIR`, `--registry-dir DIR`, `--max-size BYTES`.

## Using it as a module

Everything is standard-library only, so the package drops straight into
another project — no installation, no dependencies:

```python
import antivirus                      # one-shot, artefacts under ./

result = antivirus.scan("/path/to/scan", fast=True)
print(result.clean, result.worst_severity)
for f in result.findings:             # Finding: severity, name, path, kind, message
    print(f"[{f.severity}] {f.name}  {f.path}")

# --- long-lived engine with its own working area -------------------------
from antivirus import Antivirus

av = Antivirus(base="~/.myapp")       # signatures/cache/reports/quarantine
                                       # /baselines live under ~/.myapp
result = av.scan("some/dir", action="quarantine")
print(result.notes)                   # {path: "quarantined as …"}

av.add_signature(id="AV-MINE-001", name="Mine",
                 pattern="UNIQUE-MARKER", severity="high")
av.scan_file("suspicious.bin")        # -> [Finding, …]
av.file_info("suspicious.bin")        # type (magic), size, mtime, sha256, md5
baseline = av.manifest("some/dir")    # integrity baseline (dict)
av.save_manifest(baseline, "baseline.json")
av.verify("some/dir", "baseline.json")   # fast hash-only diff -> [Finding, …]
av.risk("invoice.pdf.exe")            # -> {score, suspicious, reasons}
av.check_url("http://c2node.evilcorp.invalid/x")  # web shield verdict
av.extract_urls(data)                 # every URL found in bytes
av.firewall_scan()                    # live connections + alerts (no root)
av.threat_intel().add_domain("bad.host")  # extend the blocklist
av.quarantine.restore("275a021b-…")
av.remove_signature("AV-MINE-001")

# --- kill engine (neutralize in place, key/IV in the registry) -------------
result = av.scan("some/dir", action="kill")
print(result.notes)                     # {path: "killed in place (registry: …)"}
for entry in av.kill_list():            # what's neutralized + its key/IV
    print(entry.id, entry.original_path)
av.kill_revive("275a021b-…")            # restore the exact original bytes
av.kill_purge("275a021b-…")             # destroy file + registry entry

# --- rescue disk -----------------------------------------------------------
manifest = antivirus.rescue_build(out_dir="/usb/kit",
                                  iso_path="/usb/rescue.iso")
info = antivirus.run_rescue("/mnt/infected-disk", action="quarantine",
                            quarantine_dir="/usb/rescue-quarantine",
                            report_dir="/usb/rescue-reports")
print(info["result"].clean, info["report"])
```

Plain-text IOC lists import through the same database:
`antivirus sig import feed.txt --source feed --severity high` turns 64-hex
lines into SHA-256 signatures, 32-hex lines into MD5 signatures, and any
other line into a literal-marker pattern — the very next scan picks them up.

`antivirus.scan` returns a `ScanResult` (see `antivirus.scanner`) and
`av.scan` additionally carries a `notes` attribute for applied actions.
The same components back the CLI, GUI, TUI and web console, so behaviour
is identical in every front-end.

## Web console

```bash
python3 -m antivirus web --port 8420
# then open http://localhost:8420
```

The dashboard (single page, no external assets, dark theme) offers:

- **Scan jobs** — target + action (detect / quarantine / kill / delete),
  `fast` / `since` options and an integrity-baseline selector; each scan
  runs in a background thread and the UI polls **live progress and a
  running findings feed**. Past jobs stay clickable in the job list.
- **Results with text filter** — filter findings by name / file / kind /
  detail while they stream in.
- **Quick file check** — type any file path: type (magic), size, mtime,
  SHA-256/MD5 plus a single-file mini-scan.
- **Integrity baselines** — create a manifest from the current target and
  scan against it (changed / missing / new files); the **verify (fast)**
  button runs the cheaper hash-only diff instead of a full scan.
- **Report history** — saved-report summary + latest reports.
- **Engine stats** — live signature / cache / quarantine / report totals.
- **Quarantine manager** — list, restore or purge quarantined files.
- **Signature editor** — add (pattern / sha256 / md5), inspect and remove
  signatures; changes apply to the very next scan.
- **API docs** — the JSON API is documented in-browser at `/api/docs`.

JSON API (useful for scripting / your own front-end):

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/health` | GET | engine status + version |
| `/api/scan` | POST | start a job: `{"target", "action", "fast", "no_archives", "since", "baseline"}` |
| `/api/jobs` | GET | all jobs (summary) |
| `/api/jobs/<id>` | GET | job progress + `findings_preview` (live) + full result when done |
| `/api/quarantine` | GET | quarantined items |
| `/api/quarantine/restore` / `/api/quarantine/purge` | POST | `{"id"}` |
| `/api/signatures` | GET / POST | list / add signatures |
| `/api/signatures/remove` | POST | `{"id"}` |
| `/api/baselines` | GET / POST | list / create integrity baselines (`{"target", "id?"}`) |
| `/api/fileinfo` | GET | `?path=…` — type, size, mtime, SHA-256/MD5 + single-file findings |
| `/api/reports` / `/api/reports/summary` | GET | saved reports / aggregate |
| `/api/verify` | GET | `?target=&baseline=` — fast integrity check (hash + diff only) |
| `/api/stats` | GET | engine statistics (signatures, cache, quarantine, reports) |
| `/api/rescue/build` | POST | `{"out"?, "iso"?}` — build the rescue kit + ISO image |
| `/api/rescue` | GET | last rescue build (404 until one exists) |
| `/api/kill` | GET | kill registry — in-place killed files + stored key/IV |
| `/api/kill/revive` | POST | `{"id"}` — restore a killed file's original bytes |
| `/api/kill/purge` | POST | `{"id"}` — destroy a killed file and its registry entry |
| `/api/webshield` | GET | `?url=…` (repeatable) — URL verdicts; no URL: the threat-intel DB |
| `/api/firewall` | GET | live connection snapshot + security alerts |
| `/api/docs` | GET | in-browser API documentation |

The console binds to `0.0.0.0` by default and has **no authentication** —
it is a local tool, so only expose it on interfaces you trust.

## Terminal UI

```bash
python3 -m antivirus tui            # or: tui /path/to/scan
```

> **Windows:** CPython does not bundle `curses`, so there is no TUI on
> Windows — `antivirus tui` tells you so and points to the web console.
> Everything else (CLI, GUI, web, rescue) works there.

A curses screen (standard library, Unix-like systems) with a live
progress line, a scrollable severity-coloured findings list (findings
appear while the scan runs) and per-finding detail. Keys: `s` scan,
`e` edit target, `j/k` move, `g/G` top/bottom, `t` fast, `a` cycle
action (detect → quarantine → kill → delete), `f` incremental window,
`?` help, `q` quit. The TUI shares the web console's job engine, so every
feature (quarantine, the kill engine, signatures, baselines) works
identically in all front-ends.

## Project layout

```
antivirus/
├── __init__.py      # package metadata + module API exports
├── __main__.py      # python3 -m antivirus
├── api.py           # high-level module API (Antivirus, scan, scan_file)
├── cli.py           # argparse CLI + console output
├── gui.py           # Tkinter graphical interface (python3 -m antivirus gui)
├── tui.py           # curses terminal UI (model + renderer)
├── web.py           # web console (dashboard + JSON API, http.server)
├── config.py        # all tunables in one dataclass
├── models.py        # Finding dataclass + entropy helpers
├── cache.py         # scan cache (fast rescans of unchanged files)
├── behavior.py      # behavioural analysis (Python AST, shell/PS/batch,
│                    #   PE/ELF import tables, binary IOCs, SUID)
├── pe.py            # PE32/PE32+ dissection ("debug report") + indicators
├── fileinfo.py      # file identification (magic + digests)
├── integrity.py     # file-integrity baselines (manifest + diff + fast verify)
├── kill.py          # kill engine: in-place obfuscation cipher + registry
├── rescue.py        # rescue kit + ISO 9660 writer + rescue scan runner
├── samples.py       # builder for the inert demo samples (fake PE/ELF,
│                    #   sneaky ZIP/TAR.GZ, `samples` tree)
├── scanner.py       # single-pass hashing, patterns, behaviour, heuristics
├── signatures.py    # JSON signature database (load/add/save) + IOC parser
├── quarantine.py    # quarantine store with manifest, restore, purge
├── monitor.py       # polling directory watcher (structured events,
│                    #   incremental cached walk for the guard)
├── guard.py         # background guard: detached daemon + start/stop/status
├── risk.py          # suspicion engine: 0-100 risk score per file
├── webshield.py     # web shield: URL extraction + reputation scoring
├── firewall.py      # live connection-table audit (no root needed)
├── benchmark.py     # labelled-corpus detection benchmark
├── engine.py        # VirusTotal-style per-layer engine report (consensus)
├── perf.py          # measured throughput benchmark (cold/warm + latency)
├── compare.py       # honest feature + positioning comparison
├── report.py        # JSON + text report writer, diff, summary, export
├── selftest.py      # built-in end-to-end self test
├── output.py        # tiny ANSI colour helper
└── utils.py         # shared helpers
data/
├── signatures.json    # bundled signature database (EICAR test string)
└── threat_intel.json  # bundled threat intel (blocklist domains/IPs/ports)
samples/
├── eicar-test.txt     # the standard 68-byte harmless AV test string
├── clean.txt
├── behavior/          # inert behavioural demo samples (scripts + fake PE)
├── suspicious/        # risk-engine + web-shield corpus (inert)
└── clean/             # labelled-clean corpus (images, CSV, notes, script)
tests/
└── test_antivirus.py
```

## Running the tests

```bash
python3 -m unittest discover -s tests -v   # stdlib only
# or, if you have pytest:
python3 -m pytest -v
```

## Extending it

- **New signature source** — `SignatureDB` is just JSON; write a script that
  merges upstream hashes into `data/signatures.json` (a "live update" would
  be a natural next step).
- **Real-time monitoring** — swap `DirectoryWatcher` for
  [`watchdog`](https://pypi.org/project/watchdog/)/inotify events; the
  `_handle()` logic stays identical.
- **Behaviour-based layers** — e.g. flag scripts that `exec` encoded blobs,
  detect suspicious PE/ELF sections, scan inside 7z archives, or go beyond
  static ELF/PE analysis (dynamic sandboxing).

## License

[MIT](LICENSE)
