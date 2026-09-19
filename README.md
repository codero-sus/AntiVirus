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
  * *ELF binaries* — high-entropy loadable segments
  * *File-system* — setuid/setgid executables
- **Static heuristic** — Shannon-entropy check that flags large
  packed/encrypted files
- **Quarantine** — infected files are moved to a sandboxed directory with a
  JSON manifest; list, restore or purge them later
- **Directory monitor** — polls a tree and scans every new/changed file
- **Reports** — every scan writes a JSON report and a human-readable text
  report
- **Signature editor** — add your own signatures from the CLI (hash or
  pattern)
- **Self test** — built-in end-to-end test using the harmless EICAR string
- **Graphical UI** — Tkinter desktop app (standard library, no extra
  packages): pick a target, scan with live progress and a stop button,
  review severity-coloured findings, and manage the quarantine
  (`python3 -m antivirus gui`)

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

# 3. Scan and quarantine threats
python3 -m antivirus scan . --action quarantine

# 4. See what was quarantined, put it back, or destroy it for good
python3 -m antivirus quarantine list
python3 -m antivirus quarantine restore 275a021bbfb6
python3 -m antivirus quarantine purge 275a021bbfb6

# 5. Watch a folder in (near) real time
python3 -m antivirus monitor . --action quarantine

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
   debugger-style red flags, and binaries are scanned for reverse-shell /
   C2 byte markers. Files up to 2 MiB are analysed (the content was already
   buffered during the single read pass). Run
   `pe analyze FILE` for the full human-readable "debug report".
5. If still nothing matched, the **heuristic** verdict is made from the
   already-collected histogram: ≥ 7.5 bits/byte on files ≥ 256 KiB is
   reported as "may be packed or encrypted".

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
| high | script/LOLBin markers embedded in PE resources (VBScript, PowerShell, `cmd.exe`, `mshta`, …) | PE debug |
| medium | persistence: cron / systemctl / shell rc / registry (`RegSetValue*`) | Shell / PE |
| medium | crypto-mining pool endpoint `stratum+tcp://` | Shell / binary IOC |
| medium | setuid executable | file-system |
| medium | high-entropy PE section / packer section name (UPX0…) | PE sections |
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

Quarantine keeps the file under an id like
`275a021bbfb6-20260918-120000-a1b2c3` inside `quarantine/files/`, with the
original path, timestamp and reason recorded in `quarantine/manifest.json`.

## Command reference

| Command | Description |
| --- | --- |
| `scan TARGET [--action detect\|quarantine\|delete] [--threads N] [--no-behavior] [--json]` | Scan a file or directory tree (`--threads`: auto, N, or 1) |
| `monitor TARGET [--action ...] [--interval 2] [--no-behavior]` | Watch a directory, scan new/changed files |
| `behavior analyze FILE [--json]` | Show what one file appears to do (static behavioural analysis) |
| `pe analyze FILE [--json]` | Full static PE dissection ("debug report") + red-flag indicators |
| `gui` | Open the graphical user interface (Tkinter) |
| `quarantine list` | Show everything that is quarantined |
| `quarantine restore ID` | Restore a quarantined file (prefix ok) |
| `quarantine purge ID` | Permanently delete a quarantined file |
| `sig show` | List signatures in the database |
| `sig add --id … --name … [--sha256/--md5/--pattern …]` | Add a signature |
| `selftest` | Run the built-in end-to-end self test |
| `report list` / `report show [FILE]` | Inspect saved reports |

Common options (most commands): `--signatures FILE`, `--quarantine-dir DIR`,
`--report-dir DIR`, `--max-size BYTES`.

## Project layout

```
antivirus/
├── __init__.py      # package metadata
├── __main__.py      # python3 -m antivirus
├── cli.py           # argparse CLI + console output
├── gui.py           # Tkinter graphical interface (python3 -m antivirus gui)
├── config.py        # all tunables in one dataclass
├── models.py        # Finding dataclass + entropy helpers
├── behavior.py      # behavioural analysis (Python AST, shell/PS/batch,
│                    #   ELF structure, binary IOCs, SUID)
├── pe.py            # PE32/PE32+ dissection ("debug report") + indicators
├── samples.py       # builder for the inert demo samples (incl. fake PEs)
├── scanner.py       # single-pass hashing, patterns, behaviour, heuristics
├── signatures.py    # JSON signature database (load/add/save)
├── quarantine.py    # quarantine store with manifest, restore, purge
├── monitor.py       # polling directory watcher
├── report.py        # JSON + text report writer
├── selftest.py      # built-in end-to-end self test
├── output.py        # tiny ANSI colour helper
└── utils.py         # shared helpers
data/
└── signatures.json  # bundled signature database (EICAR test string)
samples/
├── eicar-test.txt   # the standard 68-byte harmless AV test string
├── clean.txt
└── behavior/        # inert behavioural demo samples (scripts + fake PE)
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
  detect suspicious PE/ELF sections, scan inside ZIP/7z archives.

## License

[MIT](LICENSE)
