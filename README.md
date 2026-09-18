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

- **Three detection layers**
  1. *Hash* — SHA-256 (plus MD5) of each file vs. the signature database
  2. *Pattern* — regular expressions matched against raw file bytes
     (catches renamed/wrapped variants)
  3. *Heuristic* — Shannon-entropy check that flags large packed/encrypted
     files
- **Quarantine** — infected files are moved to a sandboxed directory with a
  JSON manifest; list, restore or purge them later
- **Directory monitor** — polls a tree and scans every new/changed file
- **Reports** — every scan writes a JSON report and a human-readable text
  report
- **Signature editor** — add your own signatures from the CLI (hash or
  pattern)
- **Self test** — built-in end-to-end test using the harmless EICAR string

## Requirements

- Python 3.9+ — that's it. No third-party packages.

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

## How detection works

For every regular file (symlinks, build dirs and VCS metadata are skipped):

1. The file is streamed in 1 MiB chunks through **SHA-256** and **MD5**.
   Files larger than `max_file_size` (512 MiB) are skipped.
2. If a digest matches a signature, the file is reported as a **definite**
   threat and scanning of that file stops.
3. Otherwise the file is read again in chunks (with an overlap window so
   patterns can't hide at chunk boundaries) and tested against every
   **pattern** signature.
4. If still nothing matched, the **heuristic** layer computes the Shannon
   entropy of up to a 2 MiB sample; ≥ 7.5 bits/byte on files ≥ 256 KiB is
   reported as "may be packed or encrypted".

Quarantine keeps the file under an id like
`275a021bbfb6-20260918-120000-a1b2c3` inside `quarantine/files/`, with the
original path, timestamp and reason recorded in `quarantine/manifest.json`.

## Command reference

| Command | Description |
| --- | --- |
| `scan TARGET [--action detect\|quarantine\|delete] [--json]` | Scan a file or directory tree |
| `monitor TARGET [--action ...] [--interval 2]` | Watch a directory, scan new/changed files |
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
├── config.py        # all tunables in one dataclass
├── scanner.py       # hashing, pattern + heuristic detection, tree walk
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
└── clean.txt
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
