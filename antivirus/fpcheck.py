"""False-positive audit – measure the indicator library against clean data.

A detection library is only useful if it stays quiet on ordinary files.  A
pattern like ``scp`` is a legitimate lateral-movement signal *and* three
random bytes in a JPEG, so every indicator must be measured against
corpora that contain no malicious intent:

* random binary blobs (the worst case: tool names appear in compressible
  noise, and a coincidence there is a pure false positive)
* random ASCII words
* real source code in several languages
* realistic administration scripts (PowerShell, Bash, batch)
* documentation / README text

``antivirus fpcheck`` runs exactly that audit and exits non-zero when the
false-positive rate exceeds a budget, so it can gate a release in CI.  The
same machinery is used during development – the numbers it prints are the
ones quoted in the README.

Two knobs matter:

``--budget``   the maximum share of *files* that may be flagged at all
               (default 0: one clean file flagged is already one too many
               for a random blob, but scripts are allowed the low/medium
               findings flagged by design)
``--severity`` findings below this severity are ignored when counting
"""
from __future__ import annotations

import os
import random
import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

#: Words used to build pseudo-random "prose" (deliberately bland).
_PROSE_WORDS = (
    "the quick brown fox jumps over a lazy dog system process file network "
    "service update install window server error report machine client user "
    "configuration directory request response session timeout memory cache "
    "table index value record version history comment message queue"
).split()

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

#: Benign corpora that any indicator must tolerate.  Each entry is
#: ``(label, filename, content)``.
_BENIGN_SCRIPTS: Tuple[Tuple[str, str, bytes], ...] = (
    ("python", "app.py", b'''
"""Small internal service - nothing malicious here."""
import base64
import json
import os
import socket
import subprocess
import sys

TOKEN = os.environ.get("API_TOKEN", "")


def run(cmd):
    """Run a helper command and fail loudly."""
    return subprocess.run(cmd, shell=False, check=True, capture_output=True)


class Client:
    def __init__(self, host: str, port: int = 8443) -> None:
        self.host = host
        self.port = port
        self.sock = None

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=5)
        return self.sock

    def encode(self, payload: bytes) -> str:
        return base64.b64encode(payload).decode("ascii")


def load_config(path: str = "data.json") -> dict:
    with open(path, "rb") as fh:
        return json.load(fh)


if __name__ == "__main__":
    run(["git", "status", "--short"])
    print(sys.version)
'''),
    ("shell", "deploy.sh", b'''#!/bin/bash
# Deployment helper: sync the build output and restart the service.
set -euo pipefail

SRC="${1:-./dist}"
DEST="/srv/app"
LOGFILE="/var/log/deploy.log"

log() { printf '%s %s\\n' "$(date -Is)" "$*" | tee -a "$LOGFILE"; }

log "stopping service"
systemctl stop app.service || true

log "syncing $SRC -> $DEST"
rsync -a --delete "$SRC/" "$DEST/"

log "fixing permissions"
find "$DEST" -type d -exec chmod 755 {} +
find "$DEST" -type f -exec chmod 644 {} +

log "starting service"
systemctl start app.service
curl -fsS http://127.0.0.1:8080/healthz || log "health check failed"
log "done"
'''),
    ("batch", "backup.bat", b'''@echo off
rem Nightly backup helper for a Windows file server.
setlocal enabledelayedexpansion
set STAMP=%DATE:~-4%%DATE:~3,2%%DATE:~0,2%
set DEST=\\\\fileserver\\backups\\%STAMP%
if not exist "%DEST%" mkdir "%DEST%"
echo Backing up user shares to %DEST%
robocopy "D:\\Shares" "%DEST%" /MIR /R:2 /W:2 /LOG+:"%TEMP%\\backup-%STAMP%.log"
if %ERRORLEVEL% GEQ 8 (
  echo Backup failed with code %ERRORLEVEL%
  exit /b 1
)
echo Backup finished at %TIME%
endlocal
'''),
    ("powershell", "inventory.ps1", b'''<#
.SYNOPSIS
    Collect a simple hardware inventory and write it as JSON.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "$env:TEMP\\inventory.json",
    [string[]]$ComputerName = @($env:COMPUTERNAME)
)

$results = foreach ($computer in $ComputerName) {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $computer
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $computer
        [pscustomobject]@{
            Computer     = $computer
            OperatingSystem = $os.Caption
            Version      = $os.Version
            Manufacturer = $cs.Manufacturer
            MemoryGB     = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        }
    } catch {
        Write-Warning "Could not reach $computer : $_"
    }
}

$results | ConvertTo-Json -Depth 4 | Set-Content -Path $OutputPath
Write-Host "Wrote inventory for $($results.Count) system(s) to $OutputPath"
'''),
    ("docs", "README.md", b'''# Internal tools

This repository collects the small utilities our team uses day to day.
Nothing here is security software; it is glue code for deployments.

## Layout

* `bin/` - shell entry points
* `src/` - python packages
* `docs/` - notes and runbooks

## Deploying

Run `make deploy` after the CI pipeline has published the artefacts.  The
deployment script stops the service, syncs the build output and starts it
again.  Rollback instructions live in `docs/runbook.md`.

## Support

Ping #platform-help on Slack, or open a ticket.  Please do not run these
tools as root unless the runbook says to.
'''),
    ("json", "package.json", b'''{
  "name": "internal-tools",
  "version": "2.4.1",
  "private": true,
  "description": "Internal glue scripts",
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "test": "jest --ci --coverage"
  },
  "dependencies": {
    "express": "^4.19.2",
    "lodash": "^4.17.21"
  },
  "devDependencies": {
    "typescript": "^5.4.5",
    "jest": "^29.7.0"
  }
}''' ),
)


@dataclass
class FPHit:
    corpus: str
    file: str
    check: str
    severity: str
    message: str = ""

    def to_dict(self) -> dict:
        return {"corpus": self.corpus, "file": self.file, "check": self.check,
                "severity": self.severity, "message": self.message}


@dataclass
class FPReport:
    blobs: int = 0
    blob_size: int = 0
    seed: int = 0
    counts: Dict[str, int] = field(default_factory=dict)
    hits: List[FPHit] = field(default_factory=list)
    per_corpus: Dict[str, int] = field(default_factory=dict)
    total_files: int = 0
    flagged_files: int = 0
    min_severity: str = "info"
    elapsed: float = 0.0

    @property
    def clean(self) -> bool:
        return not self.hits

    @property
    def rate(self) -> float:
        return (self.flagged_files / self.total_files) if self.total_files else 0.0

    def to_dict(self) -> dict:
        return {
            "blobs": self.blobs, "blob_size": self.blob_size, "seed": self.seed,
            "files": self.total_files, "flagged_files": self.flagged_files,
            "false_positive_rate": round(self.rate, 6),
            "min_severity": self.min_severity,
            "by_check": dict(self.counts), "by_corpus": dict(self.per_corpus),
            "hits": [h.to_dict() for h in self.hits],
            "clean": self.clean, "elapsed_seconds": round(self.elapsed, 3),
        }

    def summary(self) -> str:
        if self.clean:
            return (f"clean: {self.total_files} file(s) audited, no indicator "
                    f"reached {self.min_severity} severity")
        top = ", ".join(f"{name}×{count}"
                        for name, count in Counter(self.counts).most_common(5))
        return (f"{self.flagged_files}/{self.total_files} file(s) flagged "
                f"({self.rate:.2%}) – {top}")


def _indicator_scan(name: str, data: bytes) -> List[Tuple[str, str, str]]:
    """Run the indicator library over one buffer."""
    from . import indicators

    try:
        findings = indicators.analyze(name, data, filename=name)
    except Exception as exc:  # a detector must never crash the auditor
        return [(f"<error {exc}>", "info", "")]
    return [(f.name, f.severity, f.message) for f in findings]


def audit_blobs(*, blobs: int = 150, size: int = 300 * 1024,
                seeds: Iterable[int] = (1, 7, 20261015),
                min_severity: str = "info") -> FPReport:
    """Random-binary corpus: the strictest possible false-positive test."""
    report = FPReport(blobs=blobs * len(list(seeds)), blob_size=size,
                      min_severity=min_severity)
    threshold = _SEVERITY_RANK.get(min_severity, 0)
    for seed in seeds:
        random.seed(seed)
        for index in range(blobs):
            blob = os.urandom(size)
            name = f"blob-{seed}-{index}.bin"
            report.total_files += 1
            hits = _indicator_scan(name, blob)
            report.per_corpus["random-binary"] = \
                report.per_corpus.get("random-binary", 0) + 1
            kept = [(c, s, m) for c, s, m in hits
                    if _SEVERITY_RANK.get(s, 0) >= threshold]
            if kept:
                report.flagged_files += 1
                for check, severity, message in kept:
                    report.counts[check] = report.counts.get(check, 0) + 1
                    report.hits.append(FPHit("random-binary", name, check,
                                             severity, message))
    return report


def audit_text(*, sources: Optional[List[Tuple[str, str, bytes]]] = None,
               min_severity: str = "info") -> FPReport:
    """Text corpus: pseudo-random prose, source code, docs and configs."""
    report = FPReport(min_severity=min_severity)
    threshold = _SEVERITY_RANK.get(min_severity, 0)
    corpora: List[Tuple[str, str, bytes]] = []
    random.seed(4242)
    prose = " ".join(random.choice(_PROSE_WORDS) for _ in range(40_000))
    corpora.append(("random-text", "prose.txt", prose.encode()))
    corpora.extend(_BENIGN_SCRIPTS)
    if sources:
        corpora.extend(sources)
    for label, name, data in corpora:
        report.total_files += 1
        report.per_corpus[label] = report.per_corpus.get(label, 0) + 1
        kept = [(c, s, m) for c, s, m in _indicator_scan(name, data)
                if _SEVERITY_RANK.get(s, 0) >= threshold]
        if kept:
            report.flagged_files += 1
            for check, severity, message in kept:
                report.counts[check] = report.counts.get(check, 0) + 1
                report.hits.append(FPHit(label, name, check, severity, message))
    return report


def run(*, blobs: int = 150, size: int = 300 * 1024,
        seeds: Iterable[int] = (1, 7, 20261015), min_severity: str = "info",
        blobs_only: bool = False, text_only: bool = False) -> FPReport:
    """Both corpora, merged into one report."""
    import time as _time

    started = _time.time()
    parts: List[FPReport] = []
    if not text_only:
        parts.append(audit_blobs(blobs=blobs, size=size, seeds=seeds,
                                 min_severity=min_severity))
    if not blobs_only:
        parts.append(audit_text(min_severity=min_severity))
    merged = FPReport(blobs=sum(p.blobs for p in parts),
                      blob_size=size, seed=int(list(seeds)[0]) if seeds else 0,
                      min_severity=min_severity)
    for part in parts:
        merged.total_files += part.total_files
        merged.flagged_files += part.flagged_files
        merged.hits.extend(part.hits)
        for key, value in part.counts.items():
            merged.counts[key] = merged.counts.get(key, 0) + value
        for key, value in part.per_corpus.items():
            merged.per_corpus[key] = merged.per_corpus.get(key, 0) + value
    merged.elapsed = _time.time() - started
    return merged


def corpus_summary() -> List[Tuple[str, str, int]]:
    """``(label, file name, size)`` for every static benign corpus file."""
    return [(label, name, len(data)) for label, name, data in _BENIGN_SCRIPTS]


def main(argv: Optional[List[str]] = None) -> int:  # pragma: no cover
    """Tiny standalone entry point (the CLI wires ``antivirus fpcheck``)."""
    argv = list(sys.argv[1:] if argv is None else argv)
    blobs = 20 if "--quick" in argv else 150
    report = run(blobs=blobs)
    print(report.summary())
    return 0 if report.clean else 1
