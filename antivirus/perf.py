"""Performance benchmark: real, reproducible scan throughput numbers (v2.5).

Builds a synthetic corpus of clean files (text + binary, in three size
tiers) plus a few known threats, then measures:

* **cold scan**  – fresh, empty verdict cache, so every file is read
  + analysed and recorded
* **warm scan**  – second pass: unchanged files served from the verdict
  cache without being read
* **per-file latency** – p50 / p99 of individual ``scan_file`` calls

Everything is reported as measured on *this* machine.  These numbers are
for tuning and regression checks, not a claim of superiority over
commercial engines (which run optimized C++ / kernel code and are not
directly comparable) – the honest framing is in the CLI/README.
"""
from __future__ import annotations

import random
import statistics
import time
from pathlib import Path
from typing import Dict, List, Optional

from .config import Config
from .scanner import Scanner
from .signatures import SignatureDB

#: (name, size, kind) tiers used to build the corpus.
_TIERS = (
    ("small", 2 * 1024, "text"),
    ("medium", 64 * 1024, "text"),
    ("large", 1 * 1024 * 1024, "binary"),
)

_EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _text(size: int, seed: int) -> bytes:
    rng = random.Random(seed)
    words = [b"the", b"quick", b"brown", b"fox", b"jumps", b"over",
             b"lazy", b"dog", b"pack", b"box", b"widget", b"gadget"]
    out = bytearray()
    while len(out) < size:
        out += rng.choice(words) + b" "
    return bytes(out[:size])


def _binary(size: int, seed: int) -> bytes:
    import os as _os

    return _os.urandom(size)  # high-entropy filler; fast to generate


def build_corpus(root: Path, files_per_tier: int) -> List[Path]:
    """Create the synthetic corpus; returns the list of written files."""
    root = Path(root)
    written: List[Path] = []
    i = 0
    for tier_name, size, kind in _TIERS:
        d = root / tier_name
        d.mkdir(parents=True, exist_ok=True)
        for n in range(files_per_tier):
            p = d / f"file-{i:05d}.{'bin' if kind == 'binary' else 'txt'}"
            blob = _binary(size, seed=1000 + i) if kind == "binary" \
                else _text(size, seed=2000 + i)
            p.write_bytes(blob)
            written.append(p)
            i += 1
    # A few known threats so the detection layers are exercised too.
    threats = root / "threats"
    threats.mkdir(exist_ok=True)
    for n in range(5):
        (threats / f"eicar-{n}.txt").write_bytes(_EICAR)
        written.append(threats / f"eicar-{n}.txt")
    return written


def _percentile(values: List[float], pct: float) -> float:
    if not values:
        return 0.0
    values = sorted(values)
    k = (len(values) - 1) * pct
    f = int(k)
    c = min(f + 1, len(values) - 1)
    return values[f] + (values[c] - values[f]) * (k - f)


def run(corpus_dir: Optional[Path] = None, files_per_tier: int = 400,
        config: Optional[Config] = None,
        signatures_file: Optional[Path] = None,
        keep_corpus: bool = True) -> Dict:
    """Run the full perf benchmark; returns a JSON-friendly result dict.

    When a corpus is auto-generated (no ``corpus_dir``) it is removed at the
    end unless ``keep_corpus`` is true, so repeated runs don't fill /tmp.
    """
    auto_corpus = False
    if corpus_dir is not None and Path(corpus_dir).is_dir():
        corpus = Path(corpus_dir)
        files = sorted(p for p in corpus.rglob("*") if p.is_file())
    else:
        import tempfile
        corpus = Path(tempfile.mkdtemp(prefix="av-perf-"))
        auto_corpus = True
        build_corpus(corpus, files_per_tier)
        files = sorted(p for p in corpus.rglob("*") if p.is_file())

    config = config or Config()
    config.quarantine_dir = corpus / ".q"
    config.report_dir = corpus / ".r"
    if signatures_file:
        config.signatures_file = signatures_file
    # A private, fresh cache: the cold run starts with an empty cache, so
    # every file is read + analysed, and the run records verdicts that the
    # warm run then serves.
    config.cache_dir = corpus / ".av-cache-perf"
    config.cache_enabled = True
    db = SignatureDB(config.signatures_file)
    scanner = Scanner(config, db)

    total_bytes = sum(p.stat().st_size for p in files)

    # ---- cold scan (empty cache: every file read + analysed) ------------
    t0 = time.perf_counter()
    cold = scanner.scan_path(corpus)
    cold_elapsed = time.perf_counter() - t0

    # ---- warm scan (cache populated: unchanged files served, no reads) --
    t1 = time.perf_counter()
    warm = scanner.scan_path(corpus)
    warm_elapsed = time.perf_counter() - t1

    # ---- per-file latency (individual scan_file calls) ------------------
    sample = files[: min(200, len(files))]
    latencies: List[float] = []
    for p in sample:
        t2 = time.perf_counter()
        scanner.scan_file(p)
        latencies.append(time.perf_counter() - t2)

    def mb(s: float) -> float:
        return round(total_bytes / (1024 * 1024), 1)

    def rate(n: int, secs: float, unit: str) -> float:
        return round(n / secs, 1) if secs > 0 else 0.0

    result = {
        "corpus": str(corpus),
        "files": len(files),
        "bytes": total_bytes,
        "megabytes": mb(0),
        "cold": {
            "seconds": round(cold_elapsed, 3),
            "files_per_sec": rate(cold.files_scanned, cold_elapsed, "f"),
            "mb_per_sec": round(total_bytes / 1048576 / cold_elapsed, 2)
            if cold_elapsed > 0 else 0.0,
            "findings": len(cold.findings),
        },
        "warm": {
            "seconds": round(warm_elapsed, 3),
            "files_per_sec": rate(warm.files_scanned, warm_elapsed, "f"),
            "files_cached": warm.files_cached,
            "mb_per_sec": round(total_bytes / 1048576 / warm_elapsed, 2)
            if warm_elapsed > 0 else 0.0,
            "findings": len(warm.findings),
        },
        "cache_speedup": round(cold_elapsed / warm_elapsed, 1)
        if warm_elapsed > 0 else 0.0,
        "per_file_latency_s": {
            "sample": len(sample),
            "p50_ms": round(_percentile(latencies, 0.50) * 1000, 2),
            "p99_ms": round(_percentile(latencies, 0.99) * 1000, 2),
            "mean_ms": round(statistics.mean(latencies) * 1000, 2),
        } if latencies else {},
        "corpus_auto": auto_corpus,
    }
    if auto_corpus and not keep_corpus:
        import shutil as _shutil
        _shutil.rmtree(corpus, ignore_errors=True)
        result["corpus"] = "(removed)"
    return result


def summary_line(result: Dict) -> str:
    c, w = result["cold"], result["warm"]
    return (f"{result['files']} files / {result['megabytes']} MiB – "
            f"cold {c['files_per_sec']} files/s "
            f"({c['mb_per_sec']} MB/s), "
            f"warm {w['files_per_sec']} files/s "
            f"({w['files_cached']} served from cache), "
            f"{result['cache_speedup']}× cache speedup")
