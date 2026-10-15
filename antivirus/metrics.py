"""Cumulative engine metrics (v2.8).

A scan result describes *one* run.  This module keeps counters that survive
across runs (in ``.av-cache/metrics.json``, next to the scan cache) so
operators can answer "how much has this engine actually done?" – files
scanned, bytes read, threats found, scars from quarantines and kills.

The file is written atomically after every scan and is safe to delete:
the next scan rebuilds it from scratch.  Counters are exposed as JSON and
in Prometheus text format (``antivirus metrics --format prometheus``).
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Dict, Optional

from .utils import atomic_write_json

METRICS_VERSION = 1

#: (key, help text) for every counter we track.
COUNTERS = {
    "scans": "scan runs",
    "files_scanned": "files inspected by the engine",
    "files_cached": "files answered from the scan cache",
    "files_skipped": "files skipped (size/since/symlink/…)",
    "files_budget_skipped": "files whose deep analysis hit the time budget",
    "bytes_scanned": "bytes hashed and inspected",
    "findings_total": "findings reported",
    "threats_total": "findings at severity high or critical",
    "quarantined": "files quarantined",
    "killed": "files neutralised by the kill engine",
    "scans_with_findings": "runs that reported at least one finding",
}


def _default() -> Dict:
    data: Dict = {
        "metrics_version": METRICS_VERSION,
        "created_ts": time.time(),
        "updated_ts": time.time(),
    }
    for key in COUNTERS:
        data[key] = 0
    data["by_severity"] = {}
    data["by_kind"] = {}
    return data


def load(path) -> Dict:
    """Load the metrics file (a fresh default when missing/corrupt)."""
    import json
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError
    except (OSError, ValueError):
        return _default()
    base = _default()
    base.update(data)          # keep unknown keys written by future versions
    return base


def save(path, data: Dict) -> Path:
    """Atomically persist *data*."""
    data["updated_ts"] = time.time()
    return atomic_write_json(path, data)


def record_scan(path, result) -> Dict:
    """Add one :class:`~antivirus.scanner.ScanResult` to the counters."""
    data = load(path)
    data["scans"] = int(data.get("scans", 0)) + 1
    data["files_scanned"] = int(data.get("files_scanned", 0)) + result.files_scanned
    data["files_cached"] = int(data.get("files_cached", 0)) + result.files_cached
    data["files_skipped"] = int(data.get("files_skipped", 0)) + result.files_skipped
    data["files_budget_skipped"] = (
        int(data.get("files_budget_skipped", 0)) + result.files_budget_skipped)
    data["bytes_scanned"] = int(data.get("bytes_scanned", 0)) + result.bytes_scanned
    data["findings_total"] = int(data.get("findings_total", 0)) + len(result.findings)
    threats = sum(1 for f in result.findings
                  if f.severity in ("high", "critical"))
    data["threats_total"] = int(data.get("threats_total", 0)) + threats
    if result.findings:
        data["scans_with_findings"] = int(data.get("scans_with_findings", 0)) + 1
    by_sev = dict(data.get("by_severity") or {})
    by_kind = dict(data.get("by_kind") or {})
    for finding in result.findings:
        by_sev[finding.severity] = by_sev.get(finding.severity, 0) + 1
        by_kind[finding.kind] = by_kind.get(finding.kind, 0) + 1
    data["by_severity"] = by_sev
    data["by_kind"] = by_kind
    save(path, data)
    return data


def record_event(path, name: str, n: int = 1) -> Dict:
    """Increment one named counter (e.g. ``quarantined`` / ``killed``)."""
    if name not in COUNTERS:
        raise KeyError(f"unknown counter {name!r}")
    data = load(path)
    data[name] = int(data.get(name, 0)) + n
    save(path, data)
    return data


def reset(path) -> Dict:
    """Zero every counter (keep the creation timestamp)."""
    old = load(path)
    data = _default()
    data["created_ts"] = old.get("created_ts", data["created_ts"])
    save(path, data)
    return data


def render_prometheus(data: Dict) -> str:
    """Render the counters as Prometheus text exposition format."""
    lines = ["# HELP antivirus_metrics Cumulative AntiVirus engine counters",
             "# TYPE antivirus_metrics counter"]
    for key in COUNTERS:
        lines.append(f"antivirus_{key} {int(data.get(key, 0))}")
    for severity, count in sorted((data.get("by_severity") or {}).items()):
        lines.append(f'antivirus_findings_by_severity{{severity="{severity}"}} {int(count)}')
    for kind, count in sorted((data.get("by_kind") or {}).items()):
        lines.append(f'antivirus_findings_by_kind{{kind="{kind}"}} {int(count)}')
    for key, ts in (("created_ts", data.get("created_ts")),
                    ("updated_ts", data.get("updated_ts"))):
        if ts:
            lines.append(f"antivirus_metrics_{key} {int(float(ts))}")
    return "\n".join(lines) + "\n"


def summary(data: Dict) -> Dict:
    """A compact dict for JSON output / the web console."""
    out = {key: int(data.get(key, 0)) for key in COUNTERS}
    out["by_severity"] = dict(data.get("by_severity") or {})
    out["by_kind"] = dict(data.get("by_kind") or {})
    out["created_ts"] = data.get("created_ts")
    out["updated_ts"] = data.get("updated_ts")
    return out
