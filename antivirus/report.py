"""Scan report writer: one JSON + one plain-text file per scan."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, Optional

from .scanner import ScanResult
from .utils import human_size


def render_report(data: Dict) -> str:
    """Render a report dict (as stored in the JSON file) as plain text."""
    lines = []
    lines.append("=" * 62)
    lines.append(" AntiVirus scan report")
    lines.append("=" * 62)
    lines.append(f" Target:      {data.get('target')}")
    lines.append(f" Action:      {data.get('action', 'detect')}")
    lines.append(
        f" Files:       {data.get('files_scanned', 0)} scanned, "
        f"{data.get('files_skipped', 0)} skipped "
        f"({human_size(data.get('bytes_scanned', 0))})"
    )
    lines.append(f" Errors:      {len(data.get('errors', []))}")
    if data.get("started_at"):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data["started_at"]))
        lines.append(f" Started:     {stamp}")
    lines.append(f" Duration:    {data.get('elapsed_seconds', 0)} s")
    lines.append("")
    findings = data.get("findings", [])
    if findings:
        lines.append(f" Threats found: {len(findings)}")
        lines.append("-" * 62)
        actions = data.get("actions_taken", {}) or {}
        for f in findings:
            lines.append(f"  [{f['severity'].upper():<8}] {f['name']}   ({f['kind']})")
            lines.append(f"             file:   {f['path']}")
            lines.append(f"             detail: {f['message']}")
            if f["path"] in actions:
                lines.append(f"             action: {actions[f['path']]}")
        lines.append("-" * 62)
    else:
        lines.append(" Threats found: 0")
    for err in data.get("errors", [])[:10]:
        lines.append(f" warning: {err}")
    lines.append(f" Result:      {'CLEAN' if data.get('clean') else 'INFECTED'}")
    lines.append("=" * 62)
    return "\n".join(lines) + "\n"


class ReportWriter:
    def __init__(self, report_dir: Path) -> None:
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def save(
        self,
        result: ScanResult,
        action: str = "detect",
        actions_taken: Optional[Dict[str, str]] = None,
    ) -> Path:
        """Persist the scan result; returns the path of the JSON report."""
        stamp = time.strftime("%Y%m%d-%H%M%S")
        data = result.to_dict()
        data["action"] = action
        data["actions_taken"] = actions_taken or {}

        json_path = self.report_dir / f"scan-{stamp}.json"
        n = 1
        while json_path.exists():
            json_path = self.report_dir / f"scan-{stamp}-{n}.json"
            n += 1
        json_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        json_path.with_suffix(".txt").write_text(render_report(data), encoding="utf-8")
        return json_path

    def latest(self) -> Optional[Path]:
        files = sorted(self.report_dir.glob("scan-*.json"))
        return files[-1] if files else None

    def all_reports(self) -> List[Path]:
        """All saved reports, oldest first (sorted by mtime)."""
        files = sorted(self.report_dir.glob("scan-*.json"),
                       key=lambda f: f.stat().st_mtime)
        return files


def diff_reports(old: Dict, new: Dict) -> Dict[str, List[Dict]]:
    """Compare two saved scan-report documents (JSON dicts).

    Findings are keyed by ``(path, name, severity)``. Returns
    ``{"new": [...], "cleared": [...], "unchanged": [...]}`` where *new*
    are findings only present in *new* and *cleared* only in *old*.
    """
    def _key(f: Dict):
        return (f.get("path"), f.get("name"), f.get("severity"))

    old_map = {_key(f): f for f in old.get("findings", [])}
    new_map = {_key(f): f for f in new.get("findings", [])}
    return {
        "new": [new_map[k] for k in new_map if k not in old_map],
        "cleared": [old_map[k] for k in old_map if k not in new_map],
        "unchanged": [new_map[k] for k in new_map if k in old_map],
    }
