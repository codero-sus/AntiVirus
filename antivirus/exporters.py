"""Report exporters (v2.8): SARIF 2.1.0 and standalone HTML.

SARIF is what CI systems and code-scanning dashboards (GitHub code
scanning, Azure DevOps, DefectDojo, …) ingest, so ``antivirus sarif`` makes
the engine a first-class CI citizen.  The HTML exporter writes a single
self-contained file (inline CSS, no scripts, no external requests) that can
be attached to a ticket or opened offline.

Both exporters take either a :class:`~antivirus.scanner.ScanResult` or the
plain dict produced by ``ScanResult.to_dict()``.
"""
from __future__ import annotations

import html
import json
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from . import __version__

#: finding severity -> SARIF result level
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _dict(result) -> Dict:
    return result.to_dict() if hasattr(result, "to_dict") else dict(result)


def _relative(path: str, base: Optional[Path]) -> str:
    """Best-effort path relative to *base* (for portable reports)."""
    p = Path(path)
    if base is not None:
        try:
            return str(p.relative_to(base))
        except ValueError:
            pass
    return str(p)


# --------------------------------------------------------------------- SARIF
def to_sarif(result, base: Optional[Path] = None,
             information_uri: str = "https://github.com/codero-sus/AntiVirus",
             start_time: Optional[float] = None) -> Dict:
    """Convert a scan result to a SARIF 2.1.0 log (as a dict)."""
    data = _dict(result)
    findings = data.get("findings") or []
    base = base or Path.cwd()

    rules: Dict[str, Dict] = {}
    results: List[Dict] = []
    for f in findings:
        kind = f.get("kind", "finding")
        name = f.get("name", "finding")
        rule_id = f"{kind}:{name}".replace(" ", "_")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": name,
                "shortDescription": {"text": name},
                "fullDescription": {"text": f.get("message", "")},
                "properties": {
                    "kind": kind,
                    "tags": [kind, f.get("severity", "info")],
                },
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL.get(f.get("severity", "info"), "warning"),
                },
            }
        location: Dict = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": _relative(f.get("path", ""), base).replace("\\", "/"),
                },
            },
        }
        if f.get("size"):
            location["physicalLocation"]["region"] = {"byteLength": int(f["size"])}
        results.append({
            "ruleId": rule_id,
            "ruleIndex": list(rules).index(rule_id),
            "level": _SARIF_LEVEL.get(f.get("severity", "info"), "warning"),
            "message": {"text": f.get("message") or name},
            "locations": [location],
            "properties": {
                "severity": f.get("severity"),
                "sha256": f.get("sha256", ""),
                "size": f.get("size", 0),
                "kind": kind,
            },
        })

    run: Dict = {
        "tool": {
            "driver": {
                "name": "AntiVirus",
                "organization": "AntiVirus project",
                "version": __version__,
                "informationUri": information_uri,
                "rules": list(rules.values()),
            },
        },
        "results": results,
        "invocations": [{
            "executionSuccessful": True,
            "startTimeUtc": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(start_time or data.get("started_at") or time.time())),
            "endTimeUtc": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(data.get("finished_at") or time.time())),
            "properties": {
                "target": data.get("target"),
                "files_scanned": data.get("files_scanned", 0),
                "files_skipped": data.get("files_skipped", 0),
                "files_cached": data.get("files_cached", 0),
                "bytes_scanned": data.get("bytes_scanned", 0),
                "clean": data.get("clean", not findings),
            },
        }],
    }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def render_sarif(result, base: Optional[Path] = None) -> str:
    """SARIF as pretty-printed JSON text."""
    return json.dumps(to_sarif(result, base=base), indent=2,
                      ensure_ascii=False) + "\n"


# ---------------------------------------------------------------------- HTML
_HTML_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font: 15px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial,
       sans-serif; margin: 0; padding: 32px; background: #f6f7f9; color: #1b1f24; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 16px; margin: 28px 0 8px; }
.sub { color: #57606a; margin-bottom: 20px; }
.cards { display: flex; flex-wrap: wrap; gap: 12px; margin: 16px 0 6px; }
.card { background: #fff; border: 1px solid #d8dee4; border-radius: 8px;
        padding: 12px 16px; min-width: 128px; }
.card .n { font-size: 22px; font-weight: 700; }
.card .l { font-size: 12px; color: #57606a; text-transform: uppercase;
           letter-spacing: .04em; }
table { width: 100%; border-collapse: collapse; background: #fff;
        border: 1px solid #d8dee4; border-radius: 8px; overflow: hidden; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #eaeef2;
         vertical-align: top; font-size: 13.5px; }
th { background: #f0f3f6; font-size: 12px; text-transform: uppercase;
     letter-spacing: .04em; color: #57606a; }
tr:last-child td { border-bottom: 0; }
.sev { font-weight: 700; padding: 1px 7px; border-radius: 999px;
       font-size: 12px; white-space: nowrap; }
.critical { background: #7d1128; color: #fff; }
.high { background: #cf222e; color: #fff; }
.medium { background: #bf8700; color: #fff; }
.low { background: #0969da; color: #fff; }
.info { background: #57606a; color: #fff; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        font-size: 12.5px; }
.clean { color: #1a7f37; font-weight: 600; }
footer { margin-top: 28px; color: #57606a; font-size: 12.5px; }
@media (prefers-color-scheme: dark) {
  body { background: #0d1117; color: #e6edf3; }
  .card, table { background: #161b22; border-color: #30363d; }
  th { background: #21262d; color: #8b949e; }
  th, td { border-color: #30363d; }
  .sub, footer { color: #8b949e; }
}
"""


def _e(text) -> str:
    return html.escape(str(text), quote=True)


def render_html(result, base: Optional[Path] = None,
                title: str = "AntiVirus scan report") -> str:
    """A self-contained HTML report (inline CSS, no scripts)."""
    data = _dict(result)
    findings = sorted(data.get("findings") or [],
                      key=lambda f: (_SEVERITY_ORDER.get(f.get("severity"), 9),
                                     f.get("path", "")))
    rows = []
    for f in findings:
        sev = f.get("severity", "info")
        rows.append(
            "<tr>"
            f'<td><span class="sev {_e(sev)}">{_e(sev)}</span></td>'
            f'<td>{_e(f.get("kind", ""))}</td>'
            f'<td>{_e(f.get("name", ""))}</td>'
            f'<td class="mono">{_e(_relative(f.get("path", ""), base))}</td>'
            f'<td class="mono">{_e((f.get("sha256") or "")[:16])}</td>'
            f'<td>{_e(f.get("message", ""))}</td>'
            "</tr>")
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
    cards = "".join(
        f'<div class="card"><div class="n">{data.get(key, 0)}</div>'
        f'<div class="l">{label}</div></div>'
        for key, label in (
            ("files_scanned", "files scanned"),
            ("files_skipped", "skipped"),
            ("files_cached", "from cache"),
            ("bytes_scanned", "bytes read"),
        ))
    cards += "".join(
        f'<div class="card"><div class="n">{counts.get(sev, 0)}</div>'
        f'<div class="l">{sev}</div></div>'
        for sev in ("critical", "high", "medium", "low", "info"))
    verdict = ("<span class=\"clean\">no findings</span>" if not findings
               else f"<strong>{len(findings)}</strong> finding(s)")
    started = data.get("started_at")
    started_s = (time.strftime("%Y-%m-%d %H:%M:%S",
                               time.localtime(started)) if started else "-")
    table = ("<p>No findings.</p>" if not rows else
             "<table><thead><tr><th>Severity</th><th>Layer</th><th>Name</th>"
             "<th>Path</th><th>SHA-256</th><th>Detail</th></tr></thead><tbody>"
             + "".join(rows) + "</tbody></table>")
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title><style>{_HTML_CSS}</style></head>
<body>
<h1>{_e(title)}</h1>
<div class="sub">target <span class="mono">{_e(data.get("target", ""))}</span>
 &middot; started {_e(started_s)} &middot; {verdict}</div>
<div class="cards">{cards}</div>
<h2>Findings</h2>
{table}
<footer>AntiVirus {_e(__version__)} &middot; static analysis only —
nothing was executed. Report generated
{_e(time.strftime("%Y-%m-%d %H:%M:%S"))}.</footer>
</body></html>
"""


def write_html(result, path, base: Optional[Path] = None,
               title: str = "AntiVirus scan report") -> Path:
    """Write :func:`render_html` to *path* (atomically)."""
    from .utils import atomic_write_text
    return atomic_write_text(path, render_html(result, base=base, title=title))


def write_sarif(result, path, base: Optional[Path] = None) -> Path:
    """Write :func:`render_sarif` to *path* (atomically)."""
    from .utils import atomic_write_text
    return atomic_write_text(path, render_sarif(result, base=base))
