"""Engine report: a VirusTotal-style, per-layer verdict for one file (v2.5).

VirusTotal's value is "many engines looked at this, here's what each said
and do they agree."  This is the honest single-host equivalent: the file is
read **once**, and every detection layer is run as its own "engine" —

    hash      exact signature match (SHA-256 / MD5)
    pattern   regex signature match in the file body
    behaviour what the file appears to do (static, never executed)
    url       web shield – URLs inside the file vs threat intel
    risk      suspicion engine – how suspicious it *looks* (0-100)
    entropy   Shannon-entropy heuristic (packed / encrypted)
    archive   contents of ZIP / TAR / GZIP, in memory

The report lists each engine's verdict + details and a consensus line —
``detected by N of M engines`` with an overall severity — which is the
single file's "engine consensus" the way VT shows a scan table.

Everything here reuses the *same* primitives the scanner uses, so a layer's
verdict in the report is identical to what a real scan would produce.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .config import Config
from .models import Finding, shannon_entropy
from .signatures import SignatureDB
from .utils import md5_new

#: The "engines", in report order.
_ENGINES = ("hash", "pattern", "behaviour", "url", "risk", "entropy",
            "archive")

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class LayerVerdict:
    engine: str
    label: str
    verdict: str            # "clean" | "flagged"
    severity: str           # worst severity among its findings (or "info")
    details: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "engine": self.engine, "label": self.label,
            "verdict": self.verdict, "severity": self.severity,
            "details": self.details,
        }


def _findings_to_details(findings: List[Finding]) -> List[str]:
    out = []
    for f in findings:
        msg = f.message or f.name
        out.append(f"[{f.severity}] {f.name}: {msg}")
    return out


def _worst(findings: List[Finding]) -> str:
    if not findings:
        return "info"
    return min(findings, key=lambda f: _SEV_ORDER.get(f.severity, 9)).severity


def engine_report(path, scanner, config: Optional[Config] = None) -> Dict:
    """Run every layer over one file and return a consensus-style report."""
    from . import behavior as behavior_mod
    from . import risk as risk_mod
    from . import webshield as webshield_mod

    config = config or scanner.config
    p = Path(path)
    try:
        st = p.lstat()
    except OSError as exc:
        return {"error": str(exc), "file": str(p)}

    size = st.st_size
    if size > config.max_file_size:
        return {"error": f"file too large ({size} bytes)", "file": str(p)}

    # One read pass: digests + entropy histogram + buffered content.
    sha = hashlib.sha256()
    md5 = md5_new()
    head_n = max(config.behavior_max_size, 65536)
    content = b""
    with open(p, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            sha.update(chunk)
            md5.update(chunk)
            if len(content) < head_n:
                content += chunk
    sha256 = sha.hexdigest()
    md5hex = md5.hexdigest()

    db: SignatureDB = scanner.db
    intel = scanner.threat_intel()
    layers: Dict[str, LayerVerdict] = {}

    # -- hash -------------------------------------------------------------
    sig = db.by_sha256(sha256) or db.by_md5(md5hex)
    if sig is not None:
        layers["hash"] = LayerVerdict(
            "hash", "Signature hash", "flagged", sig.severity,
            [f"matches '{sig.id}' ({sig.name})"])
    else:
        layers["hash"] = LayerVerdict("hash", "Signature hash", "clean",
                                      "info")

    # -- pattern ----------------------------------------------------------
    scanner._sync_patterns()
    hits = scanner._match_patterns(content)
    layers["pattern"] = (
        LayerVerdict("pattern", "Signature pattern", "flagged",
                     _worst([Finding(path=str(p), kind="signature-pattern",
                                     name=s.name, severity=s.severity,
                                     message="") for s in hits]),
                     [f"pattern of '{s.id}' found" for s in hits])
        if hits else
        LayerVerdict("pattern", "Signature pattern", "clean", "info"))

    # -- behaviour --------------------------------------------------------
    if config.behavior_enabled and behavior_mod.looks_executable(p, content):
        b_findings = behavior_mod.analyze_file(p, st, content)
        layers["behaviour"] = (
            LayerVerdict("behaviour", "Behavioural analysis", "flagged",
                         _worst(b_findings),
                         _findings_to_details(b_findings))
            if b_findings else
            LayerVerdict("behaviour", "Behavioural analysis", "clean",
                         "info"))
    else:
        layers["behaviour"] = LayerVerdict(
            "behaviour", "Behavioural analysis", "clean", "info",
            ["skipped – not executable-looking"]
            if not config.behavior_enabled else [])

    # -- url (web shield) -------------------------------------------------
    if config.webshield_enabled:
        u_findings = webshield_mod.audit_bytes(str(p), content, intel)
        layers["url"] = (
            LayerVerdict("url", "Web shield (URLs)", "flagged",
                         _worst(u_findings),
                         _findings_to_details(u_findings))
            if u_findings else
            LayerVerdict("url", "Web shield (URLs)", "clean", "info"))
    else:
        layers["url"] = LayerVerdict("url", "Web shield (URLs)", "clean",
                                     "info", ["disabled"])

    # -- risk -------------------------------------------------------------
    if config.risk_enabled:
        report = risk_mod.assess_risk(p, st, content[:65536])
        if report.score >= config.risk_threshold:
            layers["risk"] = LayerVerdict(
                "risk", "Suspicion engine", "flagged",
                risk_mod.severity_for(report.score),
                [f"score {report.score}/100"] + report.top_reasons(3))
        else:
            layers["risk"] = LayerVerdict(
                "risk", "Suspicion engine", "clean", "info",
                [f"score {report.score}/100 (below {config.risk_threshold})"])
    else:
        layers["risk"] = LayerVerdict("risk", "Suspicion engine", "clean",
                                      "info", ["disabled"])

    # -- entropy ----------------------------------------------------------
    entropy = shannon_entropy(content[:config.entropy_sample_size]) \
        if size >= config.entropy_min_size else None
    if entropy is not None and entropy >= config.entropy_threshold:
        layers["entropy"] = LayerVerdict(
            "entropy", "Entropy heuristic", "flagged", "medium",
            [f"{entropy:.2f} bits/byte >= {config.entropy_threshold} "
             "(may be packed/encrypted)"])
    else:
        layers["entropy"] = LayerVerdict(
            "entropy", "Entropy heuristic", "clean", "info",
            [f"{entropy:.2f} bits/byte" if entropy is not None
             else "file below heuristic size"])

    # -- archive ----------------------------------------------------------
    if config.archives_enabled and size <= config.archive_max_size:
        a_findings = scanner._scan_archives(p, content[:262])
        layers["archive"] = (
            LayerVerdict("archive", "Archive contents", "flagged",
                         _worst(a_findings),
                         _findings_to_details(a_findings))
            if a_findings else
            LayerVerdict("archive", "Archive contents", "clean", "info"))
    else:
        layers["archive"] = LayerVerdict(
            "archive", "Archive contents", "clean", "info",
            [] if config.archives_enabled else ["disabled"])

    # -- consensus --------------------------------------------------------
    flagged = [v for v in layers.values() if v.verdict == "flagged"]
    overall = _worst([
        Finding(path=str(p), kind=v.engine, name=v.label,
                severity=v.severity, message="") for v in flagged])
    if not flagged:
        overall = "info"
    detected = len(flagged)
    total = len(layers)
    consensus = (
        f"detected by {detected} of {total} engines"
        if detected else "not detected by any engine"
    )
    return {
        "file": str(p),
        "size": size,
        "sha256": sha256,
        "md5": md5hex,
        "engines_total": total,
        "engines_detected": detected,
        "consensus": consensus,
        "overall_severity": overall if detected else "clean",
        "layers": [layers[e].to_dict() for e in _ENGINES
                   if e in layers],
    }
