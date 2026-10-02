"""Web shield: URL / domain reputation and in-file URL extraction (v2.4).

Pure standard library.  The idea is the file-scanner half of a web filter:
every file we scan is also *read* for URLs (scripts, documents, notes, PE
resource strings - the regex runs on raw bytes, so it works anywhere), and
each URL is scored against a small threat-intel database plus a set of
heuristic signals (URL shorteners, IP-literal hosts, executable file TLDs,
embedded credentials, known backdoor ports, long random paths).

The bundled ``data/threat_intel.json`` is deliberately *educational*:
domains use the reserved ``.invalid`` / ``example`` TLDs (RFC 2606 - they
can never resolve) and IPs use reserved documentation ranges.  Add real
indicators with ``antivirus webshield add`` or a plain-text IOC import.
"""
from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

BUNDLED_INTEL = Path(__file__).resolve().parent.parent / "data" / "threat_intel.json"
USER_INTEL_DEFAULT = "intel/user_intel.json"

#: http(s)/ftp URLs in raw bytes (tolerant about trailing punctuation).
URL_RE = re.compile(rb"(?:https?|ftp)://[^\s\"'`<>()\[\]{}\\^\x00-\x1f]+", re.I)

#: URL max length we bother scoring (longer "urls" are almost never real).
_MAX_URL_LEN = 2048
#: Cap on URLs extracted from one file (defence against URL floods).
_MAX_URLS_PER_FILE = 50

#: TLDs that almost always mean "this link is an executable".
_RISKY_TLDS = {"exe", "zip", "scr", "hta", "vbs", "vbe", "js", "jse", "jar",
               "bat", "cmd", "pif", "com", "lnk", "msi"}

#: Ports commonly seen on legitimate traffic (keeps alerts quiet).
_COMMON_OUTBOUND = {53, 80, 443, 123, 4500, 5222, 5223, 5228, 5229, 8080,
                    8443, 8888, 1928, 5060, 5061, 1863, 3389}


@dataclass
class ThreatIntel:
    """A small, mergeable threat-intel database."""

    domains: set = field(default_factory=set)
    ips: set = field(default_factory=set)
    ports: Dict[str, str] = field(default_factory=dict)
    listen_ports: Dict[str, str] = field(default_factory=dict)
    shorteners: set = field(default_factory=set)
    path: Optional[Path] = None

    @classmethod
    def load(cls, path: Optional[Path] = None,
             user_path: Optional[Path] = None) -> "ThreatIntel":
        intel = cls()
        primary = Path(path) if path else BUNDLED_INTEL
        if primary.exists():
            intel._merge(primary)
        # User additions (webshield add / kit-local intel).
        up = Path(user_path) if user_path else Path(USER_INTEL_DEFAULT)
        if up.exists():
            intel._merge(up)
        intel.path = up
        return intel

    def _merge(self, p: Path) -> None:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        intel = data.get("intel", data)  # allow a bare dict too
        self.domains |= {d.lower() for d in intel.get("domains", [])}
        self.ips |= {i.lower() for i in intel.get("ips", [])}
        self.ports.update({str(k): v for k, v in intel.get("ports", {}).items()})
        self.listen_ports.update(
            {str(k): v for k, v in intel.get("listen_ports", {}).items()})
        self.shorteners |= {s.lower() for s in intel.get("shorteners", [])}

    # ------------------------------------------------------------ mutations
    def add_domain(self, domain: str) -> None:
        self.domains.add(domain.lower().strip("."))
        self._save()

    def add_ip(self, ip: str) -> None:
        self.ips.add(ip.lower())
        self._save()

    def add_port(self, port: int, note: str = "user-reported risky port") -> None:
        self.ports[str(int(port))] = note
        self._save()

    def _save(self) -> None:
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "version": 1,
                "domains": sorted(self.domains),
                "ips": sorted(self.ips),
                "ports": self.ports,
                "listen_ports": self.listen_ports,
                "shorteners": sorted(self.shorteners),
            }
            self.path.write_text(json.dumps(data, indent=2) + "\n",
                                 encoding="utf-8")
        except OSError:
            pass

    def summary(self) -> Dict:
        return {
            "domains": len(self.domains),
            "ips": len(self.ips),
            "ports": len(self.ports),
            "listen_ports": len(self.listen_ports),
            "shorteners": len(self.shorteners),
        }


# ------------------------------------------------------------------ URL math
def extract_urls(data: bytes) -> List[str]:
    """Every http(s)/ftp URL in *data* (deduplicated, order preserved)."""
    if not data:
        return []
    out: List[str] = []
    seen = set()
    for m in URL_RE.finditer(data):
        url = m.group(0).rstrip(b".,;:!?)]}>'\"")
        if not url or len(url) > _MAX_URL_LEN:
            continue
        text = url.decode("ascii", "replace")
        if text not in seen:
            seen.add(text)
            out.append(text)
        if len(out) >= _MAX_URLS_PER_FILE:
            break
    return out


def _host_is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host or ""))


def _randomness(text: str) -> float:
    """0..1 Shannon entropy of *text* (for "long random path segment")."""
    if len(text) < 8:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def check_url(url: str, intel: ThreatIntel) -> Dict:
    """Score one URL.  Returns ``{url, verdict, score, reasons}``."""
    reasons: List[str] = []
    score = 0
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except ValueError:
        return {"url": url, "verdict": "suspicious", "score": 30,
                "reasons": ["unparseable URL"]}
    host = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port
    path = parsed.path or ""

    # --- threat-intel matches (decisive) ---------------------------------
    if host and host in intel.domains:
        score += 100
        reasons.append(f"domain '{host}' is in the threat-intel blocklist")
    for parent in _parent_domains(host):
        if parent in intel.domains:
            score += 80
            reasons.append(f"domain is under blocklisted zone '{parent}'")
            break
    if host and _host_is_ip(host):
        if host in intel.ips:
            score += 100
            reasons.append(f"IP {host} is in the threat-intel blocklist")
        else:
            score += 20
            reasons.append("IP address used instead of a domain")

    # --- port ------------------------------------------------------------
    if port is not None and str(port) in intel.ports:
        score += 45
        reasons.append(f"port {port} ({intel.ports[str(port)]})")

    # --- heuristics --------------------------------------------------------
    seg = path.strip("/").rsplit("/", 1)[-1]
    if host:
        if host in intel.shorteners or any(
            host == s or host.endswith("." + s) for s in intel.shorteners
        ):
            score += 25
            reasons.append(f"URL shortener ('{host}')")
        # executable-looking file extension in the *path* (…/update.exe)
        ext = seg.rsplit(".", 1)[-1].lower() if "." in seg else ""
        if ext in _RISKY_TLDS:
            score += 25
            reasons.append(f"link points at an executable-looking file '.{ext}'")
    if parsed.username:
        score += 15
        reasons.append("credentials embedded in the URL")
    if len(path) >= 12 and len(seg) >= 24 and _randomness(seg) > 3.4:
        score += 10
        reasons.append("long random path segment (token/blob)")
    if parsed.scheme == "ftp":
        score += 10
        reasons.append("ftp:// (cleartext file transfer)")

    if score >= 60:
        verdict = "malicious"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "safe"
    return {"url": url, "verdict": verdict, "score": min(score, 100),
            "reasons": reasons}


def _parent_domains(host: str) -> List[str]:
    parts = host.split(".")
    return [".".join(parts[i:]) for i in range(1, len(parts) - 1)]


def check_file(name: str, data: bytes, intel: ThreatIntel) -> List[Dict]:
    """Extract + score every URL found in *data*."""
    return [check_url(u, intel) for u in extract_urls(data)]


def audit_bytes(name: str, data: bytes, intel: ThreatIntel):
    """Scanner-facing helper: findings for malicious/suspicious URLs."""
    from .models import Finding  # local import avoids a cycle at load time

    reports = check_file(name, data, intel)
    findings = []
    malicious = [r for r in reports if r["verdict"] == "malicious"]
    suspicious = [r for r in reports if r["verdict"] == "suspicious"]
    if malicious:
        host = malicious[0]["url"].split("//", 1)[-1].split("/", 1)[0]
        findings.append(Finding(
            path=name, kind="malicious_url", name="MaliciousURL",
            severity="high",
            message=(f"{len(malicious)} malicious URL(s) – e.g. "
                     f"{malicious[0]['url']} ({'; '.join(malicious[0]['reasons'])})"),
        ))
    elif suspicious:
        findings.append(Finding(
            path=name, kind="suspicious_url", name="SuspiciousURL",
            severity="medium",
            message=(f"{len(suspicious)} suspicious URL(s) – e.g. "
                     f"{suspicious[0]['url']} ({'; '.join(suspicious[0]['reasons'])})"),
        ))
    return findings
