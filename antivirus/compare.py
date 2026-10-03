"""Feature + performance comparison, stated honestly (v2.5).

``antivirus compare`` prints (1) the concrete feature set of this engine,
(2) a comparison on the axes where the picture is stable and well-known,
and (3) *measured* performance numbers from the perf harness.

It is deliberately honest about positioning: this is a lightweight,
open, dependency-free, educational engine. On raw real-world malware
detection coverage it does not – and cannot – match commercial engines
that run huge continuously-updated signature databases, cloud lookups and
ML trained on billions of samples.  Where it genuinely leads is
transparency, scriptability, no telemetry, and a set of operational
features (guard, kill+revive, FIM baselines, rescue disk, SIEM export,
in-file URL/web shield, no-root firewall audit) that the *free consumer*
products either lack or gate behind enterprise tiers.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from . import __version__

# (feature, concrete detail).  100% verifiable in this codebase.
FEATURES: List[Dict] = [
    {"feature": "Background guard (real-time, detached)",
     "detail": "guard start|stop|status|log – auto-scans new/changed files "
               "in a lightweight daemon, no console"},
    {"feature": "Suspicion engine (heuristic, no signature needed)",
     "detail": "0-100 risk score from disguise/extension/entropy/location; "
               "quarantines suspicious drops with no known signature"},
    {"feature": "Web shield (URL reputation in every file)",
     "detail": "extracts URLs from any file, scores vs threat intel + "
               "shortener/IP/credential heuristics; urlcheck / webshield"},
    {"feature": "Firewall connection audit (no root)",
     "detail": "reads /proc/net (netstat fallback); flags backdoor ports, "
               "blocklisted IPs, risky listeners; firewall scan|monitor"},
    {"feature": "Kill engine with revive",
     "detail": "neutralize in place (stdlib keystream), key/IV in registry; "
               "revive restores exact bytes; rescans treat killed as inert"},
    {"feature": "File-integrity baselines (FIM)",
     "detail": "manifest + scan --baseline + fast hash-only verify"},
    {"feature": "Rescue disk (self-contained kit + ISO 9660)",
     "detail": "scan an infected volume from a live system; quarantine "
               "stays on the live side"},
    {"feature": "Multi-layer engine report (VT-style consensus)",
     "detail": "engine FILE – each layer's verdict + 'detected by N of M'"},
    {"feature": "Scriptable Python module API",
     "detail": "import antivirus; Antivirus() engine, scan/risk/url/firewall"},
    {"feature": "SIEM-ready export",
     "detail": "export to CSV / JSONL, one row per finding"},
    {"feature": "Front-ends",
     "detail": "CLI, Tkinter GUI, curses TUI, web console + JSON API"},
    {"feature": "Zero dependencies, pure standard library",
     "detail": "no pip, no network, runs from a USB stick / rescue media"},
    {"feature": "Built-in self test + benchmark + perf",
     "detail": "selftest, benchmark (labelled corpus), perf (throughput)"},
]

# Stable, well-known comparison axes.  `this` is verifiable here;
# `commercial` reflects the free consumer offerings of the named products.
POSITIONING: List[Dict] = [
    {"axis": "Source & auditability",
     "this": "open source, every detection rule readable",
     "commercial": "closed source; detection logic opaque"},
    {"axis": "Telemetry / data collection",
     "this": "none – no network calls, nothing leaves the machine",
     "commercial": "free tiers collect telemetry / usage data"},
    {"axis": "Scriptable / embeddable API",
     "this": "clean Python module + JSON web API",
     "commercial": "enterprise SDKs; not for the free consumer apps"},
    {"axis": "Runs fully offline",
     "this": "yes – signatures + heuristics, no cloud needed",
     "commercial": "hybrid local+cloud; VirusTotal is cloud-only"},
    {"axis": "Real-world malware coverage",
     "this": "signature + behaviour + heuristic; extend with your own",
     "commercial": "far larger, continuously updated DBs + cloud + ML"},
    {"axis": "Guard / kill+revive / FIM / rescue / SIEM export",
     "this": "built in, in the free core",
     "commercial": "split across paid / enterprise tiers"},
    {"axis": "Footprint & dependencies",
     "this": "pure stdlib, no install, ~MBs",
     "commercial": "native agents, services, drivers, GBs"},
]

_COMPARED_AGAINST = ("AVG (free)", "Avast (free)", "Malwarebytes (free)",
                    "VirusTotal")


def run(perf_result: Optional[Dict] = None) -> Dict:
    return {
        "version": __version__,
        "compared_against": list(_COMPARED_AGAINST),
        "features": FEATURES,
        "positioning": POSITIONING,
        "performance": perf_result,
        "honesty_note": (
            "Detection coverage is the one axis the commercial engines "
            "genuinely lead: they maintain huge, continuously updated "
            "signature databases, cloud lookups and ML trained on billions "
            "of samples. This engine is lightweight, open and educational "
            "by design; it leads on transparency, no telemetry, "
            "scriptability and a broad set of operational features – not on "
            "raw real-world malware coverage. Performance numbers below are "
            "measured on this machine and are for tuning/regression, not a "
            "like-for-like claim against optimized C++/kernel engines."),
    }


def summary_lines(result: Dict) -> List[str]:
    out = []
    perf = result.get("performance")
    if perf:
        from . import perf as perf_mod

        out.append(perf_mod.summary_line(perf))
    else:
        out.append("performance: (skipped)")
    return out
