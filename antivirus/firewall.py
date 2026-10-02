"""Firewall: live network-connection audit (v2.4).

A *monitor*, not a packet filter: reading the OS connection table needs
no privileges (``/proc/net/tcp{,6}`` on Linux, ``netstat`` elsewhere), so
this works as an unprivileged user.  It lists the system's live sockets
and flags the ones that look wrong:

* remote peer on a known **backdoor port** (4444, 4431, 31337, …)
* remote peer IP in the **threat-intel blocklist**
* a **risky service listening** (telnet, FTP, VNC, RDP, SMB, …)
* outbound connection to a **non-standard port** (heuristic)

Feed it real indicators with ``antivirus webshield add`` / IOC imports.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .webshield import ThreatIntel

#: /proc/net/tcp state codes (Linux).
_TCP_STATES = {
    1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1",
    5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT",
    9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING",
}

_COMMON_OUTBOUND_PORTS = {53, 80, 443, 123, 4500, 5222, 5223, 5228, 5229,
                          8080, 8443, 8888, 1928, 5060, 5061, 1863, 3389}

_NETSTAT_LINE = re.compile(
    r"^(tcp|udp)(v6)?\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?")


@dataclass
class Connection:
    proto: str          # "tcp" / "udp"
    local: Tuple[str, int]
    remote: Tuple[str, int]
    state: str          # ESTABLISHED / LISTEN / ...
    inode: int = 0

    @property
    def key(self) -> str:
        return f"{self.proto} {self.local[0]}:{self.local[1]} <-> " \
               f"{self.remote[0]}:{self.remote[1]} [{self.state}]"

    def to_dict(self) -> Dict:
        return {
            "proto": self.proto,
            "local": list(self.local),
            "remote": list(self.remote),
            "state": self.state,
            "inode": self.inode,
        }


# --------------------------------------------------------------- /proc/net
def _hex_addr(raw: str) -> Tuple[str, int]:
    """``'0100007F:1F90'`` -> ``('127.0.0.1', 8080)`` (little-endian IP)."""
    ip_hex, port_hex = raw.split(":")
    port = int(port_hex, 16)
    if len(ip_hex) == 8:  # IPv4
        b = bytes.fromhex(ip_hex)
        return f"{b[3]}.{b[2]}.{b[1]}.{b[0]}", port
    return ip_hex, port  # IPv6 stays hex-ish; we only compare against intel


def parse_proc_net_file(path: Path, proto: str) -> List[Connection]:
    """Parse one ``/proc/net/tcp[6]`` / ``udp[6]`` table (pure function)."""
    conns: List[Connection] = []
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return conns
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        local, remote = _hex_addr(parts[1]), _hex_addr(parts[2])
        state = _TCP_STATES.get(int(parts[3], 16), "UNKNOWN") \
            if proto.startswith("tcp") else "-"
        try:
            inode = int(parts[9])
        except ValueError:
            inode = 0
        conns.append(Connection(proto=proto, local=local, remote=remote,
                                state=state, inode=inode))
    return conns


def list_connections_proc() -> List[Connection]:
    proc = Path("/proc/net")
    conns: List[Connection] = []
    for name, proto in (("tcp", "tcp"), ("tcp6", "tcp6"),
                        ("udp", "udp"), ("udp6", "udp6")):
        p = proc / name
        if p.exists():
            conns.extend(parse_proc_net_file(p, proto))
    return conns


# ---------------------------------------------------------------- netstat
def list_connections_netstat() -> List[Connection]:
    """Fallback for platforms without /proc (Windows, macOS)."""
    binary = shutil.which("netstat")
    if binary is None:
        raise RuntimeError(
            "no connection-table source available (need /proc/net or "
            "netstat)")
    out = subprocess.run(
        [binary, "-ano"] if os.name == "nt" else [binary, "-an"],
        capture_output=True, text=True, timeout=15).stdout
    conns: List[Connection] = []
    for line in out.splitlines():
        m = _NETSTAT_LINE.match(line.strip())
        if not m:
            continue
        proto, _v6, laddr, raddr, state = m.groups()
        try:
            local = _split_addr(laddr)
            remote = _split_addr(raddr)
        except ValueError:
            continue
        conns.append(Connection(proto=proto, local=local, remote=remote,
                                state=(state or "-").upper()))
    return conns


def _split_addr(raw: str) -> Tuple[str, int]:
    if raw.count(":") == 2:  # IPv6 [::1]:80
        host, port = raw.rsplit(":", 1)
        return host.strip("[]"), int(port)
    host, port = raw.rsplit(":", 1)
    return host, int(port)


def list_connections() -> Tuple[List[Connection], str]:
    """(connections, source).  Tries /proc first, then netstat."""
    if Path("/proc/net/tcp").exists():
        return list_connections_proc(), "proc"
    return list_connections_netstat(), "netstat"


# ------------------------------------------------------------------ audit
def audit(conns: List[Connection], intel: ThreatIntel) -> List[Dict]:
    """Flag connections that look wrong.  Returns alert dicts."""
    alerts: List[Dict] = []
    for c in conns:
        r_ip, r_port = c.remote
        l_ip, l_port = c.local
        base = {"conn": c.key, "local": list(c.local),
                "remote": list(c.remote), "proto": c.proto}
        # Listener checks first: LISTEN sockets have a wildcard remote.
        if c.state == "LISTEN" and str(l_port) in intel.listen_ports:
            alerts.append({
                **base, "severity": "medium", "kind": "risky_listener",
                "detail": (f"service listening on port {l_port} "
                           f"({intel.listen_ports[str(l_port)]})"),
            })
        if r_ip in ("0.0.0.0", ""):
            continue
        if str(r_port) in intel.ports:
            alerts.append({
                **base, "severity": "high", "kind": "backdoor_port",
                "detail": (f"remote peer on port {r_port} "
                           f"({intel.ports[str(r_port)]})"),
            })
        if r_ip.lower() in intel.ips:
            alerts.append({
                **base, "severity": "high", "kind": "intel_ip",
                "detail": f"remote IP {r_ip} is in the threat-intel blocklist",
            })
        loopback = l_ip.startswith("127.") and r_ip.startswith("127.")
        if (c.state == "ESTABLISHED" and c.proto == "tcp" and not loopback
                and r_port >= 1024 and r_port not in _COMMON_OUTBOUND_PORTS):
            alerts.append({
                **base, "severity": "low", "kind": "odd_outbound_port",
                "detail": f"outbound TCP to non-standard port {r_port}",
            })
    return alerts


def scan() -> Dict:
    """One-shot snapshot + audit (module/CLI entry point)."""
    intel = ThreatIntel.load()
    conns, source = list_connections()
    alerts = audit(conns, intel)
    return {"source": source, "connections": len(conns),
            "alerts": alerts,
            "connection_list": [c.to_dict() for c in conns],
            "intel": intel.summary()}


def monitor(interval: float = 5.0, once: bool = False,
            on_alert=None, on_tick=None) -> int:
    """Poll the connection table; report *new* alerts each round.

    *on_alert*(alert) is called per new alert; *on_tick*(summary) per
    round.  Returns the number of alerts ever reported.
    """
    intel = ThreatIntel.load()
    seen: set = set()
    total = 0
    while True:
        try:
            conns, source = list_connections()
        except RuntimeError as exc:
            if on_alert:
                on_alert({"severity": "error", "kind": "unsupported",
                          "detail": str(exc)})
            return total
        alerts = audit(conns, intel)
        for a in alerts:
            sig = (a["kind"], a["conn"])
            if sig not in seen:
                seen.add(sig)
                total += 1
                if on_alert:
                    on_alert(a)
        if on_tick:
            on_tick({"source": source, "connections": len(conns),
                     "alerts": len(alerts)})
        if once:
            return total
        import time
        time.sleep(max(float(interval), 0.5))
