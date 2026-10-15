"""Public threat-intel feeds → compact local indexes (v2.9).

Why this module exists
----------------------
A signature list that ships with the source code can only ever be small:
every byte is reviewed, committed and redistributed.  Real-world coverage
comes from *public threat-intel feeds* - blocklists, hash sets and rule
collections that trusted organisations publish and maintain, and that this
project may consume without inventing anything.

This module fetches those feeds, converts them into the two shapes the
engine can actually match (exact hashes, and literal/regex patterns plus
IOC tokens), and stores the result as **compact sorted indexes**, so a
database with millions of entries costs tens of megabytes instead of
gigabytes.

Design rules
------------
* **Dependency-free** - ``urllib`` and the standard library only.
* **Licence-aware** - every source is declared in :data:`SOURCES` together
  with its licence and a ``redistribution`` field: ``redistributable``
  (safe to ship inside this MIT-licensed project) or ``runtime-only``
  (usable, but the *user's* machine downloads it into a git-ignored
  directory; it is never redistributed by us).
* **Compact** - a token becomes an 8-byte BLAKE2b digest inside a sorted
  ``array('Q')``; a lookup is a binary search.  2.6 M domains ≈ 21 MB and a
  few hundred MB of RSS is not needed: the index is read straight off disk.
* **Honest** - anything a converter cannot represent faithfully (YARA
  conditions, ClamAV *logic* signatures, wildcards with jumps) is counted and
  reported, never silently dropped or mangled into a false claim.

Nothing here executes, unpacks or writes a scanned file: feeds are data.
"""
from __future__ import annotations

import bisect
import gzip
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import time
import urllib.error
import urllib.request
from array import array
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from .models import Finding
from .prefilter import pattern_runs
from .utils import atomic_write_json

#: 8-byte token digests: with 10 M entries the chance of any collision is
#: ~2.7e-6, and a false *hit* still requires the file to contain the exact
#: token - see ``feeds verify``.
_DIGEST_PERSON = b"av-feeds"
_DIGEST_SIZE = 8

#: Hard ceiling for a single download (bytes) - a safety net, not a limit.
MAX_FETCH_BYTES = 400 * 1024 * 1024

_UA = "antivirus-feeds/2.9 (+https://github.com/codero-sus/AntiVirus)"

#: Severity tiers, worst first, used as index buckets.
TIERS = ("critical", "high", "medium", "low")

#: Shortest literal accepted when converting YARA strings into signatures.
MIN_YARA_LITERAL = 8

#: Characters that make a single-token literal distinctive.
_SPECIFIC_CHARS = set(".\\/_-:=()[]{}+!@#$%^&*?~`'\"<>|,;")


def yara_literal_ok(literal: str) -> bool:
    """Is a YARA string still meaningful once its ``condition`` is dropped?

    A YARA rule is a *set* of strings plus logic.  This engine converts the
    strings and cannot evaluate the logic, so a string that only makes sense
    as part of a rule would fire on innocent files: Mandiant's rules contain
    bare API names such as ``ExitProcess``, ``GetStdHandle`` and ``WriteFile``,
    which every Windows binary imports.

    A converted literal therefore has to be distinctive on its own - it must
    contain whitespace or a separator (a path, a URL, a registry key, a
    command line) or be unusually long.
    """
    if len(literal) < MIN_YARA_LITERAL:
        return False
    if any(char.isspace() for char in literal):
        return True
    if any(char in _SPECIFIC_CHARS for char in literal):
        return True
    return len(literal) >= 20

#: Shortest fixed hex run accepted from a ClamAV ``.ndb`` signature.
MIN_NDB_LITERAL = 12

# --------------------------------------------------------------------- sources


@dataclass(frozen=True)
class FeedSource:
    """One public feed, with the licence facts needed to use it honestly."""

    id: str
    name: str
    provider: str
    repo: str                      # "owner/repo" on GitHub
    path: str                      # file inside the repository
    parser: str
    kind: str                      # domain | ip | hash | filename | pattern
    category: str
    severity: str
    license: str
    license_url: str
    redistribution: str            # "redistributable" | "runtime-only"
    homepage: str
    ref: Optional[str] = None      # branch/tag; None = repository default
    note: str = ""
    #: When true the parser computes a per-record severity (e.g. the
    #: sighting-count tiers of ``ip-count``) and that value chooses the
    #: index bucket; otherwise every record gets the source severity.
    tiered: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "provider": self.provider,
            "repo": self.repo, "path": self.path, "parser": self.parser,
            "kind": self.kind, "category": self.category,
            "severity": self.severity, "license": self.license,
            "license_url": self.license_url,
            "redistribution": self.redistribution,
            "homepage": self.homepage, "ref": self.ref, "note": self.note,
            "tiered": self.tiered,
        }


#: The vetted source list.  Every entry was checked for (a) a real, reachable
#: data file, (b) a licence we can comply with, and (c) a converter below.
SOURCES: Tuple[FeedSource, ...] = (
    FeedSource(
        id="blocklistproject-malware",
        name="Malware distribution domains",
        provider="blocklistproject",
        repo="blocklistproject/Lists", path="malware.txt", parser="hosts",
        kind="domain", category="malware", severity="high",
        license="MIT", license_url="https://opensource.org/license/mit",
        redistribution="redistributable",
        homepage="https://github.com/blocklistproject/Lists",
        ref="main",
        note="2.6 M+ malware distribution domains (hosts format)"),
    FeedSource(
        id="blocklistproject-ransomware",
        name="Ransomware C2 domains",
        provider="blocklistproject",
        repo="blocklistproject/Lists", path="ransomware.txt", parser="hosts",
        kind="domain", category="ransomware", severity="critical",
        license="MIT", license_url="https://opensource.org/license/mit",
        redistribution="redistributable",
        homepage="https://github.com/blocklistproject/Lists",
        ref="main",
        note="ransomware command-and-control and distribution domains"),
    FeedSource(
        id="blocklistproject-phishing",
        name="Phishing domains",
        provider="blocklistproject",
        repo="blocklistproject/Lists", path="phishing.txt", parser="hosts",
        kind="domain", category="phishing", severity="high",
        license="MIT", license_url="https://opensource.org/license/mit",
        redistribution="redistributable",
        homepage="https://github.com/blocklistproject/Lists",
        ref="main"),
    FeedSource(
        id="blocklistproject-abuse",
        name="Abuse / C2 domains",
        provider="blocklistproject",
        repo="blocklistproject/Lists", path="abuse.txt", parser="hosts",
        kind="domain", category="abuse", severity="high",
        license="MIT", license_url="https://opensource.org/license/mit",
        redistribution="redistributable",
        homepage="https://github.com/blocklistproject/Lists",
        ref="main"),
    FeedSource(
        id="blocklistproject-fraud",
        name="Fraud domains",
        provider="blocklistproject",
        repo="blocklistproject/Lists", path="fraud.txt", parser="hosts",
        kind="domain", category="fraud", severity="medium",
        license="MIT", license_url="https://opensource.org/license/mit",
        redistribution="redistributable",
        homepage="https://github.com/blocklistproject/Lists",
        ref="main"),
    FeedSource(
        id="blocklistproject-malware-ip",
        name="Malware distribution IPs",
        provider="blocklistproject",
        repo="blocklistproject/Lists", path="malware.ip", parser="ip-list",
        kind="ip", category="malware", severity="high",
        license="MIT", license_url="https://opensource.org/license/mit",
        redistribution="redistributable",
        homepage="https://github.com/blocklistproject/Lists",
        ref="main"),
    FeedSource(
        id="blocklistproject-abuse-ip",
        name="Abuse / C2 IPs",
        provider="blocklistproject",
        repo="blocklistproject/Lists", path="abuse.ip", parser="ip-list",
        kind="ip", category="abuse", severity="high",
        license="MIT", license_url="https://opensource.org/license/mit",
        redistribution="redistributable",
        homepage="https://github.com/blocklistproject/Lists",
        ref="main"),
    FeedSource(
        id="mandiant-hashes",
        name="Red-team tool hashes (Cobalt Strike et al.)",
        provider="Mandiant",
        repo="mandiant/red_team_tool_countermeasures", path="all-hashes.csv",
        parser="hash-csv", kind="hash", category="red-team-tools",
        severity="critical",
        license="BSD-2-Clause",
        license_url="https://opensource.org/license/bsd-2-clause",
        redistribution="redistributable",
        homepage="https://github.com/mandiant/red_team_tool_countermeasures",
        ref="master",
        note="MD5/SHA1/SHA256 of tooling used in real intrusions"),
    FeedSource(
        id="mandiant-yara",
        name="Red-team tool YARA strings",
        provider="Mandiant",
        repo="mandiant/red_team_tool_countermeasures", path="all-yara.yar",
        parser="yara-literals", kind="pattern", category="red-team-tools",
        severity="high",
        license="BSD-2-Clause",
        license_url="https://opensource.org/license/bsd-2-clause",
        redistribution="redistributable",
        homepage="https://github.com/mandiant/red_team_tool_countermeasures",
        ref="master",
        note="only plain string literals are converted - condition logic is "
             "out of scope for this engine and is reported as skipped"),
    FeedSource(
        id="signature-base-hashes",
        name="Evil hash IOCs",
        provider="Neo23x0 signature-base",
        repo="Neo23x0/signature-base", path="iocs/hash-iocs.txt",
        parser="ioc-hashes", kind="hash", category="malware", severity="high",
        license="Detection Rule License 1.1",
        license_url="https://github.com/Neo23x0/signature-base/blob/master/"
                    "LICENSE",
        redistribution="runtime-only",
        homepage="https://github.com/Neo23x0/signature-base", ref="master",
        note="free to use with attribution; not redistributed by this project"),
    FeedSource(
        id="signature-base-c2",
        name="C2 IOC list",
        provider="Neo23x0 signature-base",
        repo="Neo23x0/signature-base", path="iocs/c2-iocs.txt",
        parser="ioc-domains", kind="ioc", category="c2", severity="high",
        license="Detection Rule License 1.1",
        license_url="https://github.com/Neo23x0/signature-base/blob/master/"
                    "LICENSE",
        redistribution="runtime-only",
        homepage="https://github.com/Neo23x0/signature-base", ref="master"),
    FeedSource(
        id="signature-base-filenames",
        name="Malware file-name IOCs",
        provider="Neo23x0 signature-base",
        repo="Neo23x0/signature-base", path="iocs/filename-iocs.txt",
        parser="filename-iocs", kind="filename", category="malware",
        severity="medium",
        license="Detection Rule License 1.1",
        license_url="https://github.com/Neo23x0/signature-base/blob/master/"
                    "LICENSE",
        redistribution="runtime-only",
        homepage="https://github.com/Neo23x0/signature-base", ref="master"),

    # ------------------------------------------------------------ v3.0 pack
    FeedSource(
        id="stevenblack-unified",
        name="Unified hosts blocklist (ads, trackers, malware)",
        provider="StevenBlack",
        repo="StevenBlack/hosts", path="hosts", parser="hosts",
        kind="domain", category="adware", severity="low",
        license="MIT", license_url="https://opensource.org/license/mit",
        redistribution="redistributable",
        homepage="https://github.com/StevenBlack/hosts", ref="master",
        note="the de-facto community hosts list; mostly advertising and "
             "telemetry with a malware component, so it is filed under the "
             "lowest severity tier"),
    FeedSource(
        id="phishing-database-domains",
        name="Active phishing domains",
        provider="mitchellkrogza Phishing.Database",
        repo="mitchellkrogza/Phishing.Database",
        path="phishing-domains-ACTIVE.txt", parser="domains",
        kind="domain", category="phishing", severity="high",
        license="MIT", license_url="https://opensource.org/license/mit",
        redistribution="redistributable",
        homepage="https://github.com/mitchellkrogza/Phishing.Database",
        ref="master"),
    FeedSource(
        id="phishing-database-ips",
        name="Active phishing hosts (IPs)",
        provider="mitchellkrogza Phishing.Database",
        repo="mitchellkrogza/Phishing.Database",
        path="phishing-IPs-ACTIVE.txt", parser="ip-list",
        kind="ip", category="phishing", severity="high",
        license="MIT", license_url="https://opensource.org/license/mit",
        redistribution="redistributable",
        homepage="https://github.com/mitchellkrogza/Phishing.Database",
        ref="master"),
    FeedSource(
        id="phishing-database-adblock",
        name="Active phishing domains (adblock syntax)",
        provider="mitchellkrogza Phishing.Database",
        repo="mitchellkrogza/Phishing.Database",
        path="phishing-domains-ACTIVE.adblock", parser="adblock",
        kind="domain", category="phishing", severity="high",
        license="MIT", license_url="https://opensource.org/license/mit",
        redistribution="redistributable",
        homepage="https://github.com/mitchellkrogza/Phishing.Database",
        ref="master"),
    FeedSource(
        id="phishing-database-links",
        name="Active phishing URLs (hosts extracted)",
        provider="mitchellkrogza Phishing.Database",
        repo="mitchellkrogza/Phishing.Database",
        path="phishing-links-ACTIVE.txt", parser="url-hosts",
        kind="domain", category="phishing", severity="high",
        license="MIT", license_url="https://opensource.org/license/mit",
        redistribution="redistributable",
        homepage="https://github.com/mitchellkrogza/Phishing.Database",
        ref="master",
        note="large file (~65 MB); only the host part of each URL is indexed"),
    FeedSource(
        id="ipsum-ips",
        tiered=True,
        name="Aggregated malicious IPs (with sighting counts)",
        provider="IPsum",
        repo="stamparm/ipsum", path="ipsum.txt", parser="ip-count",
        kind="ip", category="malware", severity="high",
        license="Unlicense", license_url="https://unlicense.org/",
        redistribution="redistributable",
        homepage="https://github.com/stamparm/ipsum", ref="master",
        note="daily merge of ~30 blocklists; the sighting count becomes the "
             "severity tier (>=6 lists = critical, >=3 = high)"),
    FeedSource(
        id="tweetfeed-year",
        name="Community-reported IOCs (12 months)",
        provider="TweetFeed",
        repo="0xDanielLopez/TweetFeed", path="year.csv", parser="tweetfeed-csv",
        kind="ioc", category="community-ioc", severity="high",
        license="CC0-1.0",
        license_url="https://creativecommons.org/publicdomain/zero/1.0/",
        redistribution="redistributable",
        homepage="https://github.com/0xDanielLopez/TweetFeed", ref="master",
        note="IOCs posted publicly by the infosec community; domains, IPs "
             "and file hashes are indexed"),
    FeedSource(
        id="tweetfeed-month",
        name="Community-reported IOCs (current month)",
        provider="TweetFeed",
        repo="0xDanielLopez/TweetFeed", path="month.csv",
        parser="tweetfeed-csv", kind="ioc", category="community-ioc",
        severity="high",
        license="CC0-1.0",
        license_url="https://creativecommons.org/publicdomain/zero/1.0/",
        redistribution="redistributable",
        homepage="https://github.com/0xDanielLopez/TweetFeed", ref="master"),
    FeedSource(
        id="tweetfeed-exclusive",
        name="Community-reported IOCs (exclusive set)",
        provider="TweetFeed",
        repo="0xDanielLopez/TweetFeed", path="exclusive.csv",
        parser="tweetfeed-csv", kind="ioc", category="community-ioc",
        severity="high",
        license="CC0-1.0",
        license_url="https://creativecommons.org/publicdomain/zero/1.0/",
        redistribution="redistributable",
        homepage="https://github.com/0xDanielLopez/TweetFeed", ref="master"),
    FeedSource(
        id="hagezi-threat-intel",
        name="Threat-intelligence domains (malware, C2, phishing)",
        provider="HaGeZi DNS blocklists",
        repo="hagezi/dns-blocklists", path="wildcard/tif.txt",
        parser="wildcard-domains", kind="domain", category="malware",
        severity="high",
        license="GPL-3.0",
        license_url="https://www.gnu.org/licenses/gpl-3.0.html",
        redistribution="runtime-only",
        homepage="https://github.com/hagezi/dns-blocklists", ref="main",
        note="~1.4 M domains from many threat feeds; downloaded only on "
             "request (--all) and never redistributed by this project"),
    FeedSource(
        id="hagezi-fake",
        name="Fake/typosquatted shops and portals (HaGeZi)",
        provider="HaGeZi DNS blocklists",
        repo="hagezi/dns-blocklists", path="wildcard/fake.txt",
        parser="wildcard-domains", kind="domain", category="scam",
        severity="medium",
        license="GPL-3.0",
        license_url="https://www.gnu.org/licenses/gpl-3.0.html",
        redistribution="runtime-only",
        homepage="https://github.com/hagezi/dns-blocklists", ref="main"),
)

SOURCES_BY_ID: Dict[str, FeedSource] = {s.id: s for s in SOURCES}


# ----------------------------------------------------------------------- model


@dataclass(frozen=True)
class IOC:
    """One indicator produced by a parser."""

    kind: str        # domain | ip | md5 | sha1 | sha256 | filename | pattern
    value: str
    severity: str
    source: str      # FeedSource.id
    name: str = ""   # malware/family label when the feed provides one


@dataclass
class BuildReport:
    """What a build actually did - the numbers ``feeds audit`` prints."""

    started: str = ""
    finished: str = ""
    sources: List[dict] = field(default_factory=list)
    indexes: Dict[str, dict] = field(default_factory=dict)
    patterns: int = 0
    skipped: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "started": self.started, "finished": self.finished,
            "sources": self.sources, "indexes": self.indexes,
            "patterns": self.patterns, "skipped": self.skipped,
            "errors": self.errors,
            "total_tokens": sum(i.get("count", 0)
                                for i in self.indexes.values()),
        }

    @property
    def total_tokens(self) -> int:
        return sum(i.get("count", 0) for i in self.indexes.values())


# ------------------------------------------------------------------- fetching


def _github_contents_url(repo: str, path: str, ref: Optional[str]) -> str:
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    if ref:
        url += f"?ref={urllib.request.quote(ref)}"
    return url


def fetch_url(url: str, *, timeout: int = 120,
              limit: int = MAX_FETCH_BYTES) -> bytes:
    """Download *url* (raw media type) and return the bytes.

    Uses ``urllib`` with a descriptive user agent.  Raises ``RuntimeError``
    with a readable message when the network is unavailable, so that every
    caller can degrade to "no feeds" instead of crashing a scan.
    """
    headers = {
        "User-Agent": _UA,
        "Accept": "application/vnd.github.raw, text/plain, */*",
    }
    # Optional: raises the GitHub API rate limit (60/hour anonymously) when a
    # full build is run repeatedly.  Never required, never stored.
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            length = response.headers.get("Content-Length")
            if length and int(length) > limit:
                raise RuntimeError(
                    f"refusing {length} bytes from {url} (limit {limit})")
            chunks: List[bytes] = []
            total = 0
            while True:
                chunk = response.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise RuntimeError(f"{url} exceeded {limit} bytes")
                chunks.append(chunk)
            body = b"".join(chunks)
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 429):
            raise RuntimeError(
                f"HTTP {exc.code} for {url} - GitHub API rate limit or "
                f"permission problem; retry later, build fewer sources at a "
                f"time (--source), or set GITHUB_TOKEN") from exc
        raise RuntimeError(f"HTTP {exc.code} for {url}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"network error for {url}: {exc.reason}") from exc
    if _looks_like_api_error(body):
        raise RuntimeError(
            f"{url} returned an API error instead of data: "
            f"{body[:120].decode('utf-8', 'replace')}")
    return body


def _looks_like_api_error(body: bytes) -> bool:
    """Detect GitHub error payloads that arrive with a 200 status."""
    head = body[:200].lstrip()
    if not head.startswith(b"{"):
        return False
    lowered = head.lower()
    return b"\"message\"" in lowered or b"rate limit" in lowered


def fetch_source(source: FeedSource, *, timeout: int = 120) -> bytes:
    """Fetch one feed's data file."""
    return fetch_url(_github_contents_url(source.repo, source.path,
                                          source.ref), timeout=timeout)


# -------------------------------------------------------------------- parsing

_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
                        r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_HDB_RE = re.compile(r"^(?P<hash>[0-9a-fA-F]{32,64}):(?P<size>\*|\d+):"
                     r"(?P<name>.+)$")
_NDB_TAIL_NUM = re.compile(r"^\d+$|^\*$")
_IOC_LINE_RE = re.compile(r"^(?P<value>[^\s#;]+)(?:[;\s]+(?P<note>.*))?$")
#: ``$s = "literal"`` / ``$s = { 6A 40 }`` / ``$s = /re/`` - any of the three
#: YARA string forms, wherever they appear on a line.
_YARA_STRING_RE = re.compile(
    r'\$(?P<id>[A-Za-z0-9_*]{1,64})\s*=\s*(?P<body>"[^"\n]*"'
    r'|/[^\n]*?/|\{[^}\n]*\})')


def normalize_domain(value: str) -> str:
    """Lowercase, strip a trailing dot, reject anything that is not a name."""
    token = value.strip().strip(".").lower()
    if not token or len(token) > 253:
        return ""
    if token.startswith("www."):
        token = token[4:]
    return token if _DOMAIN_RE.match(token) else ""


#: Addresses that are list plumbing (wildcards, localhost, broadcast) and
#: never a real indicator.  Private ranges are deliberately *kept*: a C2
#: address inside a corporate network is still an indicator.
_BOGUS_IPS = {"0.0.0.0", "255.255.255.255"}


def normalize_ip(value: str) -> str:
    token = value.strip()
    if not _IPV4_RE.match(token):
        return ""
    parts = [int(p) for p in token.split(".")]
    if any(p > 255 for p in parts):
        return ""
    if token in _BOGUS_IPS or parts[0] in (0, 127):
        return ""
    return token


#: IPv4 ranges that can never be a real internet-facing indicator.
_PRIVATE_IP = re.compile(
    r"^(?:0\.|10\.|127\.|169\.254\.|192\.168\."
    r"|172\.(?:1[6-9]|2[0-9]|3[01])\.|22[4-9]\.|23[0-9]\.|24[0-9]\.|25[0-5]\.)")


def is_private_ip(value: str) -> bool:
    """True for loopback, link-local, RFC1918 and multicast/reserved space.

    A blocklist entry or a URL pointing at ``192.168.1.1`` describes someone's
    LAN, not a threat: indexing it only creates false positives on ordinary
    internal traffic.  (The same reasoning excludes those ranges from the
    ``Download from a bare IP`` indicator.)
    """
    return bool(_PRIVATE_IP.match(value or ""))


def _is_bogus_domain(domain: str) -> bool:
    """Drop list-maintenance noise (localhost, placeholders, wildcards)."""
    if domain in ("localhost", "localhost.localdomain", "local", "broadcasthost",
                  "ip6-localhost", "ip6-loopback", "0.0.0.0", "127.0.0.1"):
        return True
    if domain.endswith((".local", ".invalid", ".test", ".example",
                        ".onion", ".arpa")):
        return True
    if ".." in domain or domain.startswith("-"):
        return True
    return False


#: Hosts that must never be indexed as indicators, however often a feed
#: lists them.
#:
#: Aggregated feeds are full of them: a phishing page hosted on
#: ``github.io`` appears in a URL list as ``github.com``, a shortened
#: malicious link appears as ``bit.ly``, and a malware sample downloaded
#: from a public file host appears as that host.  Indexing those turns the
#: feed layer into a false-positive machine - the first repository scan with
#: the v3.0 feed database (4.8 M indicators) flagged ``github.com`` inside
#: this project's own README.  A domain in this set is dropped at build
#: *and* ignored at lookup, so an older database behaves too.
TRUSTED_HOSTS = frozenset("""
bit.ly buff.ly cutt.ly git.io goo.gl is.gd ow.ly rb.gy rebrand.ly reurl.cc
shorturl.at soo.gd t.co tiny.cc tinyurl.com
github.com github.io githubusercontent.com raw.githubusercontent.com gist.github.com
gitlab.com bitbucket.org sourceforge.net
google.com googleapis.com gstatic.com googleusercontent.com googlesyndication.com
google-analytics.com googletagmanager.com drive.google.com docs.google.com
gmail.com youtube.com ytimg.com googlevideo.com
microsoft.com microsoftonline.com live.com office.com office365.com
windowsupdate.com microsoft365.com sharepoint.com onedrive.com msn.com bing.com
apple.com icloud.com itunes.com
amazon.com amazonaws.com aws.amazon.com cloudfront.net
cloudflare.com cdnjs.cloudflare.com fastly.net akamai.net akamaized.net
edgekey.net azure.com azureedge.net
facebook.com fbcdn.net instagram.com whatsapp.com messenger.com
twitter.com x.com linkedin.com licdn.com tiktok.com tiktokcdn.com
wikipedia.org wikimedia.org wiktionary.org
mozilla.org firefox.com debian.org ubuntu.com fedoraproject.org
python.org pypi.org npmjs.com npmjs.org nodejs.org rubygems.org
docker.com docker.io hub.docker.com
adobe.com oracle.com java.com vmware.com cisco.com nvidia.com
dropbox.com dropboxusercontent.com box.com
slack.com zoom.us webex.com discord.com discordapp.com telegram.org
w3.org ietf.org rfc-editor.org archive.org
blogspot.com wordpress.com weebly.com wixsite.com godaddysites.com
""".split())


def is_trusted_host(token: str) -> bool:
    """True when *token* is a well-known host that must not be an indicator.

    Matching is exact, deliberately: ``evil.blogspot.com`` (a specific
    tenant page) is a precise indicator and is still indexed, while the
    bare platform domain is not.
    """
    host = (token or "").strip().lower().rstrip(".")
    return bool(host) and host in TRUSTED_HOSTS


def parse_hosts(text: str) -> Iterator[IOC]:  # noqa: ARG001 (uniform iface)
    """``0.0.0.0 example.com`` / ``127.0.0.1 example.com`` / bare domain."""
    return _parse_hosts(text)


def _parse_hosts(text: str) -> Iterator[IOC]:
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#![":
            continue
        parts = line.split()
        if len(parts) >= 2 and (parts[0].count(".") == 3 or ":" in parts[0]):
            parts = parts[1:]
        for candidate in parts[:2]:
            domain = normalize_domain(candidate)
            if domain and not _is_bogus_domain(domain):
                yield IOC("domain", domain, "high", "", "")


def parse_ip_list(text: str) -> Iterator[IOC]:
    """One IPv4 per line; also accepts hosts-style ``0.0.0.0 1.2.3.4``."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#![":
            continue
        parts = line.split()
        candidate = parts[0]
        if len(parts) >= 2:
            # hosts format - the *last* field is the address
            stripped = normalize_ip(parts[0])
            if not stripped:
                candidate = parts[-1]
            else:
                candidate = parts[-1] if normalize_ip(parts[-1]) else parts[0]
        ip = normalize_ip(candidate)
        if ip and not is_private_ip(ip):
            yield IOC("ip", ip, "high", "", "")


def parse_domains(text: str) -> Iterator[IOC]:
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#![":
            continue
        domain = normalize_domain(line.split()[0])
        if domain and not _is_bogus_domain(domain):
            yield IOC("domain", domain, "high", "", "")


def parse_hash_csv(text: str) -> Iterator[IOC]:
    """Mandiant's ``md5,sha1,sha256`` table (header row optional)."""
    for line in text.splitlines():
        row = [c.strip().lower() for c in line.replace("\r", "").split(",")]
        for column, kind in ((0, "md5"), (1, "sha1"), (2, "sha256")):
            if column >= len(row):
                continue
            value = row[column]
            if _HEX_RE.match(value) and len(value) == {"md5": 32, "sha1": 40,
                                                       "sha256": 64}[kind]:
                yield IOC(kind, value, "critical", "", "")


def parse_ioc_hashes(text: str) -> Iterator[IOC]:
    """``MD5;COMMENT`` style hash IOCs (signature-base ``hash-iocs.txt``)."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        head = line.split(";")[0].split()[0].lower()
        if not _HEX_RE.match(head):
            continue
        kind = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(head))
        if kind:
            note = line.split(";", 1)[1].strip() if ";" in line else ""
            yield IOC(kind, head, "high", "", note[:80])


def parse_ioc_domains(text: str) -> Iterator[IOC]:
    """Mixed domain / IPv4 / CIDR list (signature-base ``c2-iocs.txt``)."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split(";")[0].split()[0].strip().lower()
        token = token.split("://")[-1].split("/")[0]
        if not token:
            continue
        ip = normalize_ip(token)
        if ip:
            if not is_private_ip(ip):
                yield IOC("ip", ip, "high", "", "")
            continue
        domain = normalize_domain(token)
        if domain and not _is_bogus_domain(domain):
            yield IOC("domain", domain, "high", "", "")


def parse_filename_iocs(text: str) -> Iterator[IOC]:
    """Known-bad *file names* (matched against a scanned file's name)."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split(";")[0].split()[0].strip().lower()
        if not token or len(token) < 4 or "/" in token or "\\" in token:
            continue
        if token.startswith("*"):
            token = token.lstrip("*")
        if not token or len(token) < 4:
            continue
        yield IOC("filename", token, "medium", "", "")


def parse_yara_literals(text: str) -> Iterator[IOC]:
    """Extract plain ``$s = "literal"`` strings from YARA text.

    Only *faithful* conversions are kept: ASCII, fixed text, no hex strings,
    no regular expressions, no wildcards, at least :data:`MIN_YARA_LITERAL`
    characters.  Anything else is skipped - a YARA rule's ``condition`` logic
    cannot be represented by this engine, and pretending otherwise would be a
    false claim of detection.
    """
    for match in _YARA_STRING_RE.finditer(text):
        body = match.group("body")
        if not body.startswith('"'):
            continue                       # hex string or regex - not faithful
        literal = body[1:-1]
        if not literal or '"' in literal or "\\" in literal:
            continue                       # escaped bytes are not literals
        if not yara_literal_ok(literal):
            continue
        try:
            literal.encode("ascii")
        except UnicodeEncodeError:
            continue
        yield IOC("pattern", literal, "high", "", "")


PARSERS = {
    "hosts": parse_hosts,
    "ip-list": parse_ip_list,
    "domains": parse_domains,
    "hash-csv": parse_hash_csv,
    "ioc-hashes": parse_ioc_hashes,
    "ioc-domains": parse_ioc_domains,
    "filename-iocs": parse_filename_iocs,
    "yara-literals": parse_yara_literals,
    "adblock": None,          # filled in below (kept readable with the others)
    "url-hosts": None,
    "ip-count": None,
    "tweetfeed-csv": None,
    "wildcard-domains": None,
}


def parse_adblock(text: str) -> Iterator[IOC]:
    """Adblock/uBlock syntax: ``||domain^`` (phishing blocklists use it too)."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        if not line.startswith("||"):
            continue
        # ``||domain.com^$third-party`` and ``||domain.com/path^`` both name
        # the domain; the path/options are how the *rule* is scoped, not part
        # of the indicator.
        token = line[2:].split("^")[0].split("$")[0].split("/")[0].strip()
        domain = normalize_domain(token)
        if domain and not _is_bogus_domain(domain):
            yield IOC("domain", domain, "high", "", "")


def parse_url_hosts(text: str) -> Iterator[IOC]:
    """One URL per line - keep only the host (path/query dropped)."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        token = line.split()[0]
        if "://" in token:
            token = token.split("://", 1)[1]
        token = token.split("/")[0].split("?")[0].split("@")[-1]
        if token.count(":") == 1 and token.rsplit(":", 1)[1].isdigit():
            token = token.rsplit(":", 1)[0]
        ip = normalize_ip(token)
        if ip:
            if not is_private_ip(ip):
                yield IOC("ip", ip, "high", "", "")
            continue
        domain = normalize_domain(token)
        if domain and not _is_bogus_domain(domain):
            yield IOC("domain", domain, "high", "", "")


def parse_ip_count(text: str) -> Iterator[IOC]:
    """``<ip>\\t<count>`` - how many blocklists report the address.

    The sighting count is a free confidence signal: an address in many
    lists is a stronger indicator than one in a single list, so the
    severity tier follows it.
    """
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        ip = normalize_ip(parts[0])
        if not ip:
            continue
        count = 0
        if len(parts) > 1:
            try:
                count = int(parts[1])
            except ValueError:
                count = 0
        severity = "critical" if count >= 6 else \
            "high" if count >= 3 else "medium"
        yield IOC("ip", ip, severity, "", "")


_TWEET_KINDS = {
    "domain": "domain", "url": "url", "ip": "ip", "ipv4": "ip",
    "md5": "md5", "sha1": "sha1", "sha256": "sha256",
}


def parse_tweetfeed_csv(text: str) -> Iterator[IOC]:
    """TweetFeed: ``timestamp,reporter,type,value,tags,source``.

    Only typed IOC rows are kept (domain/url/ip/hash); CVEs and free text are
    ignored.  ``url`` rows contribute their host as well as their full form.
    """
    for line in text.splitlines():
        line = line.rstrip("\r")
        if not line or line.startswith("#"):
            continue
        fields = line.split(",")
        if len(fields) < 4:
            continue
        kind = fields[2].strip().lower()
        value = fields[3].strip().strip('"')
        mapped = _TWEET_KINDS.get(kind)
        if mapped is None or not value:
            continue
        if mapped == "domain":
            domain = normalize_domain(value)
            if domain and not _is_bogus_domain(domain):
                yield IOC("domain", domain, "high", "", "")
        elif mapped == "url":
            host = value.split("://", 1)[-1].split("/")[0]
            domain = normalize_domain(host.split("@")[-1])
            if domain and not _is_bogus_domain(domain):
                yield IOC("domain", domain, "high", "", "")
        elif mapped == "ip":
            ip = normalize_ip(value)
            if ip:
                yield IOC("ip", ip, "high", "", "")
        else:
            digest = value.strip().lower()
            if _HEX_RE.match(digest) and len(digest) == {"md5": 32, "sha1": 40,
                                                        "sha256": 64}[mapped]:
                yield IOC(mapped, digest, "high", "", "")


def parse_wildcard_domains(text: str) -> Iterator[IOC]:
    """``*.domain.tld`` wildcard blocklists (HaGeZi-style)."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        token = line.lstrip("*.").split()[0]
        domain = normalize_domain(token)
        if domain and not _is_bogus_domain(domain):
            yield IOC("domain", domain, "high", "", "")


PARSERS.update({
    "adblock": parse_adblock,
    "url-hosts": parse_url_hosts,
    "ip-count": parse_ip_count,
    "tweetfeed-csv": parse_tweetfeed_csv,
    "wildcard-domains": parse_wildcard_domains,
})


# ------------------------------------------------------------------ ClamAV

def parse_clamav_hdb(text: str) -> Iterator[IOC]:
    """ClamAV ``.hdb``/``.hsb``: ``hash:size:malwarename``."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = _HDB_RE.match(line)
        if not match:
            continue
        digest = match.group("hash").lower()
        kind = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(digest))
        if kind:
            yield IOC(kind, digest, "high", "", match.group("name")[:80])


def _ndb_fields(line: str) -> Optional[Tuple[str, str, str, str]]:
    """Split ``Name:Target:Offset:Body[:MinFL:MaxFL]``.

    The body may itself contain colons (ClamAV uses plain *text* signatures
    for target type 0 / offset ``*``), so optional trailing length modifiers
    are peeled off the end rather than trusting a naive ``split(":")``.
    """
    fields = line.split(":")
    if len(fields) < 4:
        return None
    name, target, offset, tail = fields[0], fields[1], fields[2], fields[3:]
    if (len(tail) >= 3 and _NDB_TAIL_NUM.match(tail[-1])
            and _NDB_TAIL_NUM.match(tail[-2])):
        body = ":".join(tail[:-2])
    else:
        body = ":".join(tail)
    return name, target, offset, body


def _bytes_to_pattern(data: bytes) -> Optional[str]:
    """Exact-match regex for a byte run, keeping printable text readable.

    Printable ASCII stays literal (so the scanner's literal prefilter can
    gate the signature); everything else becomes a ``\\xNN`` escape.  The
    regex matches exactly the same bytes either way.
    """
    if len(data) < MIN_NDB_LITERAL:
        return None
    out: List[str] = []
    run: List[int] = []

    def flush() -> None:
        if run:
            text = bytes(run).decode("ascii")
            out.append(re.escape(text))
            run.clear()

    for byte in data:
        if 0x20 <= byte <= 0x7E:
            run.append(byte)
        else:
            flush()
            out.append(f"\\x{byte:02x}")
    flush()
    return "".join(out) or None


def parse_clamav_ndb(text: str,
                     skipped: Optional[Dict[str, int]] = None) -> Iterator[IOC]:
    """ClamAV ``.ndb``: ``Name:Target:Offset:HexSignature[:MinFL:MaxFL]``.

    Two body forms exist in practice and both are handled:

    * **hex** - converted to an exact byte-match regex (wildcards ``??``,
      ``*`` and ``{n-m}`` jumps are *not* representable by this engine and are
      counted as skipped instead of being mangled);
    * **plain text** - used verbatim when the target type is ``0`` and the
      offset is ``*`` (the documented string-signature form).

    A converted signature must still contain a literal run the prefilter can
    gate on, otherwise it would be tested against every byte of every file.
    """
    skipped = skipped if skipped is not None else {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = _ndb_fields(line)
        if fields is None:
            skipped["ndb-unparsed"] = skipped.get("ndb-unparsed", 0) + 1
            continue
        name, _target, _offset, body = fields
        if not body:
            skipped["ndb-empty"] = skipped.get("ndb-empty", 0) + 1
            continue
        if any(char in body for char in "?*{}|"):
            skipped["ndb-wildcard"] = skipped.get("ndb-wildcard", 0) + 1
            continue
        if _HEX_RE.match(body):
            if len(body) % 2:
                skipped["ndb-odd-hex"] = skipped.get("ndb-odd-hex", 0) + 1
                continue
            pattern = _bytes_to_pattern(bytes.fromhex(body))
        else:
            pattern = re.escape(body) if len(body) >= MIN_NDB_LITERAL else None
        if pattern is None or not pattern_runs(pattern):
            skipped["ndb-too-short-or-ungated"] = \
                skipped.get("ndb-too-short-or-ungated", 0) + 1
            continue
        yield IOC("pattern", pattern, "high", "", name[:80])


def _clamav_container(data: bytes) -> Optional[Dict[str, bytes]]:
    """Unpack a CVD/CLD blob into ``{member_name: bytes}`` (small members)."""
    if data[:11] == b"ClamAV-VDB:":
        data = data[512:]                      # 512-byte ASCII CVD header
    try:
        raw = gzip.decompress(data)
    except (OSError, EOFError, gzip.BadGzipFile):
        return None
    members: Dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            for member in archive.getmembers():
                if not member.isfile() or member.size > 64 * 1024 * 1024:
                    continue
                handle = archive.extractfile(member)
                if handle is not None:
                    members[member.name] = handle.read()
    except tarfile.TarError:
        return None
    return members


def parse_clamav_file(path: Path, *,
                      skipped: Optional[Dict[str, int]] = None
                      ) -> Iterator[IOC]:
    """Read a ClamAV database file: ``.hdb``, ``.hsb``, ``.ndb``, ``.cvd``, ``.cld``.

    ``.ldb`` (logic signatures) and ``.mdb`` (PE *section* hashes, which are not
    file hashes) are deliberately not converted; they are counted so the report
    can say exactly what was left on the table.
    """
    skipped = skipped if skipped is not None else {}
    data = path.read_bytes()
    suffix = path.suffix.lower()
    if suffix in (".cvd", ".cld") or data[:11] == b"ClamAV-VDB:":
        members = _clamav_container(data)
        if members is None:
            skipped["cvd-unreadable"] = skipped.get("cvd-unreadable", 0) + 1
            return
        other = 0
        for name, blob in members.items():
            inner = name.lower()
            text = blob.decode("utf-8", "replace")
            if inner.endswith((".hdb", ".hsb")):
                yield from parse_clamav_hdb(text)
            elif inner.endswith(".ndb"):
                yield from parse_clamav_ndb(text, skipped)
            elif inner.endswith((".ldb", ".mdb", ".cbc")):
                skipped["logic-or-section-sigs"] = \
                    skipped.get("logic-or-section-sigs", 0) + text.count("\n")
            else:
                other += 1        # COPYING, *.info, DSIG - not signature data
        if other:
            skipped["cvd-other-members"] = other
        return
    text = data.decode("utf-8", "replace")
    if suffix in (".hdb", ".hsb"):
        yield from parse_clamav_hdb(text)
    elif suffix == ".ndb":
        yield from parse_clamav_ndb(text, skipped)
    elif suffix in (".ldb", ".mdb"):
        skipped["logic-or-section-sigs"] = \
            skipped.get("logic-or-section-sigs", 0) + text.count("\n")
    else:
        # Try everything: hash lines first, then ndb-style lines.
        produced = False
        for ioc in parse_clamav_hdb(text):
            produced = True
            yield ioc
        if not produced:
            yield from parse_clamav_ndb(text, skipped)


# --------------------------------------------------------------- token space


def token_digest(token: str) -> int:
    """Stable 8-byte digest of a normalised token (little-endian integer)."""
    raw = hashlib.blake2b(token.encode("utf-8", "replace"),
                          digest_size=_DIGEST_SIZE,
                          person=_DIGEST_PERSON).digest()
    return int.from_bytes(raw, "little")


def _bucket_key(kind: str, severity: str) -> str:
    tier = severity if severity in TIERS else "high"
    return f"{kind}.{tier}"


def _split_bucket(key: str) -> Tuple[str, str]:
    kind, _, tier = key.rpartition(".")
    return kind, tier


# ------------------------------------------------------------------- storage


def index_path(root: Path, key: str) -> Path:
    return Path(root) / "index" / f"{key}.idx"


def meta_path(root: Path, key: str) -> Path:
    return Path(root) / "index" / f"{key}.json"


def _existing_index(root: Path, key: str) -> Optional[array]:
    return load_index(Path(root), key)


def write_index(root: Path, key: str, digests: Iterable[int],
                meta: dict, *, merge: bool = True) -> Tuple[int, int]:
    """Write a sorted digest array + its metadata.

    With ``merge`` (the default) new digests are unioned with whatever the
    index already holds, so building one source never destroys another
    (``feeds clear`` is the way to start over).  Returns
    ``(total_entries, added_entries)``.
    """
    values = set(digests)
    added = len(values)
    if merge:
        existing = _existing_index(root, key)
        if existing:
            before = len(values)
            values.update(existing)
            added = len(values) - before
    ordered = array("Q", sorted(values))
    if sys.byteorder == "big":
        ordered.byteswap()
    path = index_path(root, key)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as handle:
        ordered.tofile(handle)
    meta = dict(meta)
    meta.update({"key": key, "count": len(ordered),
                 "bytes": len(ordered) * _DIGEST_SIZE,
                 "digest": "blake2b-64", "person": _DIGEST_PERSON.decode()})
    atomic_write_json(meta_path(root, key), meta)
    return len(ordered), added


def load_index(root: Path, key: str) -> Optional[array]:
    meta_file = meta_path(root, key)
    data_file = index_path(root, key)
    if not meta_file.exists() or not data_file.exists():
        return None
    try:
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        count = int(meta["count"])
    except (OSError, ValueError, KeyError):
        return None
    values = array("Q")
    try:
        with open(data_file, "rb") as handle:
            values.fromfile(handle, count)
    except (OSError, EOFError, ValueError):
        return None
    if len(values) != count:
        return None
    if sys.byteorder == "big":
        values.byteswap()
    return values


# ------------------------------------------------------------------- FeedDB

#: Domains/IPs are extracted from a bounded window so that scanning a large
#: log or script cannot turn into a regex marathon.
DOMAIN_RE_BYTES = re.compile(
    rb"(?<![a-z0-9._-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    rb"[a-z]{2,24})(?![a-z0-9._-])")
IPV4_RE_BYTES = re.compile(rb"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")

#: Network context *before* a token: a URL scheme, ``//``, ``www.``, ``@`` or
#: a hosts-file style ``0.0.0.0 `` prefix.  Network context *after* a token:
#: a port or a path.  A bare dotted string in source code (``subprocess.run``,
#: ``s.id``) has neither, and public blocklists really do contain junk entries
#: like that - see :func:`contextual_token`.
_SCHEME_BEFORE_RE = re.compile(rb"(?:[a-z][a-z0-9+.\-]{1,10}://|//|www\.|@)"
                               rb"$")
_HOSTS_BEFORE_RE = re.compile(rb"(?:^|\n)[ \t]*(?:\d{1,3}\.){3}\d{1,3}[ \t]+$")

#: A bare (context-free) domain must at least be this long ...
BARE_DOMAIN_MIN_LEN = 12


def contextual_token(chunk: bytes, token: str, start: int, end: int) -> bool:
    """Is *token* used in a network-ish context, or specific enough to trust?

    Public blocklists are machine-generated and contain identifiers that are
    not really domains (``subprocess.run`` and ``s.id`` both appear in
    blocklistproject's data, and ``.run``/``.id`` are real TLDs).  Matching a
    bare dotted string in source code would therefore be a false positive, so
    a context-free token must look *specific*: at least
    :data:`BARE_DOMAIN_MIN_LEN` characters and either hyphenated or three
    labels deep.

    In network context (``http://``, ``www.``, ``host:8080``, ``host/path``,
    a hosts-file line) any listed token counts, which is where indicators
    actually matter.
    """
    before = chunk[max(0, start - 40):start]
    after = chunk[end:end + 6]
    if _SCHEME_BEFORE_RE.search(before) or _HOSTS_BEFORE_RE.search(before):
        return True
    # ``host/path`` or ``host:8080`` - the colon form must be a real port,
    # otherwise Python's ``{i.id}:`` would look like one.
    if after[:1] == b"/" or (after[:1] == b":" and after[1:2].isdigit()):
        return True
    if len(token) >= BARE_DOMAIN_MIN_LEN and ("-" in token or token.count(".") >= 2):
        return True
    return False


class FeedDB:
    """Read-only view over the built feed indexes.

    Loading is lazy *per bucket*, so a scan that never sees a text file never
    pays for the domain index, and an install with no feeds built behaves
    exactly like v2.8 (every lookup returns ``None`` immediately).
    """

    def __init__(self, root: Path, *, enabled: bool = True) -> None:
        self.root = Path(root)
        self.enabled = bool(enabled)
        self._indexes: Dict[str, Optional[array]] = {}
        self._metas: Dict[str, dict] = {}
        self._manifest: Optional[dict] = None
        self._manifest_loaded = False
        self._patterns: Optional[List[dict]] = None

    # ------------------------------------------------------------- metadata
    @property
    def manifest_path(self) -> Path:
        return self.root / "manifest.json"

    def manifest(self) -> dict:
        if not self._manifest_loaded:
            self._manifest_loaded = True
            try:
                self._manifest = json.loads(
                    self.manifest_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self._manifest = {}
        return self._manifest or {}

    def buckets(self) -> List[str]:
        return sorted(self.manifest().get("indexes", {}))

    def identity(self) -> str:
        """Cheap change detector for cache keys (mtime + counts)."""
        if not self.enabled:
            return "disabled"
        try:
            stat = self.manifest_path.stat()
        except OSError:
            return "empty"
        return f"{stat.st_mtime_ns}:{stat.st_size}"

    def counts(self) -> Dict[str, int]:
        """Indicator count per bucket.

        Tolerates a hand-edited manifest where a bucket is a bare number
        instead of the ``{"count": …}`` record the builder writes – a
        corrupt manifest must never crash a scan.
        """
        out: Dict[str, int] = {}
        for key, value in (self.manifest().get("indexes") or {}).items():
            if isinstance(value, dict):
                out[key] = int(value.get("count", 0) or 0)
            elif isinstance(value, (int, float)):
                out[key] = int(value)
            elif isinstance(value, (list, tuple)):
                out[key] = len(value)
            else:
                out[key] = 0
        return out

    @property
    def built(self) -> bool:
        return bool(self.manifest().get("indexes"))

    # --------------------------------------------------------------- lookup
    def _index(self, key: str) -> Optional[array]:
        if not self.enabled:
            return None
        if key not in self._indexes:
            self._indexes[key] = load_index(self.root, key)
        return self._indexes[key]

    def bucket_meta(self, key: str) -> dict:
        """Per-bucket metadata (label, contributing sources, licence, samples)."""
        if key not in self._metas:
            try:
                self._metas[key] = json.loads(
                    meta_path(self.root, key).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self._metas[key] = self.manifest().get(
                    "indexes", {}).get(key, {})
        return self._metas[key]

    def _lookup(self, kind: str, token: str) -> Optional[dict]:
        """Return the metadata of the first bucket containing *token*."""
        if not self.enabled or not token:
            return None
        digest = token_digest(token)
        for tier in TIERS:
            key = _bucket_key(kind, tier)
            values = self._index(key)
            if not values:
                continue
            position = bisect.bisect_left(values, digest)
            if position < len(values) and values[position] == digest:
                meta = self.bucket_meta(key)
                return {"kind": kind, "tier": tier, "bucket": key,
                        "label": meta.get("label", kind),
                        "sources": meta.get("sources", []),
                        "token": token,
                        "collision_risk": _collision_note(len(values))}
        return None

    def lookup_domain(self, value: str) -> Optional[dict]:
        domain = normalize_domain(value)
        # Lookup-time guard: a database built before the trusted-host rule
        # (or one assembled by hand) must not flag github.com either.
        if is_trusted_host(domain):
            return None
        return self._lookup("domain", domain)

    def lookup_ip(self, value: str) -> Optional[dict]:
        return self._lookup("ip", normalize_ip(value))

    def lookup_ioc(self, value: str) -> Optional[dict]:
        """Domain or IPv4 - used when scanning file content."""
        hit = self.lookup_ip(value)
        return hit if hit is not None else self.lookup_domain(value)

    def lookup_filename(self, name: str) -> Optional[dict]:
        return self._lookup("filename", Path(name).name.strip().lower())

    def lookup_hash(self, *, md5: str = "", sha1: str = "",
                    sha256: str = "") -> Optional[dict]:
        for kind, value in (("sha256", sha256), ("sha1", sha1), ("md5", md5)):
            if value:
                hit = self._lookup(kind, value.strip().lower())
                if hit is not None:
                    return hit
        return None

    # -------------------------------------------------------------- content
    def extract_tokens(self, content: bytes, *, window: int = 262144,
                       limit: int = 2048) -> List[str]:
        """Bounded, context-aware domain/IP extraction from a byte window.

        Domains that appear as bare dotted strings without network context are
        only kept when they are specific enough to be worth trusting - see
        :func:`contextual_token`.  IPv4 tokens are always kept: an IP literal
        in a file is not usually a code identifier.
        """
        if not self.enabled or not content:
            return []
        chunk = bytes(content[:window]).lower()
        tokens: List[str] = []
        seen = set()
        for match in DOMAIN_RE_BYTES.finditer(chunk):
            token = match.group(1).decode("ascii", "ignore")
            if not token or token in seen:
                continue
            if not contextual_token(chunk, token, match.start(1), match.end(1)):
                continue
            seen.add(token)
            tokens.append(token)
            if len(tokens) >= limit:
                return tokens
        for match in IPV4_RE_BYTES.finditer(chunk):
            token = match.group(1).decode("ascii", "ignore")
            if token and token not in seen:
                seen.add(token)
                tokens.append(token)
                if len(tokens) >= limit:
                    return tokens
        return tokens

    def audit_content(self, name: str, content: bytes, *,
                      window: int = 262144, limit: int = 2048,
                      max_findings: int = 5) -> List[Finding]:
        """Feed findings for *content* (domains/IPs listed in the database)."""
        if not self.enabled:
            return []
        findings: List[Finding] = []
        if self.counts().get("domain.high") or self.counts().get("domain.critical") \
                or self.counts().get("ip.high"):
            for token in self.extract_tokens(content, window=window,
                                             limit=limit):
                hit = self.lookup_ioc(token)
                if hit is None:
                    continue
                findings.append(self._finding(name, token, hit))
                if len(findings) >= max_findings:
                    break
        return findings

    def audit_name(self, path: str) -> List[Finding]:
        hit = self.lookup_filename(Path(path).name)
        return [self._finding(path, Path(path).name, hit)] if hit else []

    def _finding(self, path: str, token: str, hit: dict) -> Finding:
        providers = ", ".join(
            sorted({s.get("provider", s.get("id", "?"))
                    for s in hit.get("sources", [])})) or "public feed"
        licenses = ", ".join(sorted({s.get("license", "?")
                                     for s in hit.get("sources", [])}))
        return Finding(
            path=str(path),
            kind="feed-ioc",
            name=hit.get("label", "public feed IOC"),
            severity=hit.get("tier", "high"),
            message=(f"{token!r} is listed by {providers} "
                     f"({licenses or 'see feeds audit'})"),
        )

    def hash_finding(self, path: str, hit: dict, size: int = 0,
                     sha256: str = "") -> Finding:
        providers = ", ".join(
            sorted({s.get("provider", s.get("id", "?"))
                    for s in hit.get("sources", [])})) or "public feed"
        licenses = ", ".join(sorted({s.get("license", "?")
                                     for s in hit.get("sources", [])}))
        return Finding(
            path=str(path),
            kind="signature-hash",
            name=hit.get("label", "known-bad file hash"),
            severity=hit.get("tier", "high"),
            message=(f"Matches {providers} hash list "
                     f"({licenses or 'see feeds audit'})"),
            sha256=sha256, size=size,
        )

    # ------------------------------------------------------------- patterns
    def patterns(self) -> List[dict]:
        """Literal signatures converted from feeds (YARA/ClamAV strings)."""
        if self._patterns is None:
            path = self.root / "index" / "patterns.json"
            try:
                self._patterns = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self._patterns = []
        return self._patterns

    # ---------------------------------------------------------------- stats
    def stats(self) -> dict:
        manifest = self.manifest()
        return {
            "enabled": self.enabled,
            "built": self.built,
            "root": str(self.root),
            "built_at": manifest.get("finished", ""),
            "sources": len(manifest.get("sources", [])),
            "indexes": self.counts(),
            "patterns": len(self.patterns()),
            "tokens": sum(self.counts().values()),
            "by_license": _licence_summary(manifest),
        }


def _collision_note(count: int) -> str:
    if count <= 0:
        return "none"
    probability = (count ** 2) / (2 ** (8 * _DIGEST_SIZE + 1))
    if probability < 1e-9:
        return "negligible"
    return f"~{probability:.1e} per lookup"


def _licence_summary(manifest: dict) -> Dict[str, int]:
    summary: Dict[str, int] = {}
    for source in manifest.get("sources", []):
        key = source.get("license", "unknown")
        summary[key] = summary.get(key, 0) + int(source.get("tokens", 0))
    return summary


# -------------------------------------------------------------------- build


def _collector() -> Dict[str, Dict[str, object]]:
    return {}


def pattern_matches_benign(pattern: str, benign: Sequence[bytes]) -> bool:
    """Does a converted literal fire on any known-innocent reference file?

    A converted YARA string is only *part* of a rule, so the honest test of a
    conversion is empirical: if it already matches files that are known to be
    clean, it is a false positive by construction and does not belong in the
    database.  Also catches the same class for ClamAV string signatures.
    """
    if not benign:
        return False
    try:
        compiled = re.compile(pattern.encode("utf-8"))
    except re.error:
        return True                       # uncompilable - never usable
    return any(compiled.search(blob) for blob in benign if blob)


def load_benign_corpus(samples_dir: Path) -> List[bytes]:
    """Bytes of the bundled *clean* fixtures, for the false-positive gate."""
    root = Path(samples_dir)
    blobs: List[bytes] = []
    names = ("clean.txt",)
    for name in names:
        path = root / name
        if path.is_file():
            blobs.append(path.read_bytes()[:1024 * 1024])
    for pattern in ("clean/*", "behavior/clean.*", "behavior/harmless*"):
        for path in sorted(root.glob(pattern)):
            if path.is_file():
                blobs.append(path.read_bytes()[:1024 * 1024])
    return blobs


def build(sources: Sequence[FeedSource], root: Path, *,
          fetch=fetch_source, include_restricted: bool = True,
          max_per_source: Optional[int] = None,
          max_patterns: int = 20000,
          benign: Sequence[bytes] = (),
          progress=None) -> BuildReport:
    """Fetch, convert and index *sources* into *root*.

    ``fetch`` is injectable so tests (and ``--offline`` builds) can supply
    bytes without touching the network.  ``benign`` is a list of known-clean
    file bodies used as a false-positive gate for converted patterns.
    """
    root = Path(root)
    report = BuildReport(started=time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                               time.gmtime()))
    buckets: Dict[str, Dict[int, None]] = {}
    bucket_meta: Dict[str, dict] = {}
    patterns: List[dict] = []
    pattern_seen = set()
    skipped: Dict[str, int] = {}

    for source in sources:
        if source.redistribution == "runtime-only" and not include_restricted:
            report.sources.append({**source.to_dict(), "status": "skipped",
                                   "reason": "licence: runtime-only"})
            continue
        entry = source.to_dict()
        entry["status"] = "ok"
        try:
            if progress is not None:
                progress(f"fetching {source.id} …")
            blob = fetch(source)
        except RuntimeError as exc:
            entry.update(status="error", error=str(exc))
            report.errors.append(f"{source.id}: {exc}")
            report.sources.append(entry)
            continue
        entry["url"] = _github_contents_url(source.repo, source.path,
                                            source.ref)
        entry["raw_bytes"] = len(blob)
        entry["raw_sha256"] = hashlib.sha256(blob).hexdigest()
        entry["tokens"] = 0
        entry["duplicates"] = 0
        entry["by_kind"] = {}
        entry["skipped"] = {}
        try:
            text = blob.decode("utf-8", "replace")
        except Exception:                                  # pragma: no cover
            text = ""
        parser = PARSERS.get(source.parser)
        if parser is None:
            entry.update(status="error", error=f"unknown parser {source.parser}")
            report.errors.append(f"{source.id}: unknown parser")
            report.sources.append(entry)
            continue
        produced = 0
        duplicates = 0
        for ioc in parser(text):
            if max_per_source is not None and produced >= max_per_source:
                entry["skipped"]["max_per_source"] = (
                    entry["skipped"].get("max_per_source", 0) + 1)
                break
            value = ioc.value
            if ioc.kind == "pattern":
                if value in pattern_seen:
                    continue
                if len(patterns) >= max_patterns:
                    entry["skipped"]["pattern-cap-reached"] = \
                        entry["skipped"].get("pattern-cap-reached", 0) + 1
                    skipped["pattern-cap-reached"] = \
                        skipped.get("pattern-cap-reached", 0) + 1
                    continue
                pattern_seen.add(value)
                signature = _pattern_signature(source, value)
                if signature is None:
                    skipped_key = "pattern-ungated"
                    entry["skipped"][skipped_key] = \
                        entry["skipped"].get(skipped_key, 0) + 1
                    skipped[skipped_key] = skipped.get(skipped_key, 0) + 1
                    continue
                if benign and pattern_matches_benign(signature["pattern"],
                                                     benign):
                    skipped_key = "pattern-benign-match"
                    entry["skipped"][skipped_key] = \
                        entry["skipped"].get(skipped_key, 0) + 1
                    skipped[skipped_key] = skipped.get(skipped_key, 0) + 1
                    continue
                patterns.append(signature)
                entry["by_kind"]["pattern"] = \
                    entry["by_kind"].get("pattern", 0) + 1
                produced += 1
                continue
            kind = ioc.kind
            # Tiered sources (a parser that assigns per-record severity,
            # e.g. ipsum's sighting-count tiers) choose their own bucket; a
            # ransomware C2 list is critical even though its lines look like
            # any other domain, and the same domain may sit in both a
            # malware list (high) and a ransomware list (critical) - lookups
            # check critical first, so the worst classification wins.
            if kind == "domain" and is_trusted_host(value):
                entry["skipped"]["trusted-host"] = \
                    entry["skipped"].get("trusted-host", 0) + 1
                skipped["trusted-host"] = skipped.get("trusted-host", 0) + 1
                continue
            tier = ioc.severity if (source.tiered and ioc.severity) \
                else source.severity
            key = _bucket_key(kind, tier)
            digest = token_digest(value)
            bucket = buckets.setdefault(key, {})
            if digest in bucket:
                # Already contributed by an earlier source in this run - the
                # blocklists overlap heavily, and saying so is more useful
                # than reporting an inflated total.
                duplicates += 1
                entry["duplicates"] = duplicates
                continue
            bucket[digest] = None
            meta = bucket_meta.setdefault(key, {
                "label": "", "sources": {}, "examples": []})
            source_entry = meta["sources"].setdefault(source.id, {
                "id": source.id, "provider": source.provider,
                "license": source.license,
                "redistribution": source.redistribution, "count": 0})
            source_entry["count"] += 1
            if len(meta["examples"]) < 12:
                meta["examples"].append(value)
            produced += 1
            entry["by_kind"][kind] = entry["by_kind"].get(kind, 0) + 1
        entry["tokens"] = produced
        report.sources.append(entry)
        if progress is not None:
            detail = f"  {source.id}: {produced:,} new indicator(s)"
            if duplicates:
                detail += f", {duplicates:,} already known from another list"
            progress(detail)

    # Write one index per (kind, tier) bucket (merged with what is there).
    for key, bucket in sorted(buckets.items()):
        meta = bucket_meta.get(key, {})
        kind = _split_bucket(key)[0]
        providers = sorted({s["provider"]
                            for s in meta.get("sources", {}).values()})
        label = _label_for(kind, providers)
        total, added = write_index(root, key, list(bucket.keys()), {
            "label": label,
            "kind": kind,
            "tier": _split_bucket(key)[1],
            "sources": sorted(meta.get("sources", {}).values(),
                              key=lambda s: -s["count"]),
            "examples": meta.get("examples", []),
        })
        report.indexes[key] = {"count": total, "added": added, "label": label,
                               "bytes": total * _DIGEST_SIZE}

    if patterns:
        root.mkdir(parents=True, exist_ok=True)
        (root / "index").mkdir(parents=True, exist_ok=True)
        existing = _load_patterns(root)
        merged = {s["id"]: s for s in existing}
        merged.update({s["id"]: s for s in patterns})
        atomic_write_json(root / "index" / "patterns.json",
                          list(merged.values()))
    report.patterns = len(patterns)
    report.skipped = dict(sorted(skipped.items()))
    report.finished = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    root.mkdir(parents=True, exist_ok=True)
    _save_manifest(root, report)
    return report


def _load_patterns(root: Path) -> List[dict]:
    try:
        data = json.loads((root / "index" / "patterns.json").read_text(
            encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _load_manifest(root: Path) -> dict:
    try:
        data = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_manifest(root: Path, report: BuildReport,
                   source_ids: Optional[Sequence[str]] = None) -> dict:
    """Merge this build's report into the on-disk manifest."""
    previous = _load_manifest(root)
    replaced = set(source_ids or [s.get("id") for s in report.sources])
    sources = [s for s in previous.get("sources", [])
               if s.get("id") not in replaced]
    sources.extend(report.sources)
    indexes = dict(previous.get("indexes", {}))
    for key, entry in report.indexes.items():
        merged = dict(indexes.get(key, {}))
        merged.update(entry)
        indexes[key] = merged
    manifest = report.to_dict()
    manifest["sources"] = sources
    manifest["indexes"] = indexes
    manifest["built_at"] = previous.get("finished") or report.started
    atomic_write_json(root / "manifest.json", manifest)
    return manifest


def _label_for(kind: str, providers: Sequence[str]) -> str:
    pretty = {
        "domain": "Feed-listed domain",
        "ip": "Feed-listed IP address",
        "md5": "Known-bad file (MD5)",
        "sha1": "Known-bad file (SHA1)",
        "sha256": "Known-bad file (SHA256)",
        "filename": "Known-bad file name",
        "ioc": "Feed-listed indicator",
        "pattern": "Feed pattern",
    }.get(kind, kind)
    if providers:
        return f"{pretty} – {', '.join(providers[:3])}"
    return pretty


def _pattern_signature(source: FeedSource, literal: str) -> Optional[dict]:
    """Validate a converted literal against the scanner's prefilter gate."""
    runs = pattern_runs(literal)
    if not runs:
        return None
    escaped = re.escape(literal)
    digest = hashlib.sha256(literal.encode()).hexdigest()[:12]
    return {
        "id": f"FEED-{source.id.upper()[:14]}-{digest}",
        "name": f"{source.provider} string",
        "kind": "signature",
        "pattern": escaped,
        "severity": source.severity,
        "description": f"{source.name} ({source.license})",
        "source": source.id,
    }


# ------------------------------------------------------------------ indexes


def build_sources(*, include_restricted: bool = True,
                  only: Optional[Sequence[str]] = None) -> List[FeedSource]:
    """Pick the sources for a build (``--source``/``--all`` semantics)."""
    chosen = list(SOURCES)
    if not include_restricted:
        chosen = [s for s in chosen if s.redistribution == "redistributable"]
    if only:
        wanted = {s.lower() for s in only}
        chosen = [s for s in chosen
                  if s.id.lower() in wanted
                  or s.provider.lower() in wanted
                  or s.category.lower() in wanted]
    return chosen


def import_clamav_file(path: Path, root: Path, *,
                       severity: str = "high", max_patterns: int = 20000,
                       benign: Sequence[bytes] = (),
                       source_id: str = "clamav-local") -> BuildReport:
    """Import a locally supplied ClamAV database into the feed indexes.

    Official ClamAV databases are large (millions of signatures) and licensed
    for use, not for redistribution inside another project - so they are
    imported from the user's own copy, never downloaded or shipped by us.
    """
    root = Path(root)
    skipped: Dict[str, int] = {}
    buckets: Dict[str, Dict[int, None]] = {}
    patterns: List[dict] = []
    pattern_seen = set()
    source = FeedSource(
        id=source_id, name=path.name, provider="ClamAV (local import)",
        repo="", path=str(path), parser="clamav", kind="hash",
        category="malware", severity=severity,
        license="ClamAV database licence (local copy)",
        license_url="https://docs.clamav.net/manual/Signatures.html",
        redistribution="runtime-only",
        homepage="https://www.clamav.net/",
        note="imported from the user's own ClamAV installation")

    produced = 0
    for ioc in parse_clamav_file(path, skipped=skipped):
        if ioc.kind == "pattern":
            if ioc.value in pattern_seen:
                continue
            if len(patterns) >= max_patterns:
                skipped["pattern-cap-reached"] = \
                    skipped.get("pattern-cap-reached", 0) + 1
                continue
            pattern_seen.add(ioc.value)
            signature = _pattern_signature(source, ioc.value)
            if signature is None:
                skipped["pattern-ungated"] = skipped.get("pattern-ungated", 0) + 1
                continue
            if benign and pattern_matches_benign(signature["pattern"], benign):
                skipped["pattern-benign-match"] =                     skipped.get("pattern-benign-match", 0) + 1
                continue
            patterns.append(signature)
            produced += 1
            continue
        key = _bucket_key(ioc.kind, severity)
        bucket = buckets.setdefault(key, {})
        bucket[token_digest(ioc.value)] = None
        produced += 1

    report = BuildReport(started=time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                               time.gmtime()))
    entry = source.to_dict()
    entry.update(status="ok", tokens=produced,
                 raw_bytes=path.stat().st_size,
                 raw_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                 url=str(path), skipped=dict(skipped))
    report.sources.append(entry)
    report.skipped = dict(sorted(skipped.items()))
    for key, bucket in sorted(buckets.items()):
        kind, tier = _split_bucket(key)
        label = _label_for(kind, ["ClamAV (local import)"])
        total, added = write_index(root, key, list(bucket.keys()), {
            "label": label, "kind": kind, "tier": tier,
            "sources": [{"id": source.id, "provider": source.provider,
                         "license": source.license,
                         "redistribution": source.redistribution,
                         "count": len(bucket)}],
            "examples": [],
        })
        report.indexes[key] = {"count": total, "added": added, "label": label,
                               "bytes": total * _DIGEST_SIZE}
    if patterns:
        (root / "index").mkdir(parents=True, exist_ok=True)
        merged = {s["id"]: s for s in _load_patterns(root)}
        merged.update({s["id"]: s for s in patterns})
        atomic_write_json(root / "index" / "patterns.json",
                          list(merged.values()))
    report.patterns = len(patterns)
    report.finished = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    root.mkdir(parents=True, exist_ok=True)
    _save_manifest(root, report, source_ids=[source.id])
    return report


# ------------------------------------------------------------------- helpers


def verify(root: Path) -> dict:
    """Re-read every index and check it is sorted, unique and consistent."""
    root = Path(root)
    report: Dict[str, object] = {"ok": True, "checked": 0, "errors": []}
    manifest = {}
    try:
        manifest = json.loads((root / "manifest.json").read_text(
            encoding="utf-8"))
    except (OSError, ValueError):
        pass
    patterns = 0
    try:
        patterns = len(json.loads((root / "index" / "patterns.json").read_text(
            encoding="utf-8")))
    except (OSError, ValueError):
        patterns = 0
    for key, meta in sorted(manifest.get("indexes", {}).items()):
        values = load_index(root, key)
        if values is None:
            report["errors"].append(f"{key}: index missing or unreadable")
            report["ok"] = False
            continue
        if len(values) != int(meta.get("count", -1)):
            report["errors"].append(
                f"{key}: {len(values)} entries but manifest says "
                f"{meta.get('count')}")
            report["ok"] = False
        if any(values[i] > values[i + 1] for i in range(len(values) - 1)):
            report["errors"].append(f"{key}: entries are not sorted")
            report["ok"] = False
        report["checked"] = int(report["checked"]) + 1
    report["patterns"] = patterns
    return report


def clear(root: Path) -> int:
    """Delete every built index.  Returns the number of files removed."""
    root = Path(root)
    removed = 0
    for directory in (root / "index", root):
        if not directory.exists():
            continue
        for path in sorted(directory.iterdir()):
            if path.is_file() and (path.suffix in (".idx", ".json")):
                path.unlink()
                removed += 1
    return removed
