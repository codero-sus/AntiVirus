"""Literal-token prefilter for regex sets (v2.8, performance).

Why this exists
---------------
CPython's ``re`` has **no** multi-branch optimisation: an alternation of
N regexes costs O(N) at every byte until one matches.  With a database of
100+ patterns that is seconds per MiB — measured 6.8 s/MiB for 114 simple
literal alternatives, i.e. the merged-regex approach does not scale.

Almost every real signature/indicator contains at least one *literal* run
(a family name, a registry path, a command).  A regex can only match a
buffer if one of its literal runs is present, so we can gate each pattern
with a cheap ``bytes.find`` (memchr-backed, ~0.3 ms per MiB) and only run
the full regex for the survivors — typically zero or one pattern per file.

Correctness: for a pattern with several literal runs (alternations,
optional parts) the gate is "at least one run present"; for multi-pattern
requirements (``all of``) the gate is "every pattern has a run present".
Both are necessary conditions for a match, so the prefilter can only ever
cause *extra* work, never a missed detection.  Patterns without any run of
``min_len`` bytes are always tested (no gate).

All tokens are compared in lower-cased space; patterns that are
case-sensitive simply get a superset of candidates.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Sequence, Tuple

#: Shortest literal run considered worth a token.
DEFAULT_MIN_LEN = 4
#: Characters treated as literal (unescaped) text inside a pattern.
_SAFE = set("abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            "_ -/:@#$%,.=!?*+&'\"<>[]{}()|^~`") - set("()[]{}|^$*+?.\\")


def pattern_runs(pattern: str, min_len: int = DEFAULT_MIN_LEN) -> List[str]:
    """Literal runs of at least *min_len* characters inside *pattern*.

    Understands escapes (``\\.`` → ``.``), scoped-flag groups (``(?i:…)``),
    named groups, character classes and non-literal escapes (``\\d``,
    ``\\x41``, ``\\b``); a run stops at any regex metacharacter.  Runs are
    returned lower-cased.  When nothing reaches *min_len*, the longest run of
    at least 3 characters is returned instead (short but still distinctive
    markers such as ``IEX``).
    """
    runs = _runs(pattern, min_len)
    if not runs and min_len > 3:
        runs = _runs(pattern, 3)
    return runs


def _runs(pattern: str, min_len: int) -> List[str]:
    runs: List[str] = []
    current: List[str] = []
    i, n = 0, len(pattern)

    def flush() -> None:
        if len(current) >= min_len:
            runs.append("".join(current).lower())
        current.clear()

    while i < n:
        ch = pattern[i]
        if ch == "\\" and i + 1 < n:
            nxt = pattern[i + 1]
            if nxt in "xXuU":          # hex escapes: \x41 \u00e9 \U0001F600
                flush()
                wanted = {"x": 2, "u": 4, "U": 8}[nxt]
                i += 2
                seen = 0
                while (i < n and seen < wanted
                       and pattern[i] in "0123456789abcdefABCDEF"):
                    i += 1
                    seen += 1
                continue
            if nxt == "N":             # \N{NAME}
                flush()
                end = pattern.find("}", i)
                i = (end + 1) if end != -1 else i + 2
                continue
            if nxt.isdigit() or nxt in "0":   # backreference \1 / octal
                flush()
                i += 2
                while i < n and pattern[i].isdigit():
                    i += 1
                continue
            if nxt.isalnum():          # \d \w \s \b \A \Z \p …
                flush()
                i += 2
                continue
            current.append(nxt)        # \. \- \$ \/ \\ → literal
            i += 2
            continue
        if ch == "(" and i + 1 < n and pattern[i + 1] == "?":
            # group syntax: (?i:…), (?:…), (?P<name>…), (?=…), (?#…)
            skip = i + 2
            while skip < n and pattern[skip] not in ":)":
                skip += 1
            if pattern.startswith("(?P<", i) and ">" in pattern[i:skip + 1]:
                skip = pattern.index(">", i) + 1
            else:
                skip += 1
            flush()
            i = skip
            continue
        if ch == "[":
            # character class: skip to the closing bracket (handling escapes)
            depth_end = i + 1
            if depth_end < n and pattern[depth_end] == "^":
                depth_end += 1
            if depth_end < n and pattern[depth_end] == "]":
                depth_end += 1
            while depth_end < n and pattern[depth_end] != "]":
                if pattern[depth_end] == "\\":
                    depth_end += 1
                depth_end += 1
            flush()
            i = depth_end + 1
            continue
        if ch == "{":
            # quantifier: {2}, {0,60}, {3,} – never literal text
            flush()
            end = pattern.find("}", i)
            i = (end + 1) if end != -1 else i + 1
            continue
        if ch in "()|^$*+?.\\":
            flush()
            i += 1
            continue
        current.append(ch)
        i += 1
    flush()
    return runs


class Prefilter:
    """Gate a set of regexes by required literal tokens.

    ``add(key, groups)`` registers one item whose ``groups`` are ANDed:
    every group must contain at least one token present in the buffer.
    An empty token list (no usable literal) disables the gate for that
    group, so the item is always tested.
    """

    def __init__(self, min_len: int = DEFAULT_MIN_LEN) -> None:
        self.min_len = min_len
        self._groups: Dict[str, List[List[bytes]]] = {}
        self._keys: List[str] = []

    # ------------------------------------------------------------------ setup
    def add_patterns(self, key: str, patterns: Sequence[str],
                     any_of: bool = True) -> None:
        """Register a pattern set.

        ``any_of=True``  – one group holding the runs of every pattern
        (a match of any pattern implies one of these runs).
        ``any_of=False`` – one group per pattern (all patterns required).
        """
        if not patterns:
            self._add(key, [[]])
            return
        if any_of:
            tokens: List[bytes] = []
            for pattern in patterns:
                tokens.extend(t.encode("utf-8")
                              for t in pattern_runs(pattern, self.min_len))
            self._add(key, [tokens])
        else:
            groups = []
            for pattern in patterns:
                groups.append([t.encode("utf-8") for t
                               in pattern_runs(pattern, self.min_len)])
            self._add(key, groups)

    def _add(self, key: str, groups: List[List[bytes]]) -> None:
        if key not in self._groups:
            self._keys.append(key)
        self._groups[key] = groups

    def add_raw(self, key: str, groups: List[List[bytes]]) -> None:
        """Register pre-computed (already lower-cased) token groups."""
        self._add(key, groups)

    # ------------------------------------------------------------------ query
    def candidates(self, buf: bytes) -> List[str]:
        """Keys whose gate passed for *buf* (in insertion order)."""
        if not self._groups:
            return []
        low = buf.lower()
        out: List[str] = []
        for key in self._keys:
            ok = True
            for group in self._groups[key]:
                if not group:
                    continue            # no usable literal → cannot gate out
                if not any(token in low for token in group):
                    ok = False
                    break
            if ok:
                out.append(key)
        return out

    def is_gated(self, key: str) -> bool:
        """True when *key* has at least one usable literal token."""
        for group in self._groups.get(key, []):
            if group:
                return True
        return False

    def __len__(self) -> int:
        return len(self._keys)

    def __contains__(self, key: object) -> bool:
        return key in self._groups

    def token_count(self) -> int:
        return sum(len(g) for groups in self._groups.values() for g in groups)


def build(entries: Iterable[Tuple[str, Sequence[str], bool]]) -> Prefilter:
    """Convenience: ``build([(key, patterns, any_of), …])``."""
    pf = Prefilter()
    for key, patterns, any_of in entries:
        pf.add_patterns(key, patterns, any_of=any_of)
    return pf
