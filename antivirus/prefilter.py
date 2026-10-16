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

import re

from typing import Dict, Iterable, List, Sequence, Tuple

#: Shortest literal run considered worth a token.
DEFAULT_MIN_LEN = 4
#: Characters treated as literal (unescaped) text inside a pattern.
_SAFE = set("abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            "_ -/:@#$%,.=!?*+&'\"<>[]{}()|^~`") - set("()[]{}|^$*+?.\\")


def pattern_runs(pattern: str, min_len: int = DEFAULT_MIN_LEN) -> List[str]:
    """Literal runs that **every** match of *pattern* must contain.

    The result is a disjunction: a match implies at least one of the returned
    tokens is present in the buffer, which is what makes gating safe.  A
    pattern with no such token returns ``[]`` and is therefore never gated
    out.

    Structure matters, not just characters.  ``ghp_[A-Za-z0-9]{20,}`` has a
    literal run of only three characters, so in ``gh[psouhr]_…|github_pat_…``
    the first branch guarantees *nothing* — scanning the whole pattern for
    long runs used to yield only ``github_pat_`` and silently skip every
    ``ghp_``-style token.  The extractor therefore walks the parsed pattern:

    * a sequence yields the best requirement of its members (a match has to
      satisfy all of them),
    * an alternation yields the union of its branches, but only when *every*
      branch guarantees a token,
    * optional parts (``{0,n}``, ``?``, ``*``) and negative lookarounds
      guarantee nothing, while positive lookaheads do,
    * case-insensitive patterns get a superset of candidates, so their tokens
      are compared lower-cased.

    Understands escapes (``\\.`` → ``.``), scoped-flag groups (``(?i:…)``),
    named groups, character classes and non-literal escapes (``\\d``,
    ``\\x41``, ``\\b``).  When nothing reaches *min_len*, runs of at least 3
    characters are used instead (short but still distinctive markers such as
    ``IEX``).
    """
    parsed = _parse(pattern)
    if parsed is not None:
        runs = _sequence_runs(parsed, min_len)
        if not runs and min_len > 3:
            runs = _sequence_runs(parsed, 3)
        return runs
    # parsing unavailable: fall back to the textual scan, but keep it sound
    # for alternations - every branch has to produce a token of its own
    branches = _split_top_level(pattern)
    if len(branches) > 1:
        collected: List[str] = []
        for branch in branches:
            inner = _runs(branch, min_len) or _runs(branch, 3)
            if not inner:
                return []
            collected.extend(inner)
        return collected
    return _runs(pattern, min_len) or _runs(pattern, 3)


def _parse(pattern: str):
    """Parse *pattern* with the stdlib regex parser, or return ``None``."""
    for module_name in ("re._parser", "sre_parse"):
        try:
            module = __import__(module_name, fromlist=["parse"])
            return module.parse(pattern, 0)
        except Exception:                      # pragma: no cover - defensive
            continue
    return None                            # pragma: no cover - defensive


def _split_top_level(pattern: str) -> List[str]:
    """Split *pattern* on ``|`` outside character classes (fallback path)."""
    out: List[str] = []
    current: List[str] = []
    in_class = False
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\" and i + 1 < n:
            current.append(pattern[i:i + 2])
            i += 2
            continue
        if in_class:
            if ch == "]":
                in_class = False
            current.append(ch)
            i += 1
            continue
        if ch == "[":
            in_class = True
            current.append(ch)
            i += 1
            continue
        if ch == "|":
            out.append("".join(current))
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    out.append("".join(current))
    return out


def _op_name(op) -> str:
    """Name of a parsed opcode.

    The stdlib constants are small integers whose values collide across the
    ``AT``/``OPCODES`` enumerations, so names - not values - decide what a
    node is.
    """
    name = getattr(op, "name", None)
    if isinstance(name, str):
        return name
    for module_name in ("re._constants", "sre_constants"):
        try:
            module = __import__(module_name, fromlist=["LITERAL"])
        except Exception:                      # pragma: no cover - defensive
            continue
        for attr in dir(module):
            if attr.isupper() and getattr(module, attr) is op:
                return attr
    return ""


def _sequence_runs(items, min_len: int) -> List[str]:
    """Best guaranteed token set for a parsed pattern sequence."""
    best: List[str] = []
    index, total = 0, len(items)
    while index < total:
        op, value = items[index]
        if _op_name(op) == "LITERAL":
            # merge adjacent literals: "github_pat_" is one run, not eleven
            chars = []
            while (index < total
                   and _op_name(items[index][0]) == "LITERAL"):
                chars.append(chr(items[index][1]))
                index += 1
            if len(chars) >= min_len:
                best = ["".join(chars).lower()]
            continue
        index += 1
        runs = _node_runs(op, value, min_len)
        if runs and _stronger(runs, best):
            best = runs
    return best


def _strength(tokens: Sequence[str]) -> Tuple[int, int]:
    """Gate strength: the shortest token is the weakest link."""
    if not tokens:
        return (0, 0)
    lengths = [len(token) for token in tokens]
    return (min(lengths), sum(lengths))


def _stronger(candidate: Sequence[str], current: Sequence[str]) -> bool:
    """True when *candidate* gates at least as tightly as *current*."""
    return _strength(candidate) > _strength(current)


def _node_runs(op, value, min_len: int) -> List[str]:
    """Guaranteed tokens for one parsed node (``[]`` = none)."""
    name = _op_name(op)
    if name in ("LITERAL", "NOT_LITERAL", "IN", "ANY", "CATEGORY", "AT",
                "GROUPREF"):
        return []
    if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT", "SUBPATTERN",
                "GROUP", "ASSERT", "ASSERT_NOT"):
        if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            low, _high, inner = value
            if low == 0:                       # optional: guarantees nothing
                return []
            return _sequence_runs(inner, min_len)
        if name in ("ASSERT", "ASSERT_NOT"):
            _direction, inner = value
            if name == "ASSERT_NOT":           # negative: guarantees nothing
                return []
            return _sequence_runs(inner, min_len)
        if name == "SUBPATTERN":
            return _sequence_runs(value[-1], min_len)
        return _sequence_runs(value, min_len)
    if name == "BRANCH":
        _marker, branches = value
        collected: List[str] = []
        for branch in branches:
            runs = _sequence_runs(branch, min_len)
            if not runs:                       # a branch with no token means
                return []                      # the whole alternation is ungated
            collected.extend(runs)
        return collected
    return []





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




#: How many branch combinations are generated per pattern.
WITNESS_LIMIT = 6
#: How many repetitions of a repeated element a witness contains.
REPEAT_CAP = 3


def _node_samples(op, value):
    """Witness strings for one parsed node (may be empty)."""
    name = _op_name(op)
    if name == "LITERAL":
        return [chr(value)]
    if name == "NOT_LITERAL":
        return ["a"] if value != ord("a") else ["b"]
    if name == "IN":
        for entry in value:
            if _op_name(entry[0]) == "LITERAL":
                char = chr(entry[1])
                return [char]
        return ["a"]
    if name in ("ANY", "CATEGORY", "GROUPREF"):
        return ["a"]
    if name == "AT":
        return [""]
    if name == "BRANCH":
        _marker, branches = value
        out = []
        for branch in branches:
            out.extend(_sequence_samples(branch))
        return out or [""]
    if name == "SUBPATTERN":
        return _sequence_samples(value[-1]) or [""]
    if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
        low, _high, inner = value
        piece = _sequence_samples(inner) or [""]
        count = min(low, REPEAT_CAP)
        return [piece[0] * count] if count else [""]
    if name in ("ASSERT", "ASSERT_NOT"):
        return [""]
    return [""]


def _sequence_samples(items, limit: int = WITNESS_LIMIT):
    """One witness string per combination of alternation branches."""
    out = [""]
    for op, value in items:
        pieces = _node_samples(op, value)
        out = [head + piece for head in out for piece in pieces][:limit]
        if not out:
            return []
    return out


def sample_strings(pattern: str, limit: int = WITNESS_LIMIT):
    """Strings that *pattern* is expected to match (best effort).

Built by walking the parsed pattern and taking one value per
alternative, so callers can check what a pattern really requires
of the bytes it claims to match.
"""
    parsed = _parse(pattern)
    if parsed is None:                         # pragma: no cover - defensive
        return []
    out = [witness for witness in _sequence_samples(parsed, limit)
           if witness and re.search(pattern, witness, re.IGNORECASE)]
    return list(dict.fromkeys(out))[:limit]



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
