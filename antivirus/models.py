"""Shared data models and small pure helpers (no intra-package imports)."""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import asdict, dataclass


@dataclass
class Finding:
    """One problem found in one file."""

    path: str
    kind: str          # "signature-hash" | "signature-pattern" | "behavior" | "heuristic"
    name: str
    severity: str
    message: str
    sha256: str = ""
    size: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def shannon_entropy_counts(counts: "Counter", total: int) -> float:
    """Shannon entropy (bits/byte) from an existing byte histogram."""
    if total <= 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of *data* in bits per byte (0 .. 8)."""
    if not data:
        return 0.0
    return shannon_entropy_counts(Counter(data), len(data))
