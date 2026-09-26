"""Runtime configuration."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

APP_NAME = "AntiVirus"

#: Directory names that are never walked (VCS metadata, venvs, build output).
DEFAULT_EXCLUDE_DIRS = (
    ".git", ".hg", ".svn",
    "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".cache", ".npm", ".next", ".nuxt", ".turbo", ".output",
    "target", "build", "dist", "out",
)


@dataclass
class Config:
    """All tunables used by the scanner, quarantine, monitor and reporter."""

    # Where runtime artefacts live (resolved relative to the CWD).
    quarantine_dir: Path = Path("quarantine")
    report_dir: Path = Path("reports")
    signatures_file: Path = Path("data/signatures.json")
    cache_dir: Path = Path(".av-cache")        # scan-cache file (fast rescans)

    # Scan limits.
    max_file_size: int = 512 * 1024 * 1024      # 512 MiB – larger files are skipped
    hash_chunk_size: int = 1024 * 1024          # 1 MiB reads while hashing
    pattern_chunk_size: int = 1024 * 1024       # 1 MiB reads while pattern searching

    # Behavioural analysis (what a file appears to do – static, never executed).
    behavior_enabled: bool = True
    behavior_max_size: int = 2 * 1024 * 1024    # only analyse files up to 2 MiB

    # Archives (ZIP): contents are examined in memory, never extracted to disk.
    archives_enabled: bool = True
    archive_max_size: int = 32 * 1024 * 1024    # skip archives larger than this
    archive_entry_max: int = 2 * 1024 * 1024    # per-entry bytes read for analysis
    archive_entries_max: int = 4096             # per-archive entry cap
    archive_expansion_max: int = 64 * 1024 * 1024  # total bytes read from one archive

    # Heuristics.
    entropy_threshold: float = 7.5              # bits/byte
    entropy_min_size: int = 256 * 1024          # only test files >= 256 KiB
    # 256 KiB of samples is statistically enough to estimate byte entropy
    # within ~0.01 bits/byte, and keeps the in-pass histogram cheap.
    entropy_sample_size: int = 256 * 1024

    # Fast mode: hash + pattern layers only (no behaviour, no entropy,
    # no per-entry behaviour) – meant for quick rescans.
    fast_mode: bool = False

    # Scan cache: unchanged files (same size + mtime + same engine profile)
    # reuse their previous verdict without being read from disk.
    cache_enabled: bool = True

    # Directory names that are never walked.
    exclude_dirs: tuple = DEFAULT_EXCLUDE_DIRS
    # File globs (fnmatch) that are never scanned; matched against the file
    # name and its path relative to the scan root.
    exclude_patterns: tuple = ()

    # Incremental scan cutoff: files with mtime < since_ts are skipped
    # (and counted as skipped). 0.0 = no cutoff.
    since_ts: float = 0.0

    @property
    def exclude_dir_set(self) -> set:
        return set(self.exclude_dirs)

    def resolve_paths(self, base: Path) -> None:
        """Make relative paths absolute, relative to *base* (usually the CWD)."""
        base = base.resolve()
        for name in ("quarantine_dir", "report_dir", "signatures_file",
                     "cache_dir"):
            p = Path(getattr(self, name))
            if not p.is_absolute():
                setattr(self, name, base / p)
