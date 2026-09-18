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

    # Scan limits.
    max_file_size: int = 512 * 1024 * 1024      # 512 MiB – larger files are skipped
    hash_chunk_size: int = 1024 * 1024          # 1 MiB reads while hashing
    pattern_chunk_size: int = 1024 * 1024       # 1 MiB reads while pattern searching

    # Behavioural analysis (what a file appears to do – static, never executed).
    behavior_enabled: bool = True
    behavior_max_size: int = 2 * 1024 * 1024    # only analyse files up to 2 MiB

    # Heuristics.
    entropy_threshold: float = 7.5              # bits/byte
    entropy_min_size: int = 256 * 1024          # only test files >= 256 KiB
    # 256 KiB of samples is statistically enough to estimate byte entropy
    # within ~0.01 bits/byte, and keeps the in-pass histogram cheap.
    entropy_sample_size: int = 256 * 1024

    # Directory names that are never walked.
    exclude_dirs: tuple = DEFAULT_EXCLUDE_DIRS

    @property
    def exclude_dir_set(self) -> set:
        return set(self.exclude_dirs)

    def resolve_paths(self, base: Path) -> None:
        """Make relative paths absolute, relative to *base* (usually the CWD)."""
        base = base.resolve()
        for name in ("quarantine_dir", "report_dir", "signatures_file"):
            p = Path(getattr(self, name))
            if not p.is_absolute():
                setattr(self, name, base / p)
