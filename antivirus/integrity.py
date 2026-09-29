"""File integrity monitoring: baselines ("manifests") and comparison.

``antivirus manifest DIR`` hashes every scannable file under *DIR* (one
walk, streaming hashes) and stores a JSON baseline.  A later
``scan --baseline FILE`` then reports every file that changed, appeared
or disappeared since the baseline was taken — classic file-integrity
monitoring (FIM) on top of the regular scan.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Dict, List

from .config import Config
from .models import Finding
from .scanner import walk_files

CHANGED = "File changed since baseline"
MISSING = "File missing since baseline"
NEW = "File not in baseline"


def file_sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def _hash_tree(target: Path, config: Config) -> Dict[str, Dict]:
    """Hash every scannable file under *target*.

    Returns ``{relative_path: {"sha256": …, "size": …}}`` (a single file
    maps to the empty key ``""``).
    """
    target = Path(target)
    if not target.exists():
        raise FileNotFoundError(str(target))

    files: Dict[str, Dict] = {}
    if target.is_file():
        st = target.lstat()
        files[""] = {"sha256": file_sha256(target), "size": st.st_size}
    else:
        protected = (config.quarantine_dir.resolve(),
                     config.report_dir.resolve())
        base = target.resolve()
        for p in walk_files(target, config.exclude_dirs, protected,
                            exclude_patterns=config.exclude_patterns):
            st = p.lstat()
            try:
                rel = p.resolve().relative_to(base)
            except (ValueError, OSError):
                continue
            files[rel.as_posix()] = {"sha256": file_sha256(p), "size": st.st_size}
    return files


def build_manifest(target: Path, config: Config) -> Dict:
    """Hash every scannable file under *target* and return the baseline."""
    return {
        "version": 1,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": str(target),
        "files": _hash_tree(target, config),
    }


def verify_tree(target: Path, baseline: Dict, config: Config) -> List[Finding]:
    """Fast integrity-only check: hash the tree and diff against *baseline*.

    Unlike ``scan --baseline`` no signature / behaviour / entropy layers
    run – this is the quick "is anything different since the baseline?"
    FIM check. Returns changed / missing / new findings.
    """
    return compare_baseline(baseline, _hash_tree(target, config))


def save_manifest(manifest: Dict, path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def load_manifest(path: Path) -> Dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("files"), dict):
        raise ValueError("not a manifest file (expected a 'files' object)")
    return data


def current_from_result(result: "ScanResult", target: Path) -> Dict[str, Dict]:
    """Relativise a scan's ``file_meta`` against *target*.

    Returns ``{relative_path: {"sha256": …, "size": …}}`` for files under
    the target (paths outside the tree are ignored).
    """
    from pathlib import Path as _P

    target_resolved = _P(target).resolve()
    current: Dict[str, Dict] = {}
    for p, meta in getattr(result, "file_meta", {}).items():
        pp = _P(p)
        try:
            rel = pp.resolve().relative_to(target_resolved)
        except (ValueError, OSError):
            continue
        current[rel.as_posix()] = meta
    return current


def compare_baseline(baseline: Dict, current: Dict[str, Dict]) -> List[Finding]:
    """Diff a baseline against the current state of the tree.

    *current* maps relative paths (as produced by a scan of the
    baseline's target) to ``{"sha256": …, "size": …}``. Returns findings
    for changed (medium), missing (medium) and new (low) files.
    """
    out: List[Finding] = []
    base_files: Dict = baseline.get("files", {})
    target = Path(baseline.get("target", "?"))

    for rel, meta in sorted(base_files.items()):
        fpath = target if rel in ("", ".") else target / rel
        cur = current.get(rel)
        if cur is None:
            out.append(Finding(
                path=str(fpath), kind="integrity", name=MISSING,
                severity="medium",
                message="listed in the baseline but not found on disk"))
        elif cur.get("sha256") != meta.get("sha256"):
            old = (meta.get("sha256") or "?")[:16]
            new = (cur.get("sha256") or "?")[:16]
            out.append(Finding(
                path=str(fpath), kind="integrity", name=CHANGED,
                severity="medium",
                message=f"sha256 {old}… changed to {new}…"))
    for rel in sorted(set(current) - set(base_files)):
        fpath = target if rel in ("", ".") else target / rel
        out.append(Finding(
            path=str(fpath), kind="integrity", name=NEW, severity="low",
            message="new file appeared since the baseline was taken"))
    return out
