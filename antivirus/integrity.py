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
MUTATED = "File mutated since trusted baseline"
MASS_MUTATION = "Mass file mutation - possible ransomware activity"


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


# ------------------------------------------------- standing trust baseline
def _canon(path) -> str:
    """Canonical (string) form of a path used as a baseline key."""
    import os
    return os.path.normpath(os.path.abspath(os.path.expanduser(str(path))))


def load_trust_baseline(path) -> Dict:
    """Load the standing trust baseline (same format as a manifest)."""
    return load_manifest(path)


def save_trust_baseline(baseline: Dict, path) -> None:
    save_manifest(baseline, path)


def _manifest_entries(target: Path, manifest: Dict) -> Dict[str, Dict]:
    """Rewrite a manifest's keys to canonical absolute paths."""
    base = target.resolve()
    out: Dict[str, Dict] = {}
    for rel, meta in manifest.get("files", {}).items():
        key = _canon(base if rel in ("", ".") else base / rel)
        out[key] = meta
    return out


def trust_snapshot(targets, config: Config, out_path) -> Dict:
    """Snapshot *targets* (files or dirs) into the standing trust baseline.

    Existing entries for the same paths are refreshed; unrelated entries
    are kept, so the baseline can grow incrementally.
    """
    import os
    import time as _time

    out_path = Path(out_path)
    if out_path.exists():
        try:
            baseline = load_manifest(out_path)
        except (ValueError, OSError, json.JSONDecodeError):
            baseline = {}
    else:
        baseline = {}
    files: Dict[str, Dict] = baseline.get("files", {})
    added = 0
    for t in targets:
        t = Path(t)
        if not t.exists():
            raise FileNotFoundError(str(t))
        entries = _manifest_entries(t, build_manifest(t, config))
        for key, meta in entries.items():
            if key not in files:
                added += 1
            files[key] = meta
    baseline["version"] = baseline.get("version", 1) + 1
    baseline["created"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    baseline["target"] = str(out_path)
    baseline["files"] = files
    save_trust_baseline(baseline, out_path)
    return baseline


def trust_add(targets, out_path) -> Dict:
    """Add/refresh single files in the trust baseline (no tree walk)."""
    import hashlib as _hashlib

    out_path = Path(out_path)
    baseline = {}
    if out_path.exists():
        try:
            baseline = load_manifest(out_path)
        except (ValueError, OSError, json.JSONDecodeError):
            baseline = {}
    files: Dict[str, Dict] = baseline.get("files", {})
    for t in targets:
        p = Path(t)
        if not p.is_file():
            raise FileNotFoundError(f"not a file: {t}")
        st = p.lstat()
        files[_canon(p)] = {"sha256": file_sha256(p), "size": st.st_size}
    baseline["version"] = baseline.get("version", 1) + 1
    baseline["created"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    baseline["target"] = str(out_path)
    baseline["files"] = files
    save_trust_baseline(baseline, out_path)
    return baseline


def trust_remove(targets, out_path) -> Dict:
    """Remove paths (exact files, or everything under a dir) from the
    trust baseline."""
    out_path = Path(out_path)
    if not out_path.exists():
        raise FileNotFoundError(str(out_path))
    baseline = load_manifest(out_path)
    files: Dict[str, Dict] = baseline.get("files", {})
    removed = 0
    for t in targets:
        key = _canon(t)
        to_del = [k for k in files
                  if k == key or k.startswith(key + "/")]
        for k in to_del:
            del files[k]
            removed += 1
    baseline["files"] = files
    baseline["version"] = baseline.get("version", 1) + 1
    save_trust_baseline(baseline, out_path)
    return baseline


def trust_list(out_path) -> List[Tuple[str, Dict]]:
    """(path, meta) pairs of the trust baseline, sorted by path."""
    if not Path(out_path).exists():
        return []
    baseline = load_manifest(out_path)
    return sorted(baseline.get("files", {}).items())


def trust_clear(out_path) -> None:
    p = Path(out_path)
    if p.exists():
        p.unlink()


def check_trusted(files: Dict[str, Dict], path_str: str,
                  sha256: str) -> Optional[Finding]:
    """Mutation check for one scanned file against the trust baseline."""
    meta = files.get(_canon(path_str))
    if meta is None or meta.get("sha256") == sha256:
        return None
    old = (meta.get("sha256") or "?")[:16]
    new = sha256[:16]
    msg = f"trusted sha256 {old}... changed to {new}..."
    if meta.get("size"):
        msg += f" (size {meta['size']} bytes when trusted)"
    return Finding(path=path_str, kind="integrity", name=MUTATED,
                   severity="high", message=msg)


def mutations_report(baseline: Dict) -> List[Finding]:
    """Check every registered path right now: mutated or missing."""
    out: List[Finding] = []
    for key, meta in sorted(baseline.get("files", {}).items()):
        p = Path(key)
        try:
            st = p.lstat()
        except OSError:
            out.append(Finding(
                path=key, kind="integrity", name=MISSING, severity="medium",
                message="registered in the trust baseline but missing "
                        "from disk"))
            continue
        cur = file_sha256(p)
        if cur != meta.get("sha256"):
            old = (meta.get("sha256") or "?")[:16]
            out.append(Finding(
                path=key, kind="integrity", name=MUTATED, severity="high",
                message=f"trusted sha256 {old}... changed to {cur[:16]}... "
                        f"(size {meta.get('size', '?')} -> {st.st_size} "
                        "bytes)"))
    return out


def mass_mutation_finding(findings, target: str,
                          threshold: int) -> Optional[Finding]:
    """Bulk-mutation (ransomware-style) aggregate over *findings*."""
    n = sum(1 for f in findings
            if f.kind == "integrity" and f.name == MUTATED)
    if n < threshold:
        return None
    return Finding(
        path=str(target), kind="integrity", name=MASS_MUTATION,
        severity="critical",
        message=(f"{n} trusted files mutated in one pass "
                 f"(threshold {threshold}) - bulk modification is "
                 "consistent with ransomware activity"),
    )
