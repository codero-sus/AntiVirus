"""Append technique rows to ``antivirus/techniques.py`` without hand-escaping.

Usage::

    from _addrows import append_rows, sweep
    append_rows([ (id, name, category, severity, description,
                    (pattern, ...), (tag, ...), sample), ... ])
    sweep()

``append_rows`` formats every string with ``repr()`` and inserts the block
before the closing ``])`` of the table, so patterns and samples keep exactly
the characters they were written with.  ``sweep`` then re-checks the whole
table: each row must fire on its own sample, and no row's sample may be caught
by any other check (shipped or new) - a row that fails is duplicate coverage
and gets deleted, not relabelled.
"""
from __future__ import annotations

import ast
import importlib
import pathlib
import re
import sys

ROOT = pathlib.Path("/home/user/AntiVirus")
PATH = ROOT / "antivirus" / "techniques.py"


def _format(row) -> str:
    cid, name, category, severity, description, patterns, tags, sample = row
    entries = [repr(p) for p in patterns]
    if len(", ".join(entries)) > 120:
        body = ",\n        ".join(entries)
        pat_line = f"     (\n        {body},\n    ),\n"
    elif len(entries) == 1:
        pat_line = f"     ({entries[0]},),\n"
    else:
        pat_line = f"     ({', '.join(entries)}),\n"
    return (
        f"    ({cid!r}, {name!r}, {category!r}, {severity!r},\n"
        f"     {description!r},\n"
        f"{pat_line}"
        f"     {tags!r}, {sample!r}),\n"
    )


def append_rows(rows) -> int:
    """Append *rows*, skipping ids that already exist.  Returns the count."""
    text = PATH.read_text()
    have = set(re.findall(r"\(['\"](IND2-[A-Z0-9-]+)['\"]", text))
    fresh = [r for r in rows if r[0] not in have]
    if not fresh:
        print("append_rows: nothing new")
        return 0
    tail = text.rindex("])")
    text = text[:tail] + "".join(_format(r) for r in fresh) + text[tail:]
    ast.parse(text)
    PATH.write_text(text)
    print(f"append_rows: +{len(fresh)} rows")
    return len(fresh)


def drop_rows(ids) -> int:
    """Delete complete row blocks whose id is in *ids* (duplicate coverage)."""
    ids = {i for i in ids}
    lines = PATH.read_text().splitlines(keepends=True)
    out, index, dropped = [], 0, 0
    while index < len(lines):
        m = re.match(r"""\s*\(['\"](IND2-[A-Z0-9-]+)['\"]""", lines[index])
        if not m:
            out.append(lines[index])
            index += 1
            continue
        block = [lines[index]]
        index += 1
        while index < len(lines):
            block.append(lines[index])
            index += 1
            try:
                ast.parse("x=[\n" + "".join(block) + "\n]")
                break
            except SyntaxError:
                continue
        if m.group(1) in ids:
            dropped += 1
            continue
        out.append("".join(block))
    text = "".join(out)
    ast.parse(text)
    PATH.write_text(text)
    print(f"drop_rows: -{dropped} rows")
    return dropped


def sweep(verbose: bool = True, fix: bool = False):
    """Re-import the table and check firing + duplicate coverage."""
    for mod in [m for m in list(sys.modules) if m.startswith("antivirus")]:
        del sys.modules[mod]
    import antivirus.indicators as I
    import antivirus.techniques as T

    old_ids = {c.id for c in I.CHECKS if not c.id.startswith("IND2-")}
    new_ids = {r[0] for r in T.ROWS}
    not_firing, shipped, intra, bad = [], [], [], []
    for row in T.ROWS:
        fname, text = T._sample_of(row)
        findings = I.analyze(fname, text.encode(), filename=fname)
        names = {f.name for f in findings}
        caught = set()
        for f in findings:
            m = re.search(r"\[([A-Z0-9-]+)\]", f.message or "")
            if m:
                caught.add(m.group(1))
        if row[1] not in names:
            not_firing.append(row[0])
        if caught & old_ids:
            shipped.append((row[0], sorted(caught & old_ids)))
        if caught & new_ids - {row[0]}:
            intra.append((row[0], sorted(caught & new_ids - {row[0]})))
        if len(findings) > 12:
            bad.append((row[0], len(findings)))
    if verbose:
        print(f"rows {len(T.ROWS)} | library {len(I.CHECKS)}")
        print(f"not firing on their own sample : {len(not_firing)} {not_firing}")
        print(f"also caught by a shipped check : {len(shipped)} {shipped}")
        print(f"also caught by another new row : {len(intra)} {intra}")
        print(f"samples with >12 hits          : {len(bad)} {bad}")
    return {"not_firing": not_firing, "shipped": shipped, "intra": intra,
            "noisy": bad}
