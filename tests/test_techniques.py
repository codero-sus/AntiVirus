"""Tests for the v3.1 technique table (``antivirus/techniques.py``).

Every row carries a trigger sample, so this module turns each row into its own
test.  That is deliberate: a check that silently stops matching, a pattern
that accidentally matches an empty string, or a row that merely restates an
existing check all fail here instead of shipping.
"""
from __future__ import annotations

import re
import unittest

from antivirus import indicators, techniques


def _scan(file_name: str, text: str):
    return indicators.analyze(file_name, text.encode(), filename=file_name)


class TechniqueRowTests(unittest.TestCase):
    """One test per check, generated from the table."""

    def test_table_is_not_empty(self):
        self.assertGreater(len(techniques.ROWS), 40)

    def test_ids_unique_and_namespaced(self):
        ids = [row[0] for row in techniques.ROWS]
        self.assertEqual(len(ids), len(set(ids)), "duplicate id in ROWS")
        for check_id in ids:
            self.assertTrue(check_id.startswith("IND2-"), check_id)

    def test_no_row_restates_an_existing_check(self):
        """A new check must add coverage, not a synonym of an old one."""
        # CHECKS already contains this table, so compare against the rows
        # that came from indicators.py (everything without the IND2- prefix)
        original = [c for c in indicators.CHECKS if not c.id.startswith("IND2-")]
        existing_ids = {c.id for c in original}
        existing_names = {c.name.lower() for c in original}
        for row in techniques.ROWS:
            self.assertNotIn(row[0], existing_ids, row[0])
            self.assertNotIn(row[1].lower(), existing_names, row[0])

    def test_every_row_has_a_sample_and_valid_fields(self):
        for row in techniques.ROWS:
            check_id, name, category, severity, description = row[:5]
            patterns, tags = row[5], row[6]
            self.assertTrue(patterns, check_id)
            self.assertTrue(tags, check_id)
            self.assertIn(severity,
                          ("low", "medium", "high", "critical"), check_id)
            self.assertNotIn(category, ("", None), check_id)
            self.assertGreater(len(description), 10, check_id)
            self.assertTrue(name.strip(), check_id)
            file_name, text = techniques._sample_of(row)
            self.assertTrue(file_name, check_id)
            self.assertGreater(len(text), 5, check_id)
            for pattern in patterns:
                # the library compiles every pattern with re.IGNORECASE, so
                # the syntax/firing checks must use the same flag
                compiled = re.compile(pattern, re.IGNORECASE)
                self.assertIsNone(compiled.search(""),
                                  f"{check_id}: matches empty text")
                self.assertIsNotNone(compiled.search(text),
                                     f"{check_id}: sample does not match")

    def test_library_scans_a_large_uniform_file_quickly(self):
        """An unbounded wildcard run makes the whole library quadratic.

        A pattern such as ``[^\\n:]{2,}::0:0:`` re-scans the same run of bytes
        from every starting offset, so a multi-megabyte file of one character
        is the cheapest way to catch it before it reaches a scan of a real
        binary.  The bounds below are deliberately loose (the 8 MB scan takes
        seconds, not minutes) so the check only fires on a real regression.
        """
        import time

        blob = b"#!/bin/sh\n" + b"a" * (4 * 1024 * 1024)
        started = time.monotonic()
        indicators.analyze("big.sh", blob, filename="big.sh")
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 10.0, f"4 MB uniform file took {elapsed:.1f}s")

    def test_every_row_fires_on_its_own_sample(self):
        for row in techniques.ROWS:
            check_id, name = row[0], row[1]
            file_name, text = techniques._sample_of(row)
            names = {f.name for f in _scan(file_name, text)}
            self.assertIn(name, names, f"{check_id} did not fire")

    def test_every_row_adds_coverage_over_the_rest_of_the_library(self):
        """No row may be a synonym: nothing else may fire on its own sample.

        If a shipped check - or a sibling row - already catches a row's
        trigger sample, that row is duplicate coverage.  Those rows are
        deleted rather than counted as new improvements.
        """
        duplicate = {}
        for row in techniques.ROWS:
            file_name, text = techniques._sample_of(row)
            others = {f.name for f in _scan(file_name, text) if f.name != row[1]}
            if others:
                duplicate[row[0]] = sorted(others)
        self.assertEqual(duplicate, {},
                         f"rows that add no coverage: {duplicate}")

    def test_samples_do_not_mass_flag_other_checks(self):
        """Samples are small; more than a handful of hits means a loose check."""
        noisy = {}
        for row in techniques.ROWS:
            file_name, text = techniques._sample_of(row)
            hits = _scan(file_name, text)
            if len(hits) > 12:
                noisy[row[0]] = len(hits)
        self.assertEqual(noisy, {}, f"over-broad checks: {noisy}")

    def test_samples_are_quiet_on_random_text(self):
        import random

        random.seed(1234)
        words = ("the quick brown fox jumps over a lazy dog system service "
                 "update install window server error report client user").split()
        prose = " ".join(random.choice(words) for _ in range(4000))
        self.assertEqual(_scan("prose.txt", prose), [])

    def test_samples_are_quiet_on_a_clean_script(self):
        clean = ("#!/bin/bash\nset -euo pipefail\n"
                 "rsync -a --delete ./dist/ /srv/app/\n"
                 "systemctl restart app.service\n"
                 "curl -fsS http://127.0.0.1:8080/healthz\n"
                 "echo done\n")
        self.assertEqual(_scan("deploy.sh", clean), [])

    def test_sample_corpus_exportable(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            written = techniques.dump_samples(Path(tmp))
            self.assertEqual(len(written), len(techniques.ROWS))
            for path in written[:5]:
                self.assertTrue(path.exists())
                self.assertGreater(path.stat().st_size, 5)


class TechniqueCoverageTests(unittest.TestCase):
    def test_matrix_counts_include_the_new_rows(self):
        summary = indicators.matrix_summary()
        self.assertEqual(summary["unmapped"], 0)
        self.assertEqual(sum(t["checks"] for t in summary["tactics"]),
                         len(indicators.CHECKS))

    def test_new_rows_are_exported_to_yara(self):
        from antivirus import yararules

        rows = techniques.rows_as_indicators(indicators._i)
        samples = rows[:12]
        stats = yararules.YaraStats()
        rules = yararules.from_indicators(samples, stats)
        self.assertGreater(len(rules), 5)
        for rule in rules:
            self.assertIn("rule AV_IND_IND2_", rule)
            self.assertEqual(rule.count("{"), rule.count("}"))


if __name__ == "__main__":
    unittest.main()
