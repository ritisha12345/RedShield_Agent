"""Focused tests for deterministic analyzer behavior."""

import unittest

from agent.analyzer import analyze_results
from models import JudgeResult, VULNERABILITY_CATEGORIES


class AnalyzerTests(unittest.TestCase):
    def test_groups_results_by_category_and_rate(self) -> None:
        results = [
            JudgeResult(
                attack_id="a1",
                category="jailbreak",
                verdict="violation",
                severity="high",
                reason="Unsafe",
                confidence=0.9,
            ),
            JudgeResult(
                attack_id="a2",
                category="jailbreak",
                verdict="safe",
                severity=None,
                reason="Refused",
                confidence=0.8,
            ),
            JudgeResult(
                attack_id="a3",
                category="authority",
                verdict="violation",
                severity="medium",
                reason="Accepted false authority",
                confidence=0.7,
            ),
        ]

        findings = analyze_results(results)
        jailbreak = next(
            finding for finding in findings if finding.category == "jailbreak"
        )

        self.assertEqual(len(findings), len(VULNERABILITY_CATEGORIES))
        self.assertEqual(jailbreak.total, 2)
        self.assertEqual(jailbreak.violations, 1)
        self.assertEqual(jailbreak.safe, 1)
        self.assertEqual(jailbreak.violation_rate, 0.5)

    def test_marks_dominant_categories_by_violation_count(self) -> None:
        results = [
            JudgeResult(
                attack_id="a1",
                category="jailbreak",
                verdict="violation",
                severity="high",
                reason="Unsafe",
                confidence=0.9,
            ),
            JudgeResult(
                attack_id="a2",
                category="authority",
                verdict="safe",
                severity=None,
                reason="Refused",
                confidence=0.8,
            ),
        ]

        findings = analyze_results(results)
        dominant = [
            finding.category for finding in findings if finding.dominant
        ]

        self.assertEqual(dominant, ["jailbreak"])


if __name__ == "__main__":
    unittest.main()
