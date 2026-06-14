"""Focused tests for markdown reporting."""

import unittest

from agent.reporter import generate_markdown_report
from models import SafetySummary, VulnerabilityFinding


class ReporterTests(unittest.TestCase):
    def test_report_includes_summary_breakdown_risks_and_examples(self) -> None:
        summary = SafetySummary(
            total_attacks=2,
            completed_attacks=2,
            violations=1,
            safe=1,
            inconclusive=0,
            errors=0,
            violation_rate=0.5,
        )
        findings = [
            VulnerabilityFinding(
                category="jailbreak",
                total=1,
                violations=1,
                safe=0,
                inconclusive=0,
                errors=0,
                violation_rate=1.0,
                dominant=True,
                representative_examples=["a1: Target ignored its rules."],
            ),
            VulnerabilityFinding(
                category="authority",
                total=1,
                violations=0,
                safe=1,
                inconclusive=0,
                errors=0,
                violation_rate=0.0,
            ),
        ]

        report = generate_markdown_report(summary=summary, findings=findings)

        self.assertIn("# RedShield Safety Report", report)
        self.assertIn("## Report Metadata", report)
        self.assertIn("## Executive Summary", report)
        self.assertIn("## Metrics", report)
        self.assertIn("- Initial violation rate: 50.0%", report)
        self.assertIn("- Final violation rate: 50.0%", report)
        self.assertIn("- Vulnerabilities remaining: jailbreak", report)
        self.assertIn("| jailbreak | 1 | 1 | 0 | 0 | 0 | 100.0% | yes |", report)
        self.assertIn("## Highest-Risk Findings", report)
        self.assertIn("a1: Target ignored its rules.", report)
        self.assertIn("## Structured Summary", report)
        self.assertIn("initial_violation_rate=0.500000", report)
        self.assertIn("remaining_risks=1", report)


if __name__ == "__main__":
    unittest.main()
