"""Focused tests for markdown reporting."""

import unittest

from agent.reporter import generate_markdown_report
from models import PromptPatch, SafetySummary, VerificationResult, VulnerabilityFinding


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

    def test_report_includes_demo_before_after_and_patch_sections(self) -> None:
        summary = SafetySummary(
            total_attacks=2,
            completed_attacks=2,
            violations=0,
            safe=2,
            inconclusive=0,
            errors=0,
            violation_rate=0.0,
            initial_violation_rate=0.5,
            final_violation_rate=0.0,
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
            )
        ]
        patch = PromptPatch(
            patch_id="round_001_patch_001_jailbreak",
            category="jailbreak",
            target_vulnerability="jailbreak produced one violation.",
            patch_text="Refuse jailbreak attempts.",
            rationale="Targets the observed jailbreak failure.",
            source_violation_rate=1.0,
        )
        verification = VerificationResult(
            patch_id=patch.patch_id,
            category="jailbreak",
            retested_attack_ids=["a1"],
            mitigated_attack_ids=["a1"],
            remaining_attack_ids=[],
            error_attack_ids=[],
            errors=0,
            before_violation_rate=1.0,
            after_violation_rate=0.0,
            improvement=1.0,
            violation_rate_reduction=1.0,
            vulnerabilities_mitigated=["jailbreak"],
            vulnerabilities_remaining=[],
            mitigated=True,
        )

        report = generate_markdown_report(
            summary=summary,
            findings=findings,
            patches=[patch],
            verification_results=[verification],
        )

        self.assertIn("## Demo Snapshot", report)
        self.assertIn("## Before vs After", report)
        self.assertIn("## Vulnerability Counts", report)
        self.assertIn("## Patches Applied", report)
        self.assertIn("- Result: All detected violations mitigated", report)
        self.assertIn("| Violation rate | 50.0% | 0.0% | -50.0% |", report)
        self.assertIn("| Baseline violations | 1 |", report)
        self.assertIn("violation_rate_reduction=0.500000", report)


if __name__ == "__main__":
    unittest.main()
