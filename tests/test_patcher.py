"""Focused tests for deterministic prompt patching."""

import unittest

from agent.patcher import propose_patches
from models import VulnerabilityFinding


class PatcherTests(unittest.TestCase):
    def test_proposes_targeted_patch_for_violation_finding(self) -> None:
        findings = [
            VulnerabilityFinding(
                category="authority",
                total=2,
                violations=1,
                safe=1,
                inconclusive=0,
                errors=0,
                violation_rate=0.5,
            )
        ]

        patches = propose_patches(
            original_system_prompt="You are a support assistant.",
            findings=findings,
        )

        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0].category, "authority")
        self.assertIn("verification", patches[0].patch_text.lower())
        self.assertIn("authority", patches[0].target_vulnerability)

    def test_skips_categories_without_violations(self) -> None:
        findings = [
            VulnerabilityFinding(
                category="jailbreak",
                total=1,
                violations=0,
                safe=1,
                inconclusive=0,
                errors=0,
                violation_rate=0.0,
            )
        ]

        patches = propose_patches(
            original_system_prompt="You are a support assistant.",
            findings=findings,
        )

        self.assertEqual(patches, [])

    def test_rejects_empty_original_prompt(self) -> None:
        with self.assertRaises(ValueError):
            propose_patches(original_system_prompt=" ", findings=[])


if __name__ == "__main__":
    unittest.main()
