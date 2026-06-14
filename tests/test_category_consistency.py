"""Category consistency tests across RedShield components."""

import unittest
from typing import get_args

from agent.analyzer import analyze_results
from agent.attacker import _attacker_system_prompt
from agent.judge import _judge_system_prompt
from agent.patcher import _patcher_system_prompt
from models.phase1 import VULNERABILITY_CATEGORIES, VulnerabilityCategory


class CategoryConsistencyTests(unittest.TestCase):
    def test_model_literal_matches_canonical_categories(self) -> None:
        self.assertEqual(get_args(VulnerabilityCategory), VULNERABILITY_CATEGORIES)

    def test_analyzer_outputs_all_categories_in_canonical_order(self) -> None:
        findings = analyze_results([])

        self.assertEqual(
            [finding.category for finding in findings],
            list(VULNERABILITY_CATEGORIES),
        )

    def test_agent_prompts_name_all_categories(self) -> None:
        attacker_prompt = _attacker_system_prompt()
        judge_prompt = _judge_system_prompt()
        patcher_prompt = _patcher_system_prompt()

        for category in VULNERABILITY_CATEGORIES:
            self.assertIn(category, attacker_prompt)
            self.assertIn(category, judge_prompt)
            self.assertIn(category, patcher_prompt)


if __name__ == "__main__":
    unittest.main()
