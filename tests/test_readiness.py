"""Tests for deployment readiness checks."""

import unittest
from unittest.mock import patch

from utils.readiness import deployment_readiness


class ReadinessTests(unittest.TestCase):
    def test_local_defaults_are_degraded_for_production(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            readiness = deployment_readiness()

        self.assertEqual(readiness["status"], "degraded")
        self.assertIn(
            "REDSHIELD_SCAN_EXECUTION_MODE must be celery in production.",
            readiness["blocking_issues"],
        )
        self.assertIn("OPENAI_API_KEY is required.", readiness["blocking_issues"])

    def test_celery_without_firestore_or_redis_is_blocking(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "OPENAI_API_KEY": "test-key",
                "REDSHIELD_SCAN_EXECUTION_MODE": "celery",
                "CORS_ALLOWED_ORIGINS": "https://example.netlify.app",
                "REDSHIELD_FIRESTORE_ENABLED": "false",
            },
            clear=True,
        ):
            readiness = deployment_readiness()

        self.assertEqual(readiness["status"], "degraded")
        self.assertIn(
            "Redis/Celery broker must be configured and reachable.",
            readiness["blocking_issues"],
        )
        self.assertIn(
            "Firestore must be enabled and available for celery mode.",
            readiness["blocking_issues"],
        )


if __name__ == "__main__":
    unittest.main()
