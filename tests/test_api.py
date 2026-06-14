"""Focused tests for the first FastAPI scan layer."""

import importlib.util
import time
import unittest
from types import SimpleNamespace

from models import SafetySummary


FASTAPI_AVAILABLE = importlib.util.find_spec("fastapi") is not None

if FASTAPI_AVAILABLE:
    from fastapi.testclient import TestClient

    import api.routes as routes
    from api.storage import SCAN_STORE
    from main import app


@unittest.skipUnless(FASTAPI_AVAILABLE, "FastAPI is not installed.")
class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        SCAN_STORE.clear()
        self.original_run_scan = routes.run_scan

        def fake_run_scan(**kwargs):
            event_callback = kwargs.get("event_callback")
            if event_callback is not None:
                event_callback(
                    "attack_generated",
                    {
                        "attack_id": "a1",
                        "category": "jailbreak",
                        "intent": "test",
                    },
                )
                event_callback(
                    "scan_completed",
                    {
                        "initial_violation_rate": 0.0,
                        "final_violation_rate": 0.0,
                    },
                )
            return SimpleNamespace(
                summary=SafetySummary(
                    total_attacks=1,
                    completed_attacks=1,
                    violations=0,
                    safe=1,
                    inconclusive=0,
                    errors=0,
                    violation_rate=0.0,
                    initial_violation_rate=0.0,
                    final_violation_rate=0.0,
                    remaining_risks=[],
                ),
                markdown_report="# Fake Report\n",
            )

        routes.run_scan = fake_run_scan
        self.client = TestClient(app)

    def tearDown(self) -> None:
        routes.run_scan = self.original_run_scan
        SCAN_STORE.clear()

    def test_post_scan_runs_orchestrator_and_stores_result(self) -> None:
        response = self.client.post(
            "/scans",
            json={
                "app_category": "customer_support",
                "system_prompt": "sensitive prompt",
                "attacks_per_category": 1,
                "success_threshold": 0.05,
                "max_rounds": 1,
            },
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "queued")
        self.assertIsNone(body["summary"])

        status_response = self._wait_for_completed_scan(body["status_url"])
        self.assertEqual(status_response.status_code, 200)
        status_body = status_response.json()
        self.assertEqual(status_body["status"], "completed")
        self.assertEqual(status_body["summary"]["final_violation_rate"], 0.0)
        self.assertEqual(status_body["markdown_report"], "# Fake Report\n")
        self.assertNotIn("sensitive prompt", str(status_body))

    def test_stream_returns_orchestrator_events(self) -> None:
        response = self.client.post(
            "/scans",
            json={
                "app_category": "customer_support",
                "system_prompt": "sensitive prompt",
            },
        )
        body = response.json()
        self._wait_for_completed_scan(body["status_url"])

        with self.client.stream("GET", body["stream_url"]) as stream_response:
            self.assertEqual(stream_response.status_code, 200)
            stream_text = "".join(stream_response.iter_text())

        self.assertIn("event: attack_generated", stream_text)
        self.assertIn("event: scan_completed", stream_text)
        self.assertNotIn("sensitive prompt", stream_text)

    def test_report_endpoint_returns_completed_report(self) -> None:
        response = self.client.post(
            "/scans",
            json={
                "app_category": "customer_support",
                "system_prompt": "sensitive prompt",
            },
        )
        body = response.json()
        self._wait_for_completed_scan(body["status_url"])

        report_response = self.client.get(body["report_url"])

        self.assertEqual(report_response.status_code, 200)
        report_body = report_response.json()
        self.assertEqual(report_body["status"], "completed")
        self.assertEqual(report_body["markdown_report"], "# Fake Report\n")
        self.assertNotIn("sensitive prompt", str(report_body))

    def test_health_endpoint_reports_readiness(self) -> None:
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "ok")
        self.assertIn("firestore", body["dependencies"])

    def test_cors_allows_local_frontend_origin(self) -> None:
        response = self.client.options(
            "/scans",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers["access-control-allow-origin"],
            "http://localhost:5173",
        )

    def test_get_missing_scan_returns_404(self) -> None:
        response = self.client.get("/scans/scan_missing")

        self.assertEqual(response.status_code, 404)

    def _wait_for_completed_scan(self, status_url: str):
        deadline = time.time() + 2
        response = self.client.get(status_url)
        while response.json()["status"] not in {"completed", "failed"}:
            if time.time() > deadline:
                self.fail("scan did not finish before test timeout")
            time.sleep(0.01)
            response = self.client.get(status_url)
        return response


if __name__ == "__main__":
    unittest.main()
