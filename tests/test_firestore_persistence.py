"""Tests for Firestore persistence boundaries."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime
from typing import Any

from api.storage import InMemoryScanStore
from firebase.firestore import FirestorePersistence
from models import FinalReport, PersistedScanEvent, ScanMetadata


class FirestorePersistenceTests(unittest.TestCase):
    def test_firestore_adapter_writes_expected_documents(self) -> None:
        client = FakeFirestoreClient()
        persistence = FirestorePersistence(client=client, enabled=True)
        created_at = datetime(2026, 6, 14, tzinfo=UTC)
        completed_at = datetime(2026, 6, 14, 1, tzinfo=UTC)

        persistence.persist_scan_metadata(
            ScanMetadata(
                scan_id="scan_1",
                status="completed",
                created_at=created_at,
                completed_at=completed_at,
            )
        )
        persistence.persist_scan_event(
            PersistedScanEvent(
                scan_id="scan_1",
                event_id=3,
                type="violation_found",
                timestamp=created_at,
                data={"category": "jailbreak"},
            )
        )
        persistence.persist_final_report(
            FinalReport(
                scan_id="scan_1",
                summary={"final_violation_rate": 0.0},
                markdown_report="# Report\n",
                completed_at=completed_at,
            )
        )

        self.assertEqual(client.calls[0].path, "scans/scan_1")
        self.assertTrue(client.calls[0].merge)
        self.assertEqual(client.calls[0].data["status"], "completed")
        self.assertEqual(client.calls[1].path, "scans/scan_1/events/000003")
        self.assertFalse(client.calls[1].merge)
        self.assertEqual(client.calls[1].data["type"], "violation_found")
        self.assertEqual(client.calls[2].path, "scans/scan_1/report/final")
        self.assertTrue(client.calls[2].merge)
        self.assertEqual(client.calls[2].data["markdown_report"], "# Report\n")

    def test_disabled_firestore_adapter_is_noop(self) -> None:
        client = FakeFirestoreClient()
        persistence = FirestorePersistence(client=client, enabled=False)

        persistence.persist_scan_metadata(
            ScanMetadata(
                scan_id="scan_1",
                status="queued",
                created_at=datetime(2026, 6, 14, tzinfo=UTC),
            )
        )

        self.assertEqual(client.calls, [])


class InMemoryPersistenceTests(unittest.TestCase):
    def test_store_persists_metadata_events_and_final_report(self) -> None:
        persistence = FakePersistence()
        store = InMemoryScanStore(persistence=persistence)

        record = store.create_scan()
        store.mark_running(record.scan_id)
        store.append_event(
            scan_id=record.scan_id,
            event_type="attack_generated",
            data={"attack_id": "a1"},
        )
        store.complete_scan(
            scan_id=record.scan_id,
            summary={"final_violation_rate": 0.0},
            markdown_report="# Report\n",
        )

        stored_record = store.get_scan(record.scan_id)
        events = store.get_events_after(scan_id=record.scan_id, event_id=0)

        self.assertIsNotNone(stored_record)
        self.assertEqual(stored_record.status, "completed")
        self.assertEqual(len(events), 1)
        self.assertEqual(
            [metadata.status for metadata in persistence.metadata],
            ["queued", "running", "completed"],
        )
        self.assertEqual(persistence.events[0].type, "attack_generated")
        self.assertEqual(persistence.reports[0].markdown_report, "# Report\n")

    def test_store_keeps_working_when_persistence_fails(self) -> None:
        store = InMemoryScanStore(persistence=FailingPersistence())

        record = store.create_scan()
        store.append_event(
            scan_id=record.scan_id,
            event_type="scan_completed",
            data={"final_violation_rate": 0.0},
        )

        self.assertEqual(store.get_scan(record.scan_id).status, "queued")
        self.assertEqual(
            len(store.get_events_after(scan_id=record.scan_id, event_id=0)),
            1,
        )

    def test_store_reads_persisted_scan_events_and_report(self) -> None:
        completed_at = datetime(2026, 6, 14, 1, tzinfo=UTC)
        persistence = ReadablePersistence(
            metadata=ScanMetadata(
                scan_id="scan_1",
                status="completed",
                created_at=datetime(2026, 6, 14, tzinfo=UTC),
                completed_at=completed_at,
            ),
            events=[
                PersistedScanEvent(
                    scan_id="scan_1",
                    event_id=1,
                    type="attack_generated",
                    timestamp=completed_at,
                    data={"attack_id": "a1"},
                )
            ],
            report=FinalReport(
                scan_id="scan_1",
                summary={"final_violation_rate": 0.0},
                markdown_report="# Report\n",
                completed_at=completed_at,
            ),
        )
        store = InMemoryScanStore(persistence=persistence)

        record = store.get_scan("scan_1")
        events = store.get_events_after(scan_id="scan_1", event_id=0)

        self.assertIsNotNone(record)
        self.assertEqual(record.status, "completed")
        self.assertEqual(record.summary["final_violation_rate"], 0.0)
        self.assertEqual(record.markdown_report, "# Report\n")
        self.assertEqual(events[0].type, "attack_generated")


class FakeSetCall:
    def __init__(self, *, path: str, data: dict[str, Any], merge: bool) -> None:
        self.path = path
        self.data = data
        self.merge = merge


class FakeFirestoreClient:
    def __init__(self) -> None:
        self.calls: list[FakeSetCall] = []

    def collection(self, name: str) -> "FakeCollection":
        return FakeCollection(path=name, calls=self.calls)


class FakeCollection:
    def __init__(self, *, path: str, calls: list[FakeSetCall]) -> None:
        self.path = path
        self.calls = calls

    def document(self, document_id: str) -> "FakeDocument":
        return FakeDocument(path=f"{self.path}/{document_id}", calls=self.calls)


class FakeDocument:
    def __init__(self, *, path: str, calls: list[FakeSetCall]) -> None:
        self.path = path
        self.calls = calls

    def collection(self, name: str) -> FakeCollection:
        return FakeCollection(path=f"{self.path}/{name}", calls=self.calls)

    def set(self, data: dict[str, Any], merge: bool = False) -> None:
        self.calls.append(FakeSetCall(path=self.path, data=data, merge=merge))


class FakePersistence:
    def __init__(self) -> None:
        self.metadata: list[ScanMetadata] = []
        self.events: list[PersistedScanEvent] = []
        self.reports: list[FinalReport] = []

    def persist_scan_metadata(self, metadata: ScanMetadata) -> None:
        self.metadata.append(metadata)

    def persist_scan_event(self, event: PersistedScanEvent) -> None:
        self.events.append(event)

    def persist_final_report(self, report: FinalReport) -> None:
        self.reports.append(report)


class FailingPersistence:
    def persist_scan_metadata(self, metadata: ScanMetadata) -> None:
        raise RuntimeError("storage unavailable")

    def persist_scan_event(self, event: PersistedScanEvent) -> None:
        raise RuntimeError("storage unavailable")

    def persist_final_report(self, report: FinalReport) -> None:
        raise RuntimeError("storage unavailable")


class ReadablePersistence(FakePersistence):
    def __init__(
        self,
        *,
        metadata: ScanMetadata,
        events: list[PersistedScanEvent],
        report: FinalReport,
    ) -> None:
        super().__init__()
        self._metadata = metadata
        self._events = events
        self._report = report

    def load_scan_metadata(self, scan_id: str) -> ScanMetadata | None:
        if scan_id == self._metadata.scan_id:
            return self._metadata
        return None

    def load_scan_events_after(
        self,
        *,
        scan_id: str,
        event_id: int,
    ) -> list[PersistedScanEvent]:
        if scan_id != self._metadata.scan_id:
            return []
        return [event for event in self._events if event.event_id > event_id]

    def load_final_report(self, scan_id: str) -> FinalReport | None:
        if scan_id == self._report.scan_id:
            return self._report
        return None


if __name__ == "__main__":
    unittest.main()
