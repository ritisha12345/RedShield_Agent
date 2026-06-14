"""In-memory scan storage for the first development API layer."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from threading import Condition, Lock
from typing import Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from firebase.firestore import build_firestore_persistence_from_env
from models import FinalReport, PersistedScanEvent, ScanMetadata


class ScanPersistence(Protocol):
    """Persistence backend used by the development scan store."""

    def persist_scan_metadata(self, metadata: ScanMetadata) -> None:
        """Persist scan metadata."""

    def persist_scan_event(self, event: PersistedScanEvent) -> None:
        """Persist a scan event."""

    def persist_final_report(self, report: FinalReport) -> None:
        """Persist a final report."""


class ScanRecord(BaseModel):
    """Sanitized in-memory record for one scan."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(..., min_length=1)
    status: str
    created_at: datetime
    completed_at: datetime | None = None
    summary: dict | None = None
    markdown_report: str | None = None
    error: str | None = None


class ScanEvent(BaseModel):
    """Sanitized scan event stored for SSE replay."""

    model_config = ConfigDict(extra="forbid")

    event_id: int = Field(..., ge=1)
    type: str = Field(..., min_length=1)
    timestamp: datetime
    data: dict


class InMemoryScanStore:
    """Thread-safe in-memory scan store for local development."""

    def __init__(self, persistence: ScanPersistence | None = None) -> None:
        """Initialize an empty scan store."""

        self._records: dict[str, ScanRecord] = {}
        self._events: dict[str, list[ScanEvent]] = {}
        self._lock = Lock()
        self._condition = Condition(self._lock)
        self._persistence = (
            persistence
            if persistence is not None
            else build_firestore_persistence_from_env()
        )

    def create_scan(self) -> ScanRecord:
        """Create a running scan record."""

        record = ScanRecord(
            scan_id=f"scan_{uuid4().hex}",
            status="queued",
            created_at=datetime.now(UTC),
        )
        with self._lock:
            self._records[record.scan_id] = record
            self._events[record.scan_id] = []
            self._condition.notify_all()
        self._persist_metadata(record)
        return record

    def mark_running(self, scan_id: str) -> ScanRecord:
        """Mark a scan as running."""

        with self._lock:
            record = self._require_scan(scan_id)
            updated = record.model_copy(update={"status": "running"})
            self._records[scan_id] = updated
            self._condition.notify_all()
        self._persist_metadata(updated)
        return updated

    def complete_scan(
        self,
        *,
        scan_id: str,
        summary: dict,
        markdown_report: str,
    ) -> ScanRecord:
        """Mark a scan completed with sanitized output."""

        with self._lock:
            record = self._require_scan(scan_id)
            updated = record.model_copy(
                update={
                    "status": "completed",
                    "completed_at": datetime.now(UTC),
                    "summary": summary,
                    "markdown_report": markdown_report,
                    "error": None,
                }
            )
            self._records[scan_id] = updated
            self._condition.notify_all()
        self._persist_metadata(updated)
        self._persist_final_report(updated)
        return updated

    def fail_scan(self, *, scan_id: str, error: str) -> ScanRecord:
        """Mark a scan failed with a sanitized error."""

        with self._lock:
            record = self._require_scan(scan_id)
            updated = record.model_copy(
                update={
                    "status": "failed",
                    "completed_at": datetime.now(UTC),
                    "error": error,
                }
            )
            self._records[scan_id] = updated
            self._condition.notify_all()
        self._persist_metadata(updated)
        return updated

    def append_event(
        self,
        *,
        scan_id: str,
        event_type: str,
        data: dict,
    ) -> ScanEvent:
        """Append one sanitized event to a scan."""

        with self._lock:
            self._require_scan(scan_id)
            events = self._events.setdefault(scan_id, [])
            event = ScanEvent(
                event_id=len(events) + 1,
                type=event_type,
                timestamp=datetime.now(UTC),
                data=data,
            )
            events.append(event)
            self._condition.notify_all()
        self._persist_event(scan_id=scan_id, event=event)
        return event

    def get_scan(self, scan_id: str) -> ScanRecord | None:
        """Return a scan by ID if present."""

        with self._lock:
            return self._records.get(scan_id)

    def get_events_after(self, *, scan_id: str, event_id: int) -> list[ScanEvent]:
        """Return events with ID greater than the supplied event ID."""

        with self._lock:
            if scan_id not in self._records:
                raise KeyError(scan_id)
            return [
                event
                for event in self._events.get(scan_id, [])
                if event.event_id > event_id
            ]

    def wait_for_events_after(
        self,
        *,
        scan_id: str,
        event_id: int,
        timeout_seconds: float = 15.0,
    ) -> tuple[ScanRecord | None, list[ScanEvent]]:
        """Wait for new events or terminal scan state."""

        with self._condition:
            self._condition.wait_for(
                lambda: (
                    scan_id not in self._records
                    or any(
                        event.event_id > event_id
                        for event in self._events.get(scan_id, [])
                    )
                    or self._records[scan_id].status in {"completed", "failed"}
                ),
                timeout=timeout_seconds,
            )
            record = self._records.get(scan_id)
            events = [
                event
                for event in self._events.get(scan_id, [])
                if event.event_id > event_id
            ]
            return record, events

    def clear(self) -> None:
        """Remove all in-memory scans."""

        with self._lock:
            self._records.clear()
            self._events.clear()
            self._condition.notify_all()

    def _require_scan(self, scan_id: str) -> ScanRecord:
        """Return a scan or raise KeyError."""

        record = self._records.get(scan_id)
        if record is None:
            raise KeyError(scan_id)
        return record

    def _persist_metadata(self, record: ScanRecord) -> None:
        """Persist sanitized scan metadata without affecting in-memory state."""

        metadata = ScanMetadata(
            scan_id=record.scan_id,
            status=record.status,
            created_at=record.created_at,
            completed_at=record.completed_at,
            error=record.error,
        )
        self._safe_persist(lambda: self._persistence.persist_scan_metadata(metadata))

    def _persist_event(self, *, scan_id: str, event: ScanEvent) -> None:
        """Persist a sanitized scan event without affecting SSE replay."""

        persisted_event = PersistedScanEvent(
            scan_id=scan_id,
            event_id=event.event_id,
            type=event.type,
            timestamp=event.timestamp,
            data=event.data,
        )
        self._safe_persist(
            lambda: self._persistence.persist_scan_event(persisted_event)
        )

    def _persist_final_report(self, record: ScanRecord) -> None:
        """Persist the final report when a completed scan has report content."""

        if (
            record.summary is None
            or record.markdown_report is None
            or record.completed_at is None
        ):
            return

        report = FinalReport(
            scan_id=record.scan_id,
            summary=record.summary,
            markdown_report=record.markdown_report,
            completed_at=record.completed_at,
        )
        self._safe_persist(lambda: self._persistence.persist_final_report(report))

    @staticmethod
    def _safe_persist(operation: Callable[[], None]) -> None:
        """Run one persistence operation without failing the live scan."""

        try:
            operation()
        except Exception:
            return


SCAN_STORE = InMemoryScanStore()
