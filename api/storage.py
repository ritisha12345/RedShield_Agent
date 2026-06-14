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
    app_name: str | None = None
    app_category: str | None = None
    stage: str = "queued"
    progress_current: int = Field(default=0, ge=0)
    progress_total: int = Field(default=0, ge=0)
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    summary: dict | None = None
    markdown_report: str | None = None
    error: str | None = None
    settings: dict = Field(default_factory=dict)
    metrics: dict = Field(default_factory=dict)


class ScanEvent(BaseModel):
    """Sanitized scan event stored for SSE replay."""

    model_config = ConfigDict(extra="forbid")

    event_id: int = Field(..., ge=1)
    type: str = Field(..., min_length=1)
    stage: str = "running"
    level: str = "info"
    message: str = ""
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

    def create_scan(
        self,
        *,
        app_name: str | None = None,
        app_category: str | None = None,
        settings: dict | None = None,
    ) -> ScanRecord:
        """Create a running scan record."""

        record = ScanRecord(
            scan_id=f"scan_{uuid4().hex}",
            status="queued",
            app_name=app_name,
            app_category=app_category,
            created_at=datetime.now(UTC),
            settings=settings or {},
        )
        with self._lock:
            self._records[record.scan_id] = record
            self._events[record.scan_id] = []
            self._condition.notify_all()
        self._persist_metadata(record)
        return record

    def mark_running(self, scan_id: str) -> ScanRecord:
        """Mark a scan as running."""

        self._ensure_scan_loaded(scan_id)
        with self._lock:
            record = self._records.get(scan_id)
            if record is None:
                record = ScanRecord(
                    scan_id=scan_id,
                    status="queued",
                    created_at=datetime.now(UTC),
                )
            updated = record.model_copy(
                update={
                    "status": "running",
                    "stage": "attack_generation",
                    "started_at": record.started_at or datetime.now(UTC),
                }
            )
            self._records[scan_id] = updated
            self._events.setdefault(scan_id, [])
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

        self._ensure_scan_loaded(scan_id)
        with self._lock:
            record = self._records.get(scan_id)
            if record is None:
                record = ScanRecord(
                    scan_id=scan_id,
                    status="running",
                    created_at=datetime.now(UTC),
                )
            updated = record.model_copy(
                update={
                    "status": _completion_status(summary),
                    "stage": "completed",
                    "completed_at": datetime.now(UTC),
                    "summary": summary,
                    "markdown_report": markdown_report,
                    "error": None,
                    "metrics": _metrics_from_summary(summary),
                }
            )
            self._records[scan_id] = updated
            self._events.setdefault(scan_id, [])
            self._condition.notify_all()
        self._persist_metadata(updated)
        self._persist_final_report(updated)
        return updated

    def fail_scan(self, *, scan_id: str, error: str) -> ScanRecord:
        """Mark a scan failed with a sanitized error."""

        self._ensure_scan_loaded(scan_id)
        with self._lock:
            record = self._records.get(scan_id)
            if record is None:
                record = ScanRecord(
                    scan_id=scan_id,
                    status="running",
                    created_at=datetime.now(UTC),
                )
            updated = record.model_copy(
                update={
                    "status": "failed",
                    "stage": "failed",
                    "completed_at": datetime.now(UTC),
                    "error": error,
                }
            )
            self._records[scan_id] = updated
            self._events.setdefault(scan_id, [])
            self._condition.notify_all()
        self._persist_metadata(updated)
        return updated

    def append_event(
        self,
        *,
        scan_id: str,
        event_type: str,
        data: dict,
        stage: str | None = None,
        level: str = "info",
        message: str | None = None,
    ) -> ScanEvent:
        """Append one sanitized event to a scan."""

        self._ensure_scan_loaded(scan_id)
        with self._lock:
            if scan_id not in self._records:
                self._records[scan_id] = ScanRecord(
                    scan_id=scan_id,
                    status="running",
                    created_at=datetime.now(UTC),
                )
            events = self._events.setdefault(scan_id, [])
            event = ScanEvent(
                event_id=len(events) + 1,
                type=event_type,
                stage=stage or _stage_for_event(event_type),
                level=level,
                message=message or _message_for_event(event_type, data),
                timestamp=datetime.now(UTC),
                data=data,
            )
            events.append(event)
            current_record = self._records[scan_id]
            self._records[scan_id] = current_record.model_copy(
                update={
                    "stage": event.stage,
                    "progress_current": _progress_current(
                        event_type=event_type,
                        record=current_record,
                    ),
                    "progress_total": _progress_total(
                        event_type=event_type,
                        data=data,
                        record=current_record,
                    ),
                    "metrics": _merge_metrics(current_record.metrics, event),
                }
            )
            self._condition.notify_all()
        self._persist_event(scan_id=scan_id, event=event)
        return event

    def get_scan(self, scan_id: str) -> ScanRecord | None:
        """Return a scan by ID if present."""

        with self._lock:
            record = self._records.get(scan_id)

        persisted_record = self._load_persisted_scan(scan_id)
        if persisted_record is not None:
            return persisted_record
        return record

    def get_events_after(self, *, scan_id: str, event_id: int) -> list[ScanEvent]:
        """Return events with ID greater than the supplied event ID."""

        with self._lock:
            if scan_id not in self._records:
                persisted_record = None
            else:
                persisted_record = self._records[scan_id]
            memory_events = [
                event
                for event in self._events.get(scan_id, [])
                if event.event_id > event_id
            ]

        if persisted_record is None and self._load_persisted_scan(scan_id) is None:
            raise KeyError(scan_id)

        persisted_events = self._load_persisted_events_after(
            scan_id=scan_id,
            event_id=event_id,
        )
        events_by_id = {event.event_id: event for event in memory_events}
        events_by_id.update({event.event_id: event for event in persisted_events})
        events = sorted(events_by_id.values(), key=lambda event: event.event_id)

        if persisted_events:
            self._merge_events(scan_id=scan_id, events=events)

        return events

    def wait_for_events_after(
        self,
        *,
        scan_id: str,
        event_id: int,
        timeout_seconds: float = 2.0,
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
                    or self._records[scan_id].status
                    in {"completed", "completed_with_risks", "failed"}
                ),
                timeout=timeout_seconds,
            )
            record = self._records.get(scan_id)
            events = [
                event
                for event in self._events.get(scan_id, [])
                if event.event_id > event_id
            ]

        if events or (
            record is not None
            and record.status in {"completed", "completed_with_risks", "failed"}
        ):
            return record, events

        record = self.get_scan(scan_id)
        try:
            events = self.get_events_after(scan_id=scan_id, event_id=event_id)
        except KeyError:
            events = []
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

    def _ensure_scan_loaded(self, scan_id: str) -> None:
        """Load a scan from persistence if this process has not seen it."""

        with self._lock:
            if scan_id in self._records:
                return
        self._load_persisted_scan(scan_id)

    def _persist_metadata(self, record: ScanRecord) -> None:
        """Persist sanitized scan metadata without affecting in-memory state."""

        metadata = ScanMetadata(
            scan_id=record.scan_id,
            status=record.status,
            app_name=record.app_name,
            app_category=record.app_category,
            stage=record.stage,
            progress_current=record.progress_current,
            progress_total=record.progress_total,
            created_at=record.created_at,
            started_at=record.started_at,
            completed_at=record.completed_at,
            error=record.error,
            settings=record.settings,
            metrics=record.metrics,
        )
        self._safe_persist(lambda: self._persistence.persist_scan_metadata(metadata))

    def _persist_event(self, *, scan_id: str, event: ScanEvent) -> None:
        """Persist a sanitized scan event without affecting SSE replay."""

        persisted_event = PersistedScanEvent(
            scan_id=scan_id,
            event_id=event.event_id,
            type=event.type,
            stage=event.stage,
            level=event.level,
            message=event.message,
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

    def _load_persisted_scan(self, scan_id: str) -> ScanRecord | None:
        """Load one scan record from the persistence backend when available."""

        load_metadata = getattr(self._persistence, "load_scan_metadata", None)
        if load_metadata is None:
            return None

        try:
            metadata = load_metadata(scan_id)
        except Exception:
            return None
        if metadata is None:
            return None

        summary = None
        markdown_report = None
        load_report = getattr(self._persistence, "load_final_report", None)
        if load_report is not None:
            try:
                report = load_report(scan_id)
            except Exception:
                report = None
            if report is not None:
                summary = report.summary
                markdown_report = report.markdown_report

        record = ScanRecord(
            scan_id=metadata.scan_id,
            status=metadata.status,
            app_name=metadata.app_name,
            app_category=metadata.app_category,
            stage=metadata.stage,
            progress_current=metadata.progress_current,
            progress_total=metadata.progress_total,
            created_at=metadata.created_at,
            started_at=metadata.started_at,
            completed_at=metadata.completed_at,
            summary=summary,
            markdown_report=markdown_report,
            error=metadata.error,
            settings=metadata.settings,
            metrics=metadata.metrics,
        )
        with self._lock:
            self._records[scan_id] = record
            self._events.setdefault(scan_id, [])
            self._condition.notify_all()
        return record

    def _load_persisted_events_after(
        self,
        *,
        scan_id: str,
        event_id: int,
    ) -> list[ScanEvent]:
        """Load persisted events from backends that support event reads."""

        load_events = getattr(self._persistence, "load_scan_events_after", None)
        if load_events is None:
            return []

        try:
            persisted_events = load_events(scan_id=scan_id, event_id=event_id)
        except Exception:
            return []

        return [
            ScanEvent(
                event_id=event.event_id,
                type=event.type,
                stage=event.stage,
                level=event.level,
                message=event.message,
                timestamp=event.timestamp,
                data=event.data,
            )
            for event in persisted_events
        ]

    def _merge_events(self, *, scan_id: str, events: list[ScanEvent]) -> None:
        """Merge persisted events into this process's in-memory replay buffer."""

        with self._lock:
            current = {
                event.event_id: event for event in self._events.setdefault(scan_id, [])
            }
            current.update({event.event_id: event for event in events})
            self._events[scan_id] = sorted(
                current.values(),
                key=lambda event: event.event_id,
            )
            self._condition.notify_all()

    @staticmethod
    def _safe_persist(operation: Callable[[], None]) -> None:
        """Run one persistence operation without failing the live scan."""

        try:
            operation()
        except Exception:
            return

    def has_shared_persistence(self) -> bool:
        """Return whether another process can read scan state from persistence."""

        enabled = getattr(self._persistence, "enabled", False)
        return bool(
            enabled
            and hasattr(self._persistence, "load_scan_metadata")
            and hasattr(self._persistence, "load_scan_events_after")
            and hasattr(self._persistence, "load_final_report")
        )


def _completion_status(summary: dict) -> str:
    """Return terminal status while preserving remaining-risk information."""

    remaining_risks = summary.get("remaining_risks") or []
    final_rate = summary.get("final_violation_rate")
    if remaining_risks or (isinstance(final_rate, (int, float)) and final_rate > 0):
        return "completed_with_risks"
    return "completed"


def _metrics_from_summary(summary: dict) -> dict:
    """Build queryable scan metrics from the final summary."""

    return {
        "attacks_total": summary.get("total_attacks", 0),
        "attacks_completed": summary.get("completed_attacks", 0),
        "violations": summary.get("violations", 0),
        "initial_violation_rate": summary.get("initial_violation_rate"),
        "final_violation_rate": summary.get("final_violation_rate"),
    }


def _stage_for_event(event_type: str) -> str:
    """Map event names to scan stages."""

    if event_type in {"scan_started", "attack_generated", "attacks_generated"}:
        return "attack_generation"
    if event_type in {"attack_started", "attack_completed"}:
        return "attack_execution"
    if event_type in {"judge_completed", "violation_found"}:
        return "judging"
    if event_type == "analysis_completed":
        return "analysis"
    if event_type in {"patch_proposed", "patch_applied"}:
        return "patching"
    if event_type in {"verification_started", "verification_completed", "round_completed"}:
        return "verification"
    if event_type in {"report_generated", "scan_completed"}:
        return "reporting"
    if event_type == "scan_failed":
        return "failed"
    return "running"


def _message_for_event(event_type: str, data: dict) -> str:
    """Create a stable user-facing message for one event."""

    attack_id = data.get("attack_id")
    category = data.get("category")
    if event_type == "scan_started":
        return "Scan started."
    if event_type == "attack_generated":
        return f"Generated {category} attack {attack_id}."
    if event_type == "attacks_generated":
        return f"Generated {data.get('count', 0)} attacks."
    if event_type == "attack_completed":
        return f"Executed attack {attack_id}."
    if event_type == "judge_completed":
        return f"Judged attack {attack_id}."
    if event_type == "violation_found":
        return f"Violation found for {category} attack {attack_id}."
    if event_type == "analysis_completed":
        return "Analysis completed."
    if event_type == "patch_proposed":
        return f"Patch proposed for {category}."
    if event_type == "patch_applied":
        return f"Patch applied for {category}."
    if event_type == "verification_completed":
        return f"Verification completed for {category}."
    if event_type == "round_completed":
        return f"Round {data.get('round_index')} completed."
    if event_type == "report_generated":
        return "Report generated."
    if event_type == "scan_completed":
        return "Scan completed."
    if event_type == "scan_failed":
        return "Scan failed."
    return event_type.replace("_", " ").capitalize()


def _progress_current(*, event_type: str, record: ScanRecord) -> int:
    """Return updated completed-work count for a scan event."""

    if event_type == "judge_completed":
        return record.progress_current + 1
    if event_type in {"scan_completed", "report_generated"}:
        return record.progress_total or record.progress_current
    return record.progress_current


def _progress_total(*, event_type: str, data: dict, record: ScanRecord) -> int:
    """Return updated total-work count for a scan event."""

    if event_type == "attacks_generated":
        return int(data.get("count") or record.progress_total)
    return record.progress_total


def _merge_metrics(metrics: dict, event: ScanEvent) -> dict:
    """Merge event-derived metrics into existing scan metrics."""

    merged = dict(metrics)
    if event.type == "attacks_generated":
        merged["attacks_total"] = event.data.get("count", 0)
    if event.type == "attack_generated":
        merged["attacks_total"] = merged.get("attacks_total", 0) + 1
    if event.type == "judge_completed":
        merged["attacks_completed"] = merged.get("attacks_completed", 0) + 1
        if event.data.get("verdict") == "violation":
            merged["violations"] = merged.get("violations", 0) + 1
    if event.type == "scan_completed":
        merged["initial_violation_rate"] = event.data.get("initial_violation_rate")
        merged["final_violation_rate"] = event.data.get("final_violation_rate")
    return merged


SCAN_STORE = InMemoryScanStore()
