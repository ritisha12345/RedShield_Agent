"""Firestore persistence adapter for RedShield scan data."""

from __future__ import annotations

import os
from typing import Any

from models import FinalReport, PersistedScanEvent, ScanMetadata

try:
    from google.cloud import firestore
except ImportError:  # pragma: no cover - exercised by disabled fallback.
    firestore = None


TRUE_VALUES = {"1", "true", "yes", "on"}


class FirestorePersistence:
    """Persist sanitized scan documents into Firestore."""

    def __init__(self, *, client: Any | None = None, enabled: bool = True) -> None:
        """Create a Firestore persistence adapter."""

        self._client = client
        self._enabled = enabled

        if self._client is None and self._enabled:
            if firestore is None:
                self._enabled = False
            else:
                try:
                    self._client = firestore.Client()
                except Exception:
                    self._enabled = False

        if self._client is None:
            self._enabled = False

    @property
    def enabled(self) -> bool:
        """Return whether this adapter will write to Firestore."""

        return self._enabled

    def persist_scan_metadata(self, metadata: ScanMetadata) -> None:
        """Persist scan metadata to ``scans/{scan_id}``."""

        if not self._enabled:
            return

        self._scan_document(metadata.scan_id).set(
            _to_firestore_document(metadata),
            merge=True,
        )

    def persist_scan_event(self, event: PersistedScanEvent) -> None:
        """Persist one event to ``scans/{scan_id}/events/{event_id}``."""

        if not self._enabled:
            return

        (
            self._scan_document(event.scan_id)
            .collection("events")
            .document(_event_document_id(event.event_id))
            .set(_to_firestore_document(event))
        )

    def persist_final_report(self, report: FinalReport) -> None:
        """Persist the final report to ``scans/{scan_id}/report/final``."""

        if not self._enabled:
            return

        (
            self._scan_document(report.scan_id)
            .collection("report")
            .document("final")
            .set(_to_firestore_document(report), merge=True)
        )

    def _scan_document(self, scan_id: str) -> Any:
        """Return the Firestore document reference for one scan."""

        return self._client.collection("scans").document(scan_id)


def build_firestore_persistence_from_env() -> FirestorePersistence:
    """Build Firestore persistence from local environment settings."""

    enabled = os.getenv("REDSHIELD_FIRESTORE_ENABLED", "").lower() in TRUE_VALUES
    return FirestorePersistence(enabled=enabled)


def _event_document_id(event_id: int) -> str:
    """Return a sortable event document ID."""

    return f"{event_id:06d}"


def _to_firestore_document(
    model: ScanMetadata | PersistedScanEvent | FinalReport,
) -> dict[str, Any]:
    """Serialize a Pydantic persistence model into Firestore document data."""

    return model.model_dump(mode="python")
