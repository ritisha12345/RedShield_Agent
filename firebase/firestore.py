"""Firestore persistence adapter for RedShield scan data."""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from models import FinalReport, PersistedScanEvent, ScanMetadata
from utils.settings import env_truthy

try:
    from google.cloud import firestore
except ImportError:  # pragma: no cover - exercised by disabled fallback.
    firestore = None

try:
    from google.oauth2 import service_account
except ImportError:  # pragma: no cover - bundled with google-cloud-firestore.
    service_account = None


TRUE_VALUES = {"1", "true", "yes", "on"}
SERVICE_ACCOUNT_JSON_ENV_NAMES = (
    "GOOGLE_APPLICATION_CREDENTIALS_JSON",
    "FIREBASE_SERVICE_ACCOUNT_JSON",
)
SERVICE_ACCOUNT_B64_ENV_NAMES = (
    "GOOGLE_APPLICATION_CREDENTIALS_B64",
    "FIREBASE_SERVICE_ACCOUNT_B64",
)
PROJECT_ENV_NAMES = (
    "GOOGLE_CLOUD_PROJECT",
    "FIRESTORE_PROJECT_ID",
    "FIREBASE_PROJECT_ID",
)


class FirestorePersistence:
    """Persist sanitized scan documents into Firestore."""

    def __init__(
        self,
        *,
        client: Any | None = None,
        enabled: bool = True,
        required: bool = False,
        project: str | None = None,
        credentials: Any | None = None,
    ) -> None:
        """Create a Firestore persistence adapter."""

        self._client = client
        self._enabled = enabled
        self._required = required
        self._last_error: str | None = None

        if self._client is None and self._enabled:
            if firestore is None:
                self._disable_or_raise("google-cloud-firestore is not installed.")
            else:
                try:
                    self._client = firestore.Client(
                        project=project,
                        credentials=credentials,
                    )
                except Exception as error:
                    self._disable_or_raise(
                        "Firestore client initialization failed.",
                        error=error,
                    )

        if self._client is None:
            self._enabled = False

    @property
    def enabled(self) -> bool:
        """Return whether this adapter will write to Firestore."""

        return self._enabled

    @property
    def status(self) -> str:
        """Return a sanitized readiness status."""

        if self._enabled:
            return "ok"
        if self._last_error:
            return "unavailable"
        return "disabled"

    @property
    def last_error(self) -> str | None:
        """Return a sanitized initialization error category."""

        return self._last_error

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

    def load_scan_metadata(self, scan_id: str) -> ScanMetadata | None:
        """Load sanitized scan metadata from ``scans/{scan_id}``."""

        if not self._enabled:
            return None

        snapshot = self._scan_document(scan_id).get()
        if not getattr(snapshot, "exists", False):
            return None
        data = snapshot.to_dict() or {}
        return ScanMetadata.model_validate(_model_fields(data, ScanMetadata))

    def load_scan_events_after(
        self,
        *,
        scan_id: str,
        event_id: int,
    ) -> list[PersistedScanEvent]:
        """Load sanitized scan events with an ID greater than ``event_id``."""

        if not self._enabled:
            return []

        snapshots = self._scan_document(scan_id).collection("events").stream()
        events = [
            PersistedScanEvent.model_validate(
                _model_fields(snapshot.to_dict() or {}, PersistedScanEvent)
            )
            for snapshot in snapshots
            if (snapshot.to_dict() or {}).get("event_id", 0) > event_id
        ]
        return sorted(events, key=lambda event: event.event_id)

    def load_final_report(self, scan_id: str) -> FinalReport | None:
        """Load the final report for one scan."""

        if not self._enabled:
            return None

        snapshot = (
            self._scan_document(scan_id).collection("report").document("final").get()
        )
        if not getattr(snapshot, "exists", False):
            return None
        data = snapshot.to_dict() or {}
        return FinalReport.model_validate(_model_fields(data, FinalReport))

    def _scan_document(self, scan_id: str) -> Any:
        """Return the Firestore document reference for one scan."""

        return self._client.collection("scans").document(scan_id)

    def _disable_or_raise(
        self,
        message: str,
        *,
        error: Exception | None = None,
    ) -> None:
        """Disable optional Firestore or raise when it is required."""

        self._last_error = error.__class__.__name__ if error else message
        self._enabled = False
        if self._required:
            raise RuntimeError(message) from error


def build_firestore_persistence_from_env() -> FirestorePersistence:
    """Build Firestore persistence from local environment settings."""

    enabled = os.getenv("REDSHIELD_FIRESTORE_ENABLED", "").lower() in TRUE_VALUES
    required = env_truthy("REDSHIELD_FIRESTORE_REQUIRED")

    if not enabled:
        return FirestorePersistence(enabled=False, required=required)

    return FirestorePersistence(
        enabled=True,
        required=required,
        project=_project_from_env(),
        credentials=_credentials_from_env(),
    )


def firestore_readiness_from_env() -> dict[str, str | bool | None]:
    """Return sanitized Firestore readiness details for health checks."""

    try:
        persistence = build_firestore_persistence_from_env()
    except Exception as error:
        return {
            "enabled": True,
            "status": "unavailable",
            "error": error.__class__.__name__,
        }

    return {
        "enabled": persistence.enabled,
        "status": persistence.status,
        "error": persistence.last_error,
    }


def _project_from_env() -> str | None:
    """Return the configured Google Cloud project ID, if supplied."""

    for env_name in PROJECT_ENV_NAMES:
        value = os.getenv(env_name)
        if value:
            return value.strip()
    return None


def _credentials_from_env() -> Any | None:
    """Return service account credentials supplied via environment variables."""

    if service_account is None:
        return None

    payload = _service_account_payload_from_env()
    if payload is None:
        return None
    return service_account.Credentials.from_service_account_info(payload)


def _service_account_payload_from_env() -> dict[str, Any] | None:
    """Read service-account JSON from raw or base64 environment variables."""

    for env_name in SERVICE_ACCOUNT_JSON_ENV_NAMES:
        value = os.getenv(env_name)
        if value:
            return json.loads(value)

    for env_name in SERVICE_ACCOUNT_B64_ENV_NAMES:
        value = os.getenv(env_name)
        if value:
            decoded = base64.b64decode(value).decode("utf-8")
            return json.loads(decoded)

    return None


def _event_document_id(event_id: int) -> str:
    """Return a sortable event document ID."""

    return f"{event_id:06d}"


def _to_firestore_document(
    model: ScanMetadata | PersistedScanEvent | FinalReport,
) -> dict[str, Any]:
    """Serialize a Pydantic persistence model into Firestore document data."""

    return model.model_dump(mode="python")


def _model_fields(data: dict[str, Any], model_type: Any) -> dict[str, Any]:
    """Return only fields accepted by a Pydantic model."""

    return {key: data[key] for key in model_type.model_fields if key in data}
