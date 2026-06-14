"""Persistence models for scan storage boundaries."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


ScanStatus = Literal[
    "queued",
    "running",
    "completed",
    "completed_with_risks",
    "failed",
    "cancelled",
]


class ScanMetadata(BaseModel):
    """Sanitized scan metadata safe to persist outside the request lifecycle."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(..., min_length=1)
    status: ScanStatus
    created_at: datetime
    completed_at: datetime | None = None
    error: str | None = None


class PersistedScanEvent(BaseModel):
    """Sanitized scan event serialized into Firestore."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(..., min_length=1)
    event_id: int = Field(..., ge=1)
    type: str = Field(..., min_length=1)
    timestamp: datetime
    data: dict[str, Any]


class FinalReport(BaseModel):
    """Final scan report document persisted after orchestration completes."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(..., min_length=1)
    summary: dict[str, Any]
    markdown_report: str = Field(..., min_length=1)
    completed_at: datetime
