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
    app_name: str | None = None
    app_category: str | None = None
    stage: str = "queued"
    progress_current: int = Field(default=0, ge=0)
    progress_total: int = Field(default=0, ge=0)
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    settings: dict[str, Any] = Field(default_factory=dict)
    metrics: dict[str, Any] = Field(default_factory=dict)


class PersistedScanEvent(BaseModel):
    """Sanitized scan event serialized into Firestore."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(..., min_length=1)
    event_id: int = Field(..., ge=1)
    type: str = Field(..., min_length=1)
    stage: str = "running"
    level: str = "info"
    message: str = ""
    timestamp: datetime
    data: dict[str, Any]


class FinalReport(BaseModel):
    """Final scan report document persisted after orchestration completes."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(..., min_length=1)
    summary: dict[str, Any]
    markdown_report: str = Field(..., min_length=1)
    completed_at: datetime
