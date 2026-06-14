"""API request and response schemas for RedShield scans."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ScanCreateRequest(BaseModel):
    """Request body for starting a scan."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    app_name: str | None = Field(default=None, min_length=1)
    app_category: str = Field(..., min_length=1)
    system_prompt: str = Field(..., min_length=1)
    normal_use_cases: list[str] = Field(default_factory=list)
    restricted_behaviors: list[str] = Field(default_factory=list)
    competitors: list[str] = Field(default_factory=list)
    attacks_per_category: int = Field(default=1, ge=1)
    success_threshold: float = Field(default=0.05, ge=0.0, le=1.0)
    max_rounds: int = Field(default=2, ge=0)
    target_url: str | None = Field(default=None, min_length=1)
    mock_target_response: str = Field(
        default="Mock target response: request handled safely.",
        min_length=1,
    )


class ScanCreateResponse(BaseModel):
    """Response body returned after a scan is queued."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str
    status: str
    summary: dict | None
    status_url: str
    stream_url: str
    events_url: str
    report_url: str


class ScanStatusResponse(BaseModel):
    """Response body for retrieving a scan."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str
    status: str
    stage: str
    progress_current: int
    progress_total: int
    metrics: dict
    created_at: str
    started_at: str | None
    completed_at: str | None
    summary: dict | None
    markdown_report: str | None
    error: str | None


class ScanReportResponse(BaseModel):
    """Response body for retrieving a completed report."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str
    status: str
    summary: dict | None
    markdown_report: str | None
    error: str | None
