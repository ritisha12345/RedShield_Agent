"""First RedShield scan API routes."""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from agent.orchestrator import run_scan
from api.storage import SCAN_STORE, ScanEvent, ScanRecord
from target import HttpTargetAdapter, MockTargetAdapter, TargetAdapter
from utils.settings import get_scan_execution_mode, get_target_timeout_seconds


router = APIRouter()
SCAN_EXECUTOR = ThreadPoolExecutor(max_workers=4)


class ScanCreateRequest(BaseModel):
    """Request body for starting a development scan."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    app_category: str = Field(..., min_length=1)
    system_prompt: str = Field(..., min_length=1)
    attacks_per_category: int = Field(default=1, ge=1)
    success_threshold: float = Field(default=0.05, ge=0.0, le=1.0)
    max_rounds: int = Field(default=1, ge=0)
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
    report_url: str


class ScanStatusResponse(BaseModel):
    """Response body for retrieving an in-memory scan."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str
    status: str
    created_at: str
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


@router.post("/scans", response_model=ScanCreateResponse)
def create_scan(request: ScanCreateRequest) -> ScanCreateResponse:
    """Queue a scan in-process and return immediately."""

    record = SCAN_STORE.create_scan()
    try:
        _enqueue_scan(record.scan_id, request)
    except Exception as error:
        sanitized_error = _sanitize_error(error)
        SCAN_STORE.fail_scan(scan_id=record.scan_id, error=sanitized_error)
        raise HTTPException(
            status_code=503,
            detail="Scan queue is not available.",
        ) from error

    return ScanCreateResponse(
        scan_id=record.scan_id,
        status=record.status,
        summary=record.summary,
        status_url=f"/scans/{record.scan_id}",
        stream_url=f"/scans/{record.scan_id}/stream",
        report_url=f"/scans/{record.scan_id}/report",
    )


@router.get("/scans/{scan_id}", response_model=ScanStatusResponse)
def get_scan(scan_id: str) -> ScanStatusResponse:
    """Return one in-memory scan record."""

    record = SCAN_STORE.get_scan(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return _status_response(record)


@router.get("/scans/{scan_id}/stream")
def stream_scan(scan_id: str) -> StreamingResponse:
    """Stream scan events with Server-Sent Events."""

    if SCAN_STORE.get_scan(scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return StreamingResponse(
        _scan_event_stream(scan_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache"},
    )


@router.get("/scans/{scan_id}/report", response_model=ScanReportResponse)
def get_scan_report(scan_id: str) -> ScanReportResponse:
    """Return the final report for a scan when available."""

    record = SCAN_STORE.get_scan(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return ScanReportResponse(
        scan_id=record.scan_id,
        status=record.status,
        summary=record.summary,
        markdown_report=record.markdown_report,
        error=record.error,
    )


def _enqueue_scan(scan_id: str, request: ScanCreateRequest) -> None:
    """Queue one scan using the configured execution backend."""

    execution_mode = get_scan_execution_mode()
    if execution_mode == "thread":
        SCAN_EXECUTOR.submit(_run_scan_job, scan_id, request)
        return

    from tasks.scans import run_scan_task

    run_scan_task.delay(scan_id, request.model_dump(mode="json"))


def _run_scan_job(scan_id: str, request: ScanCreateRequest) -> None:
    """Run an orchestrator scan and persist sanitized in-memory results."""

    SCAN_STORE.mark_running(scan_id)

    def emit_event(event_type: str, data: dict) -> None:
        SCAN_STORE.append_event(
            scan_id=scan_id,
            event_type=event_type,
            data=data,
        )

    try:
        result = run_scan(
            app_category=request.app_category,
            system_prompt=request.system_prompt,
            target_adapter=_build_target_adapter(request),
            attacks_per_category=request.attacks_per_category,
            success_threshold=request.success_threshold,
            max_rounds=request.max_rounds,
            event_callback=emit_event,
        )
        SCAN_STORE.complete_scan(
            scan_id=scan_id,
            summary=result.summary.model_dump(mode="json"),
            markdown_report=result.markdown_report,
        )
    except Exception as error:
        sanitized_error = _sanitize_error(error)
        SCAN_STORE.append_event(
            scan_id=scan_id,
            event_type="scan_failed",
            data={"error": sanitized_error},
        )
        SCAN_STORE.fail_scan(scan_id=scan_id, error=sanitized_error)


def _scan_event_stream(scan_id: str):
    """Yield Server-Sent Events for one scan."""

    last_event_id = 0
    while True:
        record, events = SCAN_STORE.wait_for_events_after(
            scan_id=scan_id,
            event_id=last_event_id,
        )
        if record is None:
            break
        if not events:
            if record.status in {"completed", "failed"}:
                break
            yield ": keep-alive\n\n"
            continue

        for event in events:
            last_event_id = event.event_id
            yield _format_sse_event(event)

        if record.status in {"completed", "failed"}:
            break


def _status_response(record: ScanRecord) -> ScanStatusResponse:
    """Convert an internal record into an API response."""

    return ScanStatusResponse(
        scan_id=record.scan_id,
        status=record.status,
        created_at=record.created_at.isoformat(),
        completed_at=record.completed_at.isoformat() if record.completed_at else None,
        summary=record.summary,
        markdown_report=record.markdown_report,
        error=record.error,
    )


def _format_sse_event(event: ScanEvent) -> str:
    """Format one event for the SSE wire protocol."""

    payload = json.dumps(event.model_dump(mode="json"), separators=(",", ":"))
    return f"id: {event.event_id}\nevent: {event.type}\ndata: {payload}\n\n"


def _sanitize_error(error: Exception) -> str:
    """Return an error safe for API responses."""

    return f"Scan failed: {error.__class__.__name__}"


def _build_target_adapter(request: ScanCreateRequest) -> TargetAdapter:
    """Build the target adapter from request or deployment configuration."""

    target_url = request.target_url or os.getenv("REDSHIELD_TARGET_URL")
    if target_url:
        return HttpTargetAdapter(
            endpoint_url=target_url,
            timeout_seconds=get_target_timeout_seconds(),
            headers=_target_headers_from_env(),
        )

    return MockTargetAdapter(default_response=request.mock_target_response)


def _target_headers_from_env() -> dict[str, str]:
    """Return optional target auth headers from environment variables."""

    header_name = os.getenv("REDSHIELD_TARGET_AUTH_HEADER")
    header_value = os.getenv("REDSHIELD_TARGET_AUTH_TOKEN")
    if not header_name or not header_value:
        return {}
    return {header_name: header_value}
