"""First RedShield scan API routes."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from agent.orchestrator import run_scan
from api.storage import SCAN_STORE, ScanEvent, ScanRecord
from target import MockTargetAdapter


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


@router.post("/scans", response_model=ScanCreateResponse)
def create_scan(request: ScanCreateRequest) -> ScanCreateResponse:
    """Queue a scan in-process and return immediately."""

    record = SCAN_STORE.create_scan()
    SCAN_EXECUTOR.submit(_run_scan_job, record.scan_id, request)

    return ScanCreateResponse(
        scan_id=record.scan_id,
        status=record.status,
        summary=record.summary,
        status_url=f"/scans/{record.scan_id}",
        stream_url=f"/scans/{record.scan_id}/stream",
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
            target_adapter=MockTargetAdapter(
                default_response=request.mock_target_response,
            ),
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
