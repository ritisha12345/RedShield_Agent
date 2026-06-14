"""First RedShield scan API routes."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from agent.orchestrator import run_scan
from api.schemas import (
    ScanCreateRequest,
    ScanCreateResponse,
    ScanReportResponse,
    ScanStatusResponse,
)
from api.storage import SCAN_STORE, ScanEvent, ScanRecord
import tasks.runner as scan_runner
from tasks.runner import sanitize_error, scan_settings
from utils.settings import get_scan_execution_mode


router = APIRouter()
SCAN_EXECUTOR = ThreadPoolExecutor(max_workers=4)


@router.post("/scans", response_model=ScanCreateResponse)
def create_scan(request: ScanCreateRequest) -> ScanCreateResponse:
    """Queue a scan in-process and return immediately."""

    record = SCAN_STORE.create_scan(
        app_name=request.app_name,
        app_category=request.app_category,
        settings=scan_settings(request),
    )
    try:
        _enqueue_scan(record.scan_id, request)
    except Exception as error:
        sanitized_error = sanitize_error(error)
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
        events_url=f"/scans/{record.scan_id}/events",
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
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/scans/{scan_id}/events")
def stream_scan_events(scan_id: str) -> StreamingResponse:
    """Compatibility endpoint matching the documented SSE route."""

    return stream_scan(scan_id)


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
        scan_runner.run_scan = run_scan
        SCAN_EXECUTOR.submit(scan_runner.run_scan_job, scan_id, request)
        return
    if not SCAN_STORE.has_shared_persistence():
        raise RuntimeError("Celery scan execution requires shared persistence.")

    from tasks.scans import run_scan_task

    run_scan_task.delay(scan_id, request.model_dump(mode="json"))

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
            if record.status in {"completed", "completed_with_risks", "failed"}:
                break
            yield ": keep-alive\n\n"
            continue

        for event in events:
            last_event_id = event.event_id
            yield _format_sse_event(event)

        if record.status in {"completed", "completed_with_risks", "failed"}:
            break


def _status_response(record: ScanRecord) -> ScanStatusResponse:
    """Convert an internal record into an API response."""

    return ScanStatusResponse(
        scan_id=record.scan_id,
        status=record.status,
        stage=record.stage,
        progress_current=record.progress_current,
        progress_total=record.progress_total,
        metrics=record.metrics,
        created_at=record.created_at.isoformat(),
        started_at=record.started_at.isoformat() if record.started_at else None,
        completed_at=record.completed_at.isoformat() if record.completed_at else None,
        summary=record.summary,
        markdown_report=record.markdown_report,
        error=record.error,
    )


def _format_sse_event(event: ScanEvent) -> str:
    """Format one event for the SSE wire protocol."""

    payload = json.dumps(event.model_dump(mode="json"), separators=(",", ":"))
    return f"id: {event.event_id}\nevent: {event.type}\ndata: {payload}\n\n"

