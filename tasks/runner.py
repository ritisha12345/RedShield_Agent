"""Shared scan runner used by API thread mode and Celery workers."""

from __future__ import annotations

import os

from agent.orchestrator import run_scan
from api.schemas import ScanCreateRequest
from api.storage import SCAN_STORE
from target import HttpTargetAdapter, ImportTargetAdapter, MockTargetAdapter, TargetAdapter
from utils.settings import get_target_timeout_seconds


def run_scan_job(scan_id: str, request: ScanCreateRequest) -> None:
    """Run an orchestrator scan and persist sanitized results."""

    SCAN_STORE.mark_running(scan_id)
    SCAN_STORE.append_event(
        scan_id=scan_id,
        event_type="scan_started",
        data={"scan_id": scan_id, "app_category": request.app_category},
    )

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
            target_adapter=build_target_adapter(request),
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
        sanitized_error = sanitize_error(error)
        SCAN_STORE.append_event(
            scan_id=scan_id,
            event_type="scan_failed",
            data={"error": sanitized_error},
            level="error",
        )
        SCAN_STORE.fail_scan(scan_id=scan_id, error=sanitized_error)


def build_target_adapter(request: ScanCreateRequest) -> TargetAdapter:
    """Build the target adapter from request or deployment configuration."""

    target_url = request.target_url or os.getenv("REDSHIELD_TARGET_URL")
    if target_url:
        return HttpTargetAdapter(
            endpoint_url=target_url,
            timeout_seconds=get_target_timeout_seconds(),
            headers=target_headers_from_env(),
        )

    target_module = os.getenv("REDSHIELD_TARGET_MODULE")
    if target_module:
        return ImportTargetAdapter(module_name=target_module)

    return MockTargetAdapter(default_response=request.mock_target_response)


def target_headers_from_env() -> dict[str, str]:
    """Return optional target auth headers from environment variables."""

    header_name = os.getenv("REDSHIELD_TARGET_AUTH_HEADER")
    header_value = os.getenv("REDSHIELD_TARGET_AUTH_TOKEN")
    if not header_name or not header_value:
        return {}
    return {header_name: header_value}


def sanitize_error(error: Exception) -> str:
    """Return an error safe for API responses."""

    return f"Scan failed: {error.__class__.__name__}"


def scan_settings(request: ScanCreateRequest) -> dict:
    """Return non-sensitive scan settings safe for persistence."""

    return {
        "attacks_per_category": request.attacks_per_category,
        "success_threshold": request.success_threshold,
        "max_rounds": request.max_rounds,
        "target_configured": bool(request.target_url or os.getenv("REDSHIELD_TARGET_URL")),
        "normal_use_cases_count": len(request.normal_use_cases),
        "restricted_behaviors_count": len(request.restricted_behaviors),
        "competitors_count": len(request.competitors),
    }
