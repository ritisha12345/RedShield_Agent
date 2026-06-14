"""Background scan tasks."""

from __future__ import annotations

from tasks.celery_app import celery_app


@celery_app.task(name="redshield.run_scan")
def run_scan_task(scan_id: str, request_payload: dict) -> None:
    """Run one RedShield scan in a Celery worker."""

    from api.routes import ScanCreateRequest, _run_scan_job

    request = ScanCreateRequest.model_validate(request_payload)
    _run_scan_job(scan_id, request)
