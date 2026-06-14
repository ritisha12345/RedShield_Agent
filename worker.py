"""Celery worker entrypoint for RedShield."""

from tasks.celery_app import celery_app

# Import task modules so Celery registers them when loading ``-A worker``.
import tasks.scans  # noqa: F401


app = celery_app
celery = celery_app

__all__ = ["app", "celery", "celery_app"]
