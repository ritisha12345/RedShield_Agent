"""Celery application configuration for RedShield workers."""

from __future__ import annotations

from celery import Celery

from utils.settings import (
    get_celery_broker_url,
    get_celery_result_backend,
    load_dotenv_if_available,
)


load_dotenv_if_available()

celery_app = Celery(
    "redshield",
    broker=get_celery_broker_url(),
    backend=get_celery_result_backend(),
)
celery_app.conf.update(
    accept_content=["json"],
    result_serializer="json",
    task_serializer="json",
    task_track_started=True,
    worker_prefetch_multiplier=1,
)
