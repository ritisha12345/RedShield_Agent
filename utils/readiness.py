"""Deployment readiness checks for RedShield."""

from __future__ import annotations

import os
from typing import Any

from firebase.firestore import firestore_readiness_from_env
from utils.settings import (
    get_celery_broker_url,
    get_celery_result_backend,
    get_cors_allowed_origins,
    get_scan_execution_mode,
)


LOCAL_ORIGIN_MARKERS = ("localhost", "127.0.0.1")


def deployment_readiness() -> dict[str, Any]:
    """Return sanitized deployment readiness details."""

    execution_mode = _execution_mode_status()
    openai = _openai_status()
    cors = _cors_status()
    queue = _queue_status(execution_mode["mode"])
    firestore = firestore_readiness_from_env()

    checks = {
        "execution_mode": execution_mode,
        "openai": openai,
        "cors": cors,
        "queue": queue,
        "firestore": firestore,
    }
    blocking = _blocking_issues(checks)
    return {
        "status": "ok" if not blocking else "degraded",
        "checks": checks,
        "blocking_issues": blocking,
    }


def _execution_mode_status() -> dict[str, str | bool]:
    """Return configured scan execution mode readiness."""

    try:
        mode = get_scan_execution_mode()
    except ValueError:
        return {
            "status": "misconfigured",
            "mode": "invalid",
            "production_ready": False,
        }
    return {
        "status": "ok",
        "mode": mode,
        "production_ready": mode == "celery",
    }


def _openai_status() -> dict[str, str | bool]:
    """Return sanitized OpenAI configuration readiness."""

    has_key = bool(os.getenv("OPENAI_API_KEY"))
    return {
        "status": "ok" if has_key else "missing",
        "api_key_configured": has_key,
        "attacker_model": _configured_or_default("ATTACKER_MODEL", "gpt-4o"),
        "judge_model": _configured_or_default("JUDGE_MODEL", "gpt-4o"),
        "patcher_model": _configured_or_default("PATCHER_MODEL", "gpt-4o"),
    }


def _cors_status() -> dict[str, Any]:
    """Return CORS readiness without exposing secrets."""

    origins = get_cors_allowed_origins()
    local_only = all(
        any(marker in origin for marker in LOCAL_ORIGIN_MARKERS)
        for origin in origins
    )
    return {
        "status": "local_only" if local_only else "ok",
        "allowed_origins": origins,
        "production_ready": not local_only,
    }


def _queue_status(mode: str) -> dict[str, str | bool]:
    """Return Redis/Celery readiness."""

    if mode != "celery":
        return {
            "status": "disabled",
            "required": False,
            "production_ready": False,
        }

    broker_url = get_celery_broker_url()
    result_backend = get_celery_result_backend()
    ping = _redis_ping(broker_url)
    return {
        "status": "ok" if ping else "unavailable",
        "required": True,
        "broker_configured": bool(broker_url),
        "result_backend_configured": bool(result_backend),
        "reachable": ping,
        "production_ready": ping,
    }


def _redis_ping(url: str) -> bool:
    """Return whether Redis responds to a ping."""

    try:
        import redis
    except ModuleNotFoundError:
        return False

    try:
        client = redis.Redis.from_url(url, socket_connect_timeout=2, socket_timeout=2)
        return bool(client.ping())
    except Exception:
        return False


def _blocking_issues(checks: dict[str, Any]) -> list[str]:
    """Return deployment blockers from sanitized check results."""

    issues: list[str] = []
    if checks["execution_mode"]["mode"] != "celery":
        issues.append("REDSHIELD_SCAN_EXECUTION_MODE must be celery in production.")
    if checks["openai"]["status"] != "ok":
        issues.append("OPENAI_API_KEY is required.")
    if not checks["cors"]["production_ready"]:
        issues.append("CORS_ALLOWED_ORIGINS must include the production frontend origin.")
    if checks["queue"]["status"] != "ok":
        issues.append("Redis/Celery broker must be configured and reachable.")
    if checks["firestore"]["status"] != "ok":
        issues.append("Firestore must be enabled and available for celery mode.")
    return issues


def _configured_or_default(name: str, default: str) -> str:
    """Return an environment value or its configured default label."""

    return os.getenv(name) or default
