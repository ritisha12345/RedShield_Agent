"""Environment configuration helpers for RedShield deployment."""

from __future__ import annotations

import os


TRUE_VALUES = {"1", "true", "yes", "on"}
LOCAL_CORS_ORIGINS = (
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
)
SCAN_EXECUTION_MODES = {"thread", "celery"}


def load_dotenv_if_available() -> None:
    """Load local ``.env`` values when python-dotenv is installed."""

    try:
        from dotenv import load_dotenv
    except ModuleNotFoundError:
        return

    load_dotenv()


def env_truthy(name: str, *, default: bool = False) -> bool:
    """Return whether an environment variable is set to a truthy value."""

    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in TRUE_VALUES


def env_list(name: str, *, default: tuple[str, ...] = ()) -> list[str]:
    """Parse a comma-separated environment variable into clean values."""

    raw_value = os.getenv(name, "")
    if not raw_value.strip():
        return list(default)
    return [item.strip().rstrip("/") for item in raw_value.split(",") if item.strip()]


def get_cors_allowed_origins() -> list[str]:
    """Return browser origins allowed to call the API."""

    origins = env_list("CORS_ALLOWED_ORIGINS")
    if origins:
        return origins

    return env_list(
        "REDSHIELD_CORS_ALLOWED_ORIGINS",
        default=LOCAL_CORS_ORIGINS,
    )


def get_scan_execution_mode() -> str:
    """Return the configured scan execution mode."""

    mode = os.getenv("REDSHIELD_SCAN_EXECUTION_MODE", "thread").strip().lower()
    if mode not in SCAN_EXECUTION_MODES:
        valid_modes = ", ".join(sorted(SCAN_EXECUTION_MODES))
        raise ValueError(
            "REDSHIELD_SCAN_EXECUTION_MODE must be one of: "
            f"{valid_modes}."
        )
    return mode


def get_redis_url() -> str:
    """Return the Redis URL used by Celery when no explicit broker is set."""

    return os.getenv("REDIS_URL", "redis://localhost:6379/0")


def get_celery_broker_url() -> str:
    """Return the Celery broker URL."""

    return os.getenv("CELERY_BROKER_URL") or get_redis_url()


def get_celery_result_backend() -> str:
    """Return the Celery result backend URL."""

    return os.getenv("CELERY_RESULT_BACKEND") or get_celery_broker_url()


def get_target_timeout_seconds() -> float:
    """Return the HTTP target adapter timeout."""

    raw_value = os.getenv("REDSHIELD_TARGET_TIMEOUT_SECONDS", "30")
    try:
        timeout = float(raw_value)
    except ValueError as error:
        raise ValueError("REDSHIELD_TARGET_TIMEOUT_SECONDS must be numeric.") from error

    if timeout <= 0:
        raise ValueError("REDSHIELD_TARGET_TIMEOUT_SECONDS must be positive.")
    return timeout
