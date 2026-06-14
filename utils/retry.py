"""Small retry helper for RedShield LLM and adapter calls."""

from collections.abc import Callable
from time import sleep
from typing import TypeVar


T = TypeVar("T")


def retry_call(
    operation: Callable[[], T],
    *,
    attempts: int = 3,
    delay_seconds: float = 1.0,
) -> T:
    """Run an operation with basic retries and re-raise the final error."""

    if attempts < 1:
        raise ValueError("attempts must be at least 1")

    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            return operation()
        except Exception as error:  # pragma: no cover - re-raised on final try
            last_error = error
            if attempt == attempts - 1:
                break
            sleep(delay_seconds)

    if last_error is not None:
        raise last_error
    raise RuntimeError("retry_call failed without an exception")
