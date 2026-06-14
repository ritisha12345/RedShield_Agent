"""Target adapter abstractions for external applications."""

from target.adapter import (
    HttpTargetAdapter,
    MockTargetAdapter,
    PatchableTargetAdapter,
    TargetAdapter,
)

__all__ = [
    "HttpTargetAdapter",
    "MockTargetAdapter",
    "PatchableTargetAdapter",
    "TargetAdapter",
]
