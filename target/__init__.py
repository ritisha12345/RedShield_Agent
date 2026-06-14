"""Target adapter abstractions for external applications."""

from target.adapter import (
    HttpTargetAdapter,
    ImportTargetAdapter,
    MockTargetAdapter,
    PatchableTargetAdapter,
    TargetAdapter,
)

__all__ = [
    "HttpTargetAdapter",
    "ImportTargetAdapter",
    "MockTargetAdapter",
    "PatchableTargetAdapter",
    "TargetAdapter",
]
