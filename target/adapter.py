"""Target adapter boundary for external applications.

RedShield does not implement target applications. It calls target applications
through this adapter interface so the agent loop stays independent from target
transport, framework, hosting, and request/response details.
"""

from collections.abc import Mapping
from typing import Protocol

from models import Attack, PromptPatch, TargetResponse


class TargetAdapter(Protocol):
    """Single interface RedShield uses to execute attacks against a target."""

    def execute(self, attack: Attack) -> TargetResponse:
        """Send one attack to the target application and return its response."""


class PatchableTargetAdapter(TargetAdapter, Protocol):
    """Optional target adapter capability for verification with a patch."""

    def execute_with_patch(
        self,
        attack: Attack,
        patch: PromptPatch,
    ) -> TargetResponse:
        """Send one attack to the target application with a proposed patch."""


class MockTargetAdapter:
    """Mock target adapter for developing RedShield without a real target app."""

    def __init__(
        self,
        default_response: str = "Mock target response: request handled safely.",
        responses_by_attack_id: Mapping[str, str] | None = None,
        patched_default_response: str = (
            "Mock patched target response: request refused safely."
        ),
        patched_responses_by_attack_id: Mapping[str, str] | None = None,
    ) -> None:
        """Initialize canned responses for local Phase 1 development."""

        self.default_response = default_response
        self.responses_by_attack_id = dict(responses_by_attack_id or {})
        self.patched_default_response = patched_default_response
        self.patched_responses_by_attack_id = dict(
            patched_responses_by_attack_id or {}
        )

    def execute(self, attack: Attack) -> TargetResponse:
        """Return a canned target response for the supplied attack."""

        response_text = self.responses_by_attack_id.get(
            attack.attack_id,
            self.default_response,
        )
        return TargetResponse(
            attack_id=attack.attack_id,
            response_text=response_text,
        )

    def execute_with_patch(
        self,
        attack: Attack,
        patch: PromptPatch,
    ) -> TargetResponse:
        """Return a canned patched response for the supplied attack."""

        response_text = self.patched_responses_by_attack_id.get(
            attack.attack_id,
            self.patched_default_response,
        )
        return TargetResponse(
            attack_id=attack.attack_id,
            response_text=response_text,
        )
