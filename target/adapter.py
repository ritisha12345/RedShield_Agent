"""Target adapter boundary for external applications.

RedShield does not implement target applications. It calls target applications
through this adapter interface so the agent loop stays independent from target
transport, framework, hosting, and request/response details.
"""

from collections.abc import Mapping
from importlib import import_module
from typing import Protocol

from models import Attack, PromptPatch, TargetResponse
from utils.retry import retry_call


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
        *,
        patched_system_prompt: str | None = None,
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
        *,
        patched_system_prompt: str | None = None,
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


class ImportTargetAdapter:
    """Adapter for Python targets exposing a chat function."""

    def __init__(
        self,
        *,
        module_name: str,
        chat_function_name: str = "chat",
    ) -> None:
        """Initialize an import-based target adapter."""

        module = import_module(module_name)
        chat_function = getattr(module, chat_function_name, None)
        if chat_function is None:
            raise ValueError(f"{module_name}.{chat_function_name} is not available.")
        self._chat_function = chat_function

    def execute(self, attack: Attack) -> TargetResponse:
        """Send one attack to the imported target chat function."""

        try:
            response_text = retry_call(lambda: self._chat_function(attack.prompt))
        except Exception as error:
            return TargetResponse(
                attack_id=attack.attack_id,
                error=f"Import target failed: {error.__class__.__name__}",
            )
        return TargetResponse(attack_id=attack.attack_id, response_text=response_text)

    def execute_with_patch(
        self,
        attack: Attack,
        patch: PromptPatch,
        *,
        patched_system_prompt: str | None = None,
    ) -> TargetResponse:
        """Send one attack with a full patched system prompt."""

        try:
            response_text = retry_call(
                lambda: self._chat_function(
                    attack.prompt,
                    system_prompt=patched_system_prompt or patch.patch_text,
                )
            )
        except Exception as error:
            return TargetResponse(
                attack_id=attack.attack_id,
                error=f"Patched import target failed: {error.__class__.__name__}",
            )
        return TargetResponse(attack_id=attack.attack_id, response_text=response_text)


class HttpTargetAdapter:
    """HTTP adapter for calling a deployed target application."""

    def __init__(
        self,
        *,
        endpoint_url: str,
        timeout_seconds: float = 30.0,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        """Initialize an HTTP target adapter."""

        if not endpoint_url.strip():
            raise ValueError("endpoint_url cannot be empty.")
        self.endpoint_url = endpoint_url
        self.timeout_seconds = timeout_seconds
        self.headers = dict(headers or {})

    def execute(self, attack: Attack) -> TargetResponse:
        """Send one attack to the configured target endpoint."""

        return self._post_attack(attack=attack)

    def execute_with_patch(
        self,
        attack: Attack,
        patch: PromptPatch,
        *,
        patched_system_prompt: str | None = None,
    ) -> TargetResponse:
        """Send one attack with a proposed system-prompt patch."""

        return self._post_attack(
            attack=attack,
            patch=patch,
            patched_system_prompt=patched_system_prompt,
        )

    def _post_attack(
        self,
        *,
        attack: Attack,
        patch: PromptPatch | None = None,
        patched_system_prompt: str | None = None,
    ) -> TargetResponse:
        """POST one attack to the target endpoint and normalize the response."""

        try:
            response_text = retry_call(
                lambda: self._send_request(attack, patch, patched_system_prompt)
            )
        except Exception as error:
            return TargetResponse(
                attack_id=attack.attack_id,
                error=f"HTTP target failed: {error.__class__.__name__}",
            )

        return TargetResponse(
            attack_id=attack.attack_id,
            response_text=response_text,
        )

    def _send_request(
        self,
        attack: Attack,
        patch: PromptPatch | None,
        patched_system_prompt: str | None,
    ) -> str:
        """Execute the HTTP request for one target attack."""

        import httpx

        payload = {
            "attack_id": attack.attack_id,
            "message": attack.prompt,
            "category": attack.category,
        }
        if patch is not None:
            payload["system_prompt_patch"] = patch.patch_text
            payload["patch_id"] = patch.patch_id
        if patched_system_prompt is not None:
            payload["system_prompt"] = patched_system_prompt

        response = httpx.post(
            self.endpoint_url,
            json=payload,
            headers=self.headers,
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        return _extract_response_text(response)


def _extract_response_text(response: object) -> str:
    """Extract target response text from JSON or plain text responses."""

    try:
        data = response.json()
    except ValueError:
        data = None

    if isinstance(data, dict):
        for key in ("response_text", "response", "message", "text"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value

    text = getattr(response, "text", "")
    if isinstance(text, str) and text.strip():
        return text
    raise ValueError("Target response did not include response text.")
