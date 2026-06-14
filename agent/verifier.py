"""Patch verification for previously successful RedShield attacks."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from agent.judge import judge_response
from models import Attack, JudgeResult, PromptPatch, TargetResponse, VerificationResult
from target import TargetAdapter


ResponseJudge = Callable[..., JudgeResult]


def verify_patch(
    *,
    successful_attacks: Iterable[Attack],
    patch: PromptPatch,
    target_adapter: TargetAdapter,
    response_judge: ResponseJudge = judge_response,
    judge_model: str | None = None,
    judge_client: Any | None = None,
) -> VerificationResult:
    """Re-run previously successful attacks for the patch category."""

    attacks_to_retest = [
        attack for attack in successful_attacks if attack.category == patch.category
    ]

    mitigated_attack_ids: list[str] = []
    remaining_attack_ids: list[str] = []
    error_attack_ids: list[str] = []

    for attack in attacks_to_retest:
        target_response = _execute_with_patch(
            target_adapter=target_adapter,
            attack=attack,
            patch=patch,
        )

        if target_response.error:
            error_attack_ids.append(attack.attack_id)
            continue

        judge_result = _judge_patched_response(
            response_judge=response_judge,
            attack=attack,
            target_response=target_response,
            judge_model=judge_model,
            judge_client=judge_client,
        )

        if judge_result.verdict == "violation":
            remaining_attack_ids.append(attack.attack_id)
        elif judge_result.verdict == "safe":
            mitigated_attack_ids.append(attack.attack_id)
        else:
            error_attack_ids.append(attack.attack_id)

    retested_attack_ids = [attack.attack_id for attack in attacks_to_retest]
    before_violation_rate = 1.0 if retested_attack_ids else 0.0
    unresolved = len(remaining_attack_ids) + len(error_attack_ids)
    after_violation_rate = (
        unresolved / len(retested_attack_ids)
        if retested_attack_ids
        else 0.0
    )
    improvement = before_violation_rate - after_violation_rate

    return VerificationResult(
        patch_id=patch.patch_id,
        category=patch.category,
        retested_attack_ids=retested_attack_ids,
        mitigated_attack_ids=mitigated_attack_ids,
        remaining_attack_ids=remaining_attack_ids,
        error_attack_ids=error_attack_ids,
        errors=len(error_attack_ids),
        before_violation_rate=before_violation_rate,
        after_violation_rate=after_violation_rate,
        improvement=improvement,
        mitigated=bool(retested_attack_ids) and unresolved == 0,
    )


def _execute_with_patch(
    *,
    target_adapter: TargetAdapter,
    attack: Attack,
    patch: PromptPatch,
) -> TargetResponse:
    """Execute an attack through the adapter's patch-aware path."""

    execute_with_patch = getattr(target_adapter, "execute_with_patch", None)
    if execute_with_patch is None:
        return TargetResponse(
            attack_id=attack.attack_id,
            error="Target adapter does not support patched execution.",
        )

    try:
        return execute_with_patch(attack, patch)
    except Exception as error:
        return TargetResponse(
            attack_id=attack.attack_id,
            error=f"Patched target adapter failed: {error}",
        )


def _judge_patched_response(
    *,
    response_judge: ResponseJudge,
    attack: Attack,
    target_response: TargetResponse,
    judge_model: str | None,
    judge_client: Any | None,
) -> JudgeResult:
    """Judge a patched target response, converting failures to error results."""

    try:
        return response_judge(
            attack=attack,
            target_response=target_response,
            model=judge_model,
            client=judge_client,
        )
    except Exception as error:
        return JudgeResult(
            attack_id=attack.attack_id,
            category=attack.category,
            verdict="error",
            severity=None,
            reason=f"Patched judge execution failed: {error}",
            confidence=0.0,
        )
