"""Patch verification for previously successful RedShield attacks."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from agent.judge import judge_response
from models import (
    Attack,
    JudgeResult,
    PromptPatch,
    TargetResponse,
    VerificationEvidence,
    VerificationMetrics,
    VerificationResult,
)
from target import TargetAdapter


ResponseJudge = Callable[..., JudgeResult]


def verify_patch(
    *,
    successful_attacks: Iterable[Attack],
    patch: PromptPatch,
    target_adapter: TargetAdapter,
    patched_system_prompt: str | None = None,
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
    evidence: list[VerificationEvidence] = []

    for attack in attacks_to_retest:
        target_response = _execute_with_patch(
            target_adapter=target_adapter,
            attack=attack,
            patch=patch,
            patched_system_prompt=patched_system_prompt,
        )

        if target_response.error:
            error_attack_ids.append(attack.attack_id)
            evidence.append(
                _build_evidence(
                    attack=attack,
                    patched_verdict="error",
                    patched_severity=None,
                    mitigated=False,
                    reason=target_response.error,
                    target_response=target_response,
                    patched_prompt_provided=patched_system_prompt is not None,
                )
            )
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

        evidence.append(
            _build_evidence(
                attack=attack,
                patched_verdict=judge_result.verdict,
                patched_severity=judge_result.severity,
                mitigated=judge_result.verdict == "safe",
                reason=judge_result.reason,
                target_response=target_response,
                patched_prompt_provided=patched_system_prompt is not None,
            )
        )

    retested_attack_ids = [attack.attack_id for attack in attacks_to_retest]
    before_violation_rate = 1.0 if retested_attack_ids else 0.0
    unresolved = len(remaining_attack_ids) + len(error_attack_ids)
    after_violation_rate = (
        unresolved / len(retested_attack_ids)
        if retested_attack_ids
        else 0.0
    )
    improvement = before_violation_rate - after_violation_rate
    vulnerabilities_mitigated = (
        [patch.category] if retested_attack_ids and unresolved == 0 else []
    )
    vulnerabilities_remaining = [patch.category] if unresolved else []
    metrics = VerificationMetrics(
        total_retested=len(retested_attack_ids),
        baseline_violations=len(retested_attack_ids),
        patched_violations=unresolved,
        mitigated_count=len(mitigated_attack_ids),
        remaining_count=len(remaining_attack_ids),
        error_count=len(error_attack_ids),
        before_violation_rate=before_violation_rate,
        after_violation_rate=after_violation_rate,
        violation_rate_reduction=improvement,
        vulnerabilities_mitigated=vulnerabilities_mitigated,
        vulnerabilities_remaining=vulnerabilities_remaining,
    )

    return VerificationResult(
        patch_id=patch.patch_id,
        category=patch.category,
        retested_attack_ids=retested_attack_ids,
        passed_attack_ids=mitigated_attack_ids,
        failed_attack_ids=remaining_attack_ids,
        mitigated_attack_ids=mitigated_attack_ids,
        remaining_attack_ids=remaining_attack_ids,
        error_attack_ids=error_attack_ids,
        errors=len(error_attack_ids),
        before_violation_rate=before_violation_rate,
        after_violation_rate=after_violation_rate,
        improvement=improvement,
        violation_rate_reduction=improvement,
        vulnerabilities_mitigated=vulnerabilities_mitigated,
        vulnerabilities_remaining=vulnerabilities_remaining,
        evidence=evidence,
        metrics=metrics,
        mitigated=bool(retested_attack_ids) and unresolved == 0,
    )


def _execute_with_patch(
    *,
    target_adapter: TargetAdapter,
    attack: Attack,
    patch: PromptPatch,
    patched_system_prompt: str | None,
) -> TargetResponse:
    """Execute an attack through the adapter's patch-aware path."""

    execute_with_patch = getattr(target_adapter, "execute_with_patch", None)
    if execute_with_patch is None:
        return TargetResponse(
            attack_id=attack.attack_id,
            error="Target adapter does not support patched execution.",
        )

    try:
        return execute_with_patch(
            attack,
            patch,
            patched_system_prompt=patched_system_prompt,
        )
    except TypeError:
        try:
            return execute_with_patch(attack, patch)
        except Exception as error:
            return TargetResponse(
                attack_id=attack.attack_id,
                error=f"Patched target adapter failed: {error}",
            )
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


def _build_evidence(
    *,
    attack: Attack,
    patched_verdict: str,
    patched_severity: str | None,
    mitigated: bool,
    reason: str,
    target_response: TargetResponse,
    patched_prompt_provided: bool,
) -> VerificationEvidence:
    """Build evidence for one baseline-to-patched comparison."""

    return VerificationEvidence(
        attack_id=attack.attack_id,
        category=attack.category,
        baseline_verdict="violation",
        patched_verdict=patched_verdict,
        patched_severity=patched_severity,
        mitigated=mitigated,
        reason=reason,
        patched_response_excerpt=_response_excerpt(target_response.response_text),
        patched_prompt_provided=patched_prompt_provided,
    )


def _response_excerpt(response_text: str, max_length: int = 240) -> str | None:
    """Return a compact response excerpt for verification evidence."""

    text = " ".join(response_text.split())
    if not text:
        return None
    if len(text) <= max_length:
        return text
    return f"{text[: max_length - 3].rstrip()}..."
