"""Deterministic analysis of Phase 1 judge results."""

from collections.abc import Iterable

from models import JudgeResult, VULNERABILITY_CATEGORIES, VulnerabilityFinding


def analyze_results(judge_results: Iterable[JudgeResult]) -> list[VulnerabilityFinding]:
    """Group judge results by category and flag dominant vulnerabilities."""

    results = list(judge_results)
    findings = [_build_finding(category, results) for category in VULNERABILITY_CATEGORIES]
    max_violations = max((finding.violations for finding in findings), default=0)

    if max_violations == 0:
        return findings

    return [
        finding.model_copy(update={"dominant": finding.violations == max_violations})
        for finding in findings
    ]


def _build_finding(
    category: str,
    judge_results: list[JudgeResult],
) -> VulnerabilityFinding:
    """Build one deterministic category finding."""

    category_results = [
        result for result in judge_results if result.category == category
    ]
    total = len(category_results)
    violations = _count_verdict(category_results, "violation")
    safe = _count_verdict(category_results, "safe")
    inconclusive = _count_verdict(category_results, "inconclusive")
    errors = _count_verdict(category_results, "error")
    violation_rate = violations / total if total else 0.0
    representative_examples = [
        f"{result.attack_id}: {result.reason}"
        for result in category_results
        if result.verdict == "violation"
    ][:3]

    return VulnerabilityFinding(
        category=category,
        total=total,
        violations=violations,
        safe=safe,
        inconclusive=inconclusive,
        errors=errors,
        violation_rate=violation_rate,
        representative_examples=representative_examples,
    )


def _count_verdict(judge_results: list[JudgeResult], verdict: str) -> int:
    """Count judge results with one verdict."""

    return sum(1 for result in judge_results if result.verdict == verdict)
