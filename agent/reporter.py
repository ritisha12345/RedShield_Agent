"""Markdown reporting for RedShield scan summaries."""

from collections.abc import Iterable
from datetime import UTC, datetime

from models import PromptPatch, SafetySummary, VerificationResult, VulnerabilityFinding


def generate_markdown_report(
    *,
    summary: SafetySummary,
    findings: Iterable[VulnerabilityFinding],
    patches: Iterable[PromptPatch] | None = None,
    verification_results: Iterable[VerificationResult] | None = None,
    generated_at: datetime | None = None,
) -> str:
    """Generate a terminal-friendly markdown safety report."""

    ordered_findings = list(findings)
    ordered_patches = list(patches or [])
    ordered_verification = list(verification_results or [])
    generated_time = generated_at or datetime.now(UTC)
    before_patch_rate = (
        summary.initial_violation_rate
        if summary.initial_violation_rate is not None
        else summary.violation_rate
    )
    after_patch_rate = (
        summary.final_violation_rate
        if summary.final_violation_rate is not None
        else _after_patch_violation_rate(
            summary=summary,
            verification_results=ordered_verification,
        )
    )
    risky_findings = [
        finding for finding in ordered_findings if finding.violations > 0
    ]
    highest_risk_findings = sorted(
        risky_findings,
        key=lambda finding: (
            finding.violations,
            finding.violation_rate,
            finding.category,
        ),
        reverse=True,
    )
    mitigated_categories = sorted(
        {result.category for result in ordered_verification if result.mitigated}
    )
    remaining_risks = _remaining_risks_for_report(
        summary=summary,
        risky_findings=risky_findings,
        verification_results=ordered_verification,
    )
    baseline_violations = _baseline_violation_count(summary, before_patch_rate)
    verification_errors = sum(result.errors for result in ordered_verification)
    baseline_errors = max(summary.errors - verification_errors, 0)
    baseline_safe = _baseline_safe_count(
        summary=summary,
        baseline_violations=baseline_violations,
        baseline_errors=baseline_errors,
    )
    rate_delta = before_patch_rate - after_patch_rate
    final_status = _status_label(after_patch_rate, remaining_risks)
    mitigation_label = _mitigation_label(
        before_patch_rate=before_patch_rate,
        after_patch_rate=after_patch_rate,
    )
    effectiveness_counts = _patch_effectiveness_counts(summary.evidence_records)
    effective_retests = effectiveness_counts.get("mitigated", 0)
    ineffective_retests = sum(
        count for status, count in effectiveness_counts.items() if status != "mitigated"
    )

    lines = [
        "# RedShield Safety Report",
        "",
        "## Demo Snapshot",
        "",
        f"- Status: {final_status}",
        f"- Result: {mitigation_label}",
        f"- Violation rate: {before_patch_rate:.1%} -> {after_patch_rate:.1%}",
        f"- Patches applied: {len(ordered_patches)}",
        f"- Remaining risks: {len(remaining_risks)}",
        f"- Effective retests: {effective_retests}",
        f"- Ineffective retests: {ineffective_retests}",
        "",
        "## Report Metadata",
        "",
        f"- Generated at: {generated_time.isoformat()}",
        "- Runtime: terminal",
        "- Scope: autonomous attack, judge, analyze, patch, verify loop",
        "",
        "## Executive Summary",
        "",
        _executive_summary(
            status=final_status,
            total_attacks=summary.total_attacks,
            completed_attacks=summary.completed_attacks,
            baseline_violations=baseline_violations,
            final_violations=summary.violations,
            before_patch_rate=before_patch_rate,
            after_patch_rate=after_patch_rate,
            patches_applied=len(ordered_patches),
            remaining_risks=remaining_risks,
        ),
        "",
        "- Key numbers:",
        f"- Initial violation rate: {before_patch_rate:.1%}",
        f"- Final violation rate: {after_patch_rate:.1%}",
        f"- Violation rate reduction: {rate_delta:.1%}",
        f"- Vulnerabilities mitigated: {_format_categories(mitigated_categories)}",
        f"- Vulnerabilities remaining: {_format_categories(remaining_risks)}",
        "",
        "## Before vs After",
        "",
        "| Metric | Before patching | After patching | Change |",
        "| --- | ---: | ---: | ---: |",
        f"| Violation rate | {before_patch_rate:.1%} | {after_patch_rate:.1%} | {_format_rate_change(rate_delta)} |",
        f"| Violations | {baseline_violations} | {summary.violations} | {_format_count_change(summary.violations - baseline_violations)} |",
        f"| Safe responses | {baseline_safe} | {summary.safe} | {_format_count_change(summary.safe - baseline_safe)} |",
        f"| Errors | {baseline_errors} | {summary.errors} | {_format_count_change(summary.errors - baseline_errors)} |",
        "",
        "## Vulnerability Counts",
        "",
        "| Count | Value |",
        "| --- | ---: |",
        f"| Vulnerability categories tested | {len(ordered_findings)} |",
        f"| Categories with baseline violations | {len(risky_findings)} |",
        f"| Baseline violations | {baseline_violations} |",
        f"| Final unresolved violations | {summary.violations} |",
        f"| Categories mitigated | {len(mitigated_categories)} |",
        f"| Remaining risk items | {len(remaining_risks)} |",
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Total attacks | {summary.total_attacks} |",
        f"| Completed attacks | {summary.completed_attacks} |",
        f"| Baseline violations | {baseline_violations} |",
        f"| Final unresolved violations | {summary.violations} |",
        f"| Safe responses | {summary.safe} |",
        f"| Inconclusive results | {summary.inconclusive} |",
        f"| Errors | {summary.errors} |",
        f"| Initial violation rate | {before_patch_rate:.1%} |",
        f"| Final violation rate | {after_patch_rate:.1%} |",
        f"| Effective retests | {effective_retests} |",
        f"| Ineffective retests | {ineffective_retests} |",
        "",
        "## Category Breakdown",
        "",
        "| Category | Total | Violations | Safe | Inconclusive | Errors | Violation Rate | Dominant |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]

    for finding in ordered_findings:
        dominant = "yes" if finding.dominant else "no"
        lines.append(
            "| "
            f"{finding.category} | "
            f"{finding.total} | "
            f"{finding.violations} | "
            f"{finding.safe} | "
            f"{finding.inconclusive} | "
            f"{finding.errors} | "
            f"{finding.violation_rate:.1%} | "
            f"{dominant} |"
        )

    lines.extend(["", "## Highest-Risk Findings", ""])
    if not highest_risk_findings:
        lines.append("No violation-producing categories were detected.")
    else:
        for finding in highest_risk_findings:
            lines.extend(
                [
                    f"### {finding.category}",
                    "",
                    (
                        f"- Violation rate: {finding.violation_rate:.1%} "
                        f"({finding.violations}/{finding.total})"
                    ),
                    f"- Dominant category: {'yes' if finding.dominant else 'no'}",
                ]
            )
            if finding.representative_examples:
                lines.append("- Representative examples:")
                for example in finding.representative_examples:
                    lines.append(f"  - {example}")
            else:
                lines.append("- Representative examples: none captured")
            lines.append("")

    lines.extend(["", "## Evidence Records", ""])
    if not summary.evidence_records:
        lines.append("No attack evidence records were captured.")
    else:
        for evidence in summary.evidence_records:
            lines.extend(
                [
                    f"### {evidence.attack_id} ({evidence.category})",
                    "",
                    f"- Verdict: {evidence.verdict}",
                    f"- Confidence: {evidence.confidence:.2f}",
                ]
            )
            if evidence.severity:
                lines.append(f"- Severity: {evidence.severity}")
            if evidence.violated_rule:
                lines.append(f"- Violated rule: {evidence.violated_rule}")
            lines.extend(
                [
                    f"- Judge reason: {evidence.judge_reason}",
                    "- Attack prompt:",
                    "```text",
                    evidence.attack_prompt,
                    "```",
                    "- Target response excerpt:",
                    "```text",
                    evidence.target_response_excerpt or "No response text captured.",
                    "```",
                ]
            )
            if evidence.patch_id:
                lines.extend(
                    [
                        f"- Verification patch: {evidence.patch_id}",
                        f"- Patched prompt passed: {_format_optional_bool(evidence.patched_prompt_provided)}",
                        f"- Verification verdict: {evidence.verification_verdict}",
                        f"- Response changed after patch: {_format_optional_bool(evidence.verification_response_changed)}",
                        f"- Patch effectiveness: {evidence.patch_effectiveness_status or 'n/a'}",
                        f"- Failure reason: {evidence.patch_failure_reason or 'none'}",
                        f"- Severity change: {evidence.severity_changed or 'n/a'}",
                        f"- Mitigated: {'yes' if evidence.mitigated else 'no'}",
                        f"- Verification reason: {evidence.verification_reason or 'none'}",
                    ]
                )
                if evidence.verification_response_excerpt:
                    lines.extend(
                        [
                            "- Verification response excerpt:",
                            "```text",
                            evidence.verification_response_excerpt,
                            "```",
                        ]
                    )
            lines.append("")

    lines.extend(["", "## Patches Applied", ""])
    if not ordered_patches:
        lines.append("No prompt patches were proposed.")
    else:
        for patch in ordered_patches:
            lines.extend(
                [
                    f"### {patch.patch_id}",
                    "",
                    f"- Category: {patch.category}",
                    f"- Round: {patch.round_index}",
                    f"- Target vulnerability: {patch.target_vulnerability}",
                    f"- Source violation rate: {patch.source_violation_rate:.1%}",
                    f"- Rationale: {patch.rationale}",
                    "- Patch:",
                    "```text",
                    patch.patch_text,
                    "```",
                ]
            )

    lines.extend(["", "## Verification", ""])
    if not ordered_verification:
        lines.append("No patch verification was run.")
    else:
        lines.extend(
            [
                f"- Vulnerabilities mitigated: {_format_categories(mitigated_categories)}",
                f"- Vulnerabilities remaining: {_format_categories(remaining_risks)}",
                "",
                "### Patch Effectiveness",
                "",
                "| Status | Count |",
                "| --- | ---: |",
            ]
        )
        for status, count in sorted(effectiveness_counts.items()):
            lines.append(f"| {_humanize_status(status)} | {count} |")
        lines.extend(
            [
                "",
                "| Patch | Category | Retested | Mitigated | Remaining | Errors | Improvement |",
                "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for result in ordered_verification:
            lines.append(
                "| "
                f"{result.patch_id} | "
                f"{result.category} | "
                f"{len(result.retested_attack_ids)} | "
                f"{len(result.mitigated_attack_ids)} | "
                f"{len(result.remaining_attack_ids)} | "
                f"{result.errors} | "
                f"{result.violation_rate_reduction:.1%} |"
            )
        lines.extend(["", "### Verification Evidence", ""])
        for result in ordered_verification:
            if not result.evidence:
                lines.append(f"- {result.patch_id}: no evidence captured.")
                continue
            for evidence in result.evidence:
                outcome = "mitigated" if evidence.mitigated else "unresolved"
                lines.append(
                    f"- {evidence.attack_id}: baseline violation -> "
                    f"patched {evidence.patched_verdict} ({outcome}). "
                    f"Evidence: {evidence.reason}"
                )
                if evidence.patched_response_excerpt:
                    lines.append(
                        f"  Patched response excerpt: {evidence.patched_response_excerpt}"
                    )

    lines.extend(["", "## Remaining Risks", ""])
    if not remaining_risks:
        lines.append("No remaining risks were identified by verification.")
    else:
        for risk in remaining_risks:
            lines.append(f"- {risk}")

    lines.extend(
        [
            "",
            "## Structured Summary",
            "",
            "```text",
            f"initial_violation_rate={before_patch_rate:.6f}",
            f"final_violation_rate={after_patch_rate:.6f}",
            f"violation_rate_reduction={rate_delta:.6f}",
            f"baseline_violations={baseline_violations}",
            f"final_unresolved_violations={summary.violations}",
            f"patches_applied={len(ordered_patches)}",
            f"verification_results={len(ordered_verification)}",
            f"evidence_records={len(summary.evidence_records)}",
            f"effective_retests={effective_retests}",
            f"ineffective_retests={ineffective_retests}",
            f"remaining_risks={len(remaining_risks)}",
            "```",
        ]
    )

    return "\n".join(lines).rstrip() + "\n"


def _executive_summary(
    *,
    status: str,
    total_attacks: int,
    completed_attacks: int,
    baseline_violations: int,
    final_violations: int,
    before_patch_rate: float,
    after_patch_rate: float,
    patches_applied: int,
    remaining_risks: list[str],
) -> str:
    """Create a deterministic executive summary paragraph."""

    tested = (
        f"RedShield completed {completed_attacks} of {total_attacks} generated "
        "adversarial checks"
    )
    outcome = (
        f"and reduced the violation rate from {before_patch_rate:.1%} to "
        f"{after_patch_rate:.1%}."
    )
    counts = (
        f"Baseline violations moved from {baseline_violations} to "
        f"{final_violations} unresolved violation(s) after applying "
        f"{patches_applied} patch(es)."
    )
    risk = (
        f"The scan finished with status `{status}` and "
        f"{len(remaining_risks)} remaining risk item(s)."
    )
    return f"{tested} {outcome} {counts} {risk}"


def _after_patch_violation_rate(
    *,
    summary: SafetySummary,
    verification_results: list[VerificationResult],
) -> float:
    """Estimate remaining overall violation rate after verification."""

    if not verification_results or summary.completed_attacks == 0:
        return summary.violation_rate

    retested = sum(len(result.retested_attack_ids) for result in verification_results)
    unresolved = sum(
        len(result.remaining_attack_ids) + len(result.error_attack_ids)
        for result in verification_results
    )
    unretested_baseline_violations = max(summary.violations - retested, 0)
    return (unresolved + unretested_baseline_violations) / summary.completed_attacks


def _mitigation_label(*, before_patch_rate: float, after_patch_rate: float) -> str:
    """Return a demo-friendly before/after outcome label."""

    if before_patch_rate == 0 and after_patch_rate == 0:
        return "No violations detected"
    if after_patch_rate == 0:
        return "All detected violations mitigated"
    if after_patch_rate < before_patch_rate:
        return "Risk reduced with remaining exposure"
    if after_patch_rate == before_patch_rate:
        return "No measured risk reduction"
    return "Risk increased during verification"


def _format_rate_change(delta: float) -> str:
    """Format a before/after rate delta for markdown tables."""

    if delta > 0:
        return f"-{delta:.1%}"
    if delta < 0:
        return f"+{abs(delta):.1%}"
    return "0.0%"


def _format_count_change(delta: int) -> str:
    """Format a before/after count delta for markdown tables."""

    if delta > 0:
        return f"+{delta}"
    if delta < 0:
        return str(delta)
    return "0"


def _baseline_safe_count(
    *,
    summary: SafetySummary,
    baseline_violations: int,
    baseline_errors: int,
) -> int:
    """Estimate baseline safe count from completed attacks and baseline outcomes."""

    return max(
        summary.completed_attacks
        - baseline_violations
        - summary.inconclusive
        - baseline_errors,
        0,
    )


def _format_categories(categories: list[str]) -> str:
    """Format a category list for terminal markdown."""

    return ", ".join(categories) if categories else "none"


def _format_optional_bool(value: bool | None) -> str:
    """Format optional diagnostic booleans for reports."""

    if value is None:
        return "n/a"
    return "yes" if value else "no"


def _patch_effectiveness_counts(evidence_records: list) -> dict[str, int]:
    """Count patch verification diagnoses captured on evidence records."""

    counts: dict[str, int] = {}
    for evidence in evidence_records:
        if not evidence.patch_id or not evidence.patch_effectiveness_status:
            continue
        counts[evidence.patch_effectiveness_status] = (
            counts.get(evidence.patch_effectiveness_status, 0) + 1
        )
    return counts


def _humanize_status(status: str) -> str:
    """Format a compact status label for report tables."""

    return status.replace("_", " ")


def _remaining_categories(
    verification_results: list[VerificationResult],
) -> list[str]:
    """Return categories with unresolved verification outcomes."""

    return [
        result.category
        for result in verification_results
        if result.remaining_attack_ids or result.error_attack_ids
    ]


def _remaining_risks_for_report(
    *,
    summary: SafetySummary,
    risky_findings: list[VulnerabilityFinding],
    verification_results: list[VerificationResult],
) -> list[str]:
    """Return final or inferred remaining risks for report display."""

    if summary.initial_violation_rate is not None:
        return summary.remaining_risks
    if verification_results:
        return _remaining_categories(verification_results)
    return [finding.category for finding in risky_findings]


def _baseline_violation_count(
    summary: SafetySummary,
    before_patch_rate: float,
) -> int:
    """Estimate baseline violation count for structured display."""

    return round(before_patch_rate * summary.completed_attacks)


def _status_label(
    final_violation_rate: float,
    remaining_risks: list[str],
) -> str:
    """Return a concise report status label."""

    if final_violation_rate == 0 and not remaining_risks:
        return "mitigated"
    if remaining_risks:
        return "completed_with_remaining_risk"
    return "completed"
