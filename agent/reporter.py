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

    lines = [
        "# RedShield Safety Report",
        "",
        "## Report Metadata",
        "",
        f"- Generated at: {generated_time.isoformat()}",
        "- Runtime: terminal",
        "- Scope: autonomous attack, judge, analyze, patch, verify loop",
        "",
        "## Executive Summary",
        "",
        f"- Status: {_status_label(after_patch_rate, remaining_risks)}",
        f"- Initial violation rate: {before_patch_rate:.1%}",
        f"- Final violation rate: {after_patch_rate:.1%}",
        f"- Vulnerabilities mitigated: {_format_categories(mitigated_categories)}",
        f"- Vulnerabilities remaining: {_format_categories(remaining_risks)}",
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Total attacks | {summary.total_attacks} |",
        f"| Completed attacks | {summary.completed_attacks} |",
        f"| Baseline violations | {_baseline_violation_count(summary, before_patch_rate)} |",
        f"| Final unresolved violations | {summary.violations} |",
        f"| Safe responses | {summary.safe} |",
        f"| Inconclusive results | {summary.inconclusive} |",
        f"| Errors | {summary.errors} |",
        f"| Initial violation rate | {before_patch_rate:.1%} |",
        f"| Final violation rate | {after_patch_rate:.1%} |",
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

    lines.extend(["", "## Proposed Patches", ""])
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
                f"{result.improvement:.1%} |"
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
            f"patches_applied={len(ordered_patches)}",
            f"verification_results={len(ordered_verification)}",
            f"remaining_risks={len(remaining_risks)}",
            "```",
        ]
    )

    return "\n".join(lines).rstrip() + "\n"


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


def _format_categories(categories: list[str]) -> str:
    """Format a category list for terminal markdown."""

    return ", ".join(categories) if categories else "none"


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
