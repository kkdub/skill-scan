"""Verdict calculation logic — pure functions, no I/O.

Determines scan verdict and severity counts from findings.
"""

from __future__ import annotations

from skill_scan.models import Finding, Severity, Verdict

_BLOCK_SEVERITIES = frozenset({Severity.HIGH, Severity.CRITICAL})
_FLAG_SEVERITIES = frozenset({Severity.LOW, Severity.MEDIUM})


def calculate_verdict(findings: tuple[Finding, ...]) -> Verdict:
    """Determine the overall scan verdict from findings.

    Rules:
        - No findings or only INFO findings -> PASS
        - Only LOW/MEDIUM findings (no HIGH/CRITICAL) -> FLAG
        - Any HIGH or CRITICAL -> BLOCK
    """
    severities = {f.severity for f in findings}

    if severities & _BLOCK_SEVERITIES:
        return Verdict.BLOCK

    if severities & _FLAG_SEVERITIES:
        return Verdict.FLAG

    return Verdict.PASS


def count_by_severity(findings: tuple[Finding, ...]) -> dict[str, int]:
    """Count findings grouped by severity value string.

    Returns a dict keyed by the severity's string value (e.g. "critical", "high").
    Only severities with at least one finding are included.
    """
    counts: dict[str, int] = {}
    for finding in findings:
        key = finding.severity.value
        counts[key] = counts.get(key, 0) + 1
    return counts
