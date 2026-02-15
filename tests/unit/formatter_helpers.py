"""Shared test helpers for formatter tests."""

from __future__ import annotations

from skill_scan.models import Finding, Severity


def make_finding(
    rule_id: str = "TEST-001",
    severity: Severity = Severity.MEDIUM,
    category: str = "test-category",
    file: str = "test.md",
    line: int | None = 10,
    matched_text: str = "test match",
    description: str = "Test description",
    recommendation: str = "Test recommendation",
) -> Finding:
    """Create a Finding with sensible defaults for testing."""
    return Finding(
        rule_id=rule_id,
        severity=severity,
        category=category,
        file=file,
        line=line,
        matched_text=matched_text,
        description=description,
        recommendation=recommendation,
    )
