"""Shared test helpers for formatter tests."""

from __future__ import annotations

from skill_scan.models import Finding, PackageRiskSummary, Severity


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


def make_package_risk(
    score: int = 12,
    band: str = "guarded",
    top_drivers: tuple[str, ...] = ("operator-manipulation", "remote-bootstrap"),
    counts_by_role: dict[str, int] | None = None,
    suspicious_url_count: int = 1,
    correlated_signal_count: int = 1,
) -> PackageRiskSummary:
    """Create a PackageRiskSummary with sensible defaults for testing."""
    return PackageRiskSummary(
        score=score,
        band=band,
        top_drivers=top_drivers,
        counts_by_role=counts_by_role or {"entrypoint": 1, "script": 1},
        suspicious_url_count=suspicious_url_count,
        correlated_signal_count=correlated_signal_count,
    )
