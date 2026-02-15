"""Unit tests for skill_scan.verdict calculation logic.

Tests for calculate_verdict and count_by_severity functions.
"""

from __future__ import annotations

import pytest

from skill_scan.models import Finding, Severity, Verdict
from skill_scan.verdict import calculate_verdict, count_by_severity


def make_finding(
    severity: Severity,
    rule_id: str = "TEST-001",
    category: str = "test",
    file: str = "test.txt",
) -> Finding:
    """Helper to create Finding instances for tests."""
    return Finding(
        rule_id=rule_id,
        severity=severity,
        category=category,
        file=file,
        line=1,
        matched_text="test",
        description="test finding",
        recommendation="test recommendation",
    )


class TestCalculateVerdict:
    """Tests for calculate_verdict function."""

    def test_calculate_verdict_returns_pass_for_empty_findings(self) -> None:
        verdict = calculate_verdict(())
        assert verdict == Verdict.PASS

    def test_calculate_verdict_returns_pass_for_info_only(self) -> None:
        findings = (
            make_finding(Severity.INFO, rule_id="INFO-001"),
            make_finding(Severity.INFO, rule_id="INFO-002"),
        )
        verdict = calculate_verdict(findings)
        assert verdict == Verdict.PASS

    @pytest.mark.parametrize(
        "severity",
        [Severity.LOW, Severity.MEDIUM],
    )
    def test_calculate_verdict_returns_flag_for_low_or_medium(self, severity: Severity) -> None:
        findings = (make_finding(severity),)
        verdict = calculate_verdict(findings)
        assert verdict == Verdict.FLAG

    @pytest.mark.parametrize(
        "severity",
        [Severity.HIGH, Severity.CRITICAL],
    )
    def test_calculate_verdict_returns_block_for_high_or_critical(self, severity: Severity) -> None:
        findings = (make_finding(severity),)
        verdict = calculate_verdict(findings)
        assert verdict == Verdict.BLOCK

    def test_calculate_verdict_returns_block_for_mixed_low_and_high(self) -> None:
        findings = (
            make_finding(Severity.LOW, rule_id="LOW-001"),
            make_finding(Severity.HIGH, rule_id="HIGH-001"),
        )
        verdict = calculate_verdict(findings)
        assert verdict == Verdict.BLOCK

    def test_calculate_verdict_returns_flag_for_mixed_info_and_medium(self) -> None:
        findings = (
            make_finding(Severity.INFO, rule_id="INFO-001"),
            make_finding(Severity.MEDIUM, rule_id="MED-001"),
        )
        verdict = calculate_verdict(findings)
        assert verdict == Verdict.FLAG

    def test_calculate_verdict_returns_block_for_mixed_medium_and_critical(
        self,
    ) -> None:
        findings = (
            make_finding(Severity.MEDIUM, rule_id="MED-001"),
            make_finding(Severity.CRITICAL, rule_id="CRIT-001"),
        )
        verdict = calculate_verdict(findings)
        assert verdict == Verdict.BLOCK

    def test_calculate_verdict_returns_block_for_all_severities(self) -> None:
        findings = (
            make_finding(Severity.INFO, rule_id="INFO-001"),
            make_finding(Severity.LOW, rule_id="LOW-001"),
            make_finding(Severity.MEDIUM, rule_id="MED-001"),
            make_finding(Severity.HIGH, rule_id="HIGH-001"),
            make_finding(Severity.CRITICAL, rule_id="CRIT-001"),
        )
        verdict = calculate_verdict(findings)
        assert verdict == Verdict.BLOCK


class TestCountBySeverity:
    """Tests for count_by_severity function."""

    def test_count_by_severity_returns_empty_dict_for_empty_findings(self) -> None:
        counts = count_by_severity(())
        assert counts == {}

    def test_count_by_severity_counts_single_finding(self) -> None:
        findings = (make_finding(Severity.HIGH),)
        counts = count_by_severity(findings)
        assert counts == {"high": 1}

    def test_count_by_severity_counts_multiple_findings_same_severity(self) -> None:
        findings = (
            make_finding(Severity.CRITICAL, rule_id="CRIT-001"),
            make_finding(Severity.CRITICAL, rule_id="CRIT-002"),
            make_finding(Severity.CRITICAL, rule_id="CRIT-003"),
        )
        counts = count_by_severity(findings)
        assert counts == {"critical": 3}

    def test_count_by_severity_counts_multiple_findings_mixed_severities(self) -> None:
        findings = (
            make_finding(Severity.INFO, rule_id="INFO-001"),
            make_finding(Severity.INFO, rule_id="INFO-002"),
            make_finding(Severity.LOW, rule_id="LOW-001"),
            make_finding(Severity.MEDIUM, rule_id="MED-001"),
            make_finding(Severity.MEDIUM, rule_id="MED-002"),
            make_finding(Severity.HIGH, rule_id="HIGH-001"),
            make_finding(Severity.CRITICAL, rule_id="CRIT-001"),
        )
        counts = count_by_severity(findings)
        assert counts == {
            "info": 2,
            "low": 1,
            "medium": 2,
            "high": 1,
            "critical": 1,
        }

    def test_count_by_severity_uses_severity_value_strings(self) -> None:
        findings = (make_finding(Severity.HIGH),)
        counts = count_by_severity(findings)
        # Verify we get the string value "high", not "HIGH" or the enum
        assert "high" in counts
        assert counts["high"] == 1
