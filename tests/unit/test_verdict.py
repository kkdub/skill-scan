"""Unit tests for skill_scan.verdict calculation logic.

Tests for calculate_verdict and count_by_severity functions.
"""

from __future__ import annotations

import pytest

from skill_scan.models import Severity, Verdict
from skill_scan.verdict import calculate_verdict, count_by_severity, coverage_aware_verdict
from tests.unit.formatter_helpers import make_finding


class TestCalculateVerdict:
    """Tests for calculate_verdict function."""

    def test_calculate_verdict_returns_pass_for_empty_findings(self) -> None:
        verdict = calculate_verdict(())
        assert verdict == Verdict.PASS

    def test_calculate_verdict_returns_pass_for_info_only(self) -> None:
        findings = (
            make_finding(severity=Severity.INFO, rule_id="INFO-001"),
            make_finding(severity=Severity.INFO, rule_id="INFO-002"),
        )
        verdict = calculate_verdict(findings)
        assert verdict == Verdict.PASS

    @pytest.mark.parametrize(
        "severity",
        [Severity.LOW, Severity.MEDIUM],
    )
    def test_calculate_verdict_returns_flag_for_low_or_medium(self, severity: Severity) -> None:
        findings = (make_finding(severity=severity),)
        verdict = calculate_verdict(findings)
        assert verdict == Verdict.FLAG

    @pytest.mark.parametrize(
        "severity",
        [Severity.HIGH, Severity.CRITICAL],
    )
    def test_calculate_verdict_returns_block_for_high_or_critical(self, severity: Severity) -> None:
        findings = (make_finding(severity=severity),)
        verdict = calculate_verdict(findings)
        assert verdict == Verdict.BLOCK

    def test_calculate_verdict_returns_block_for_mixed_low_and_high(self) -> None:
        findings = (
            make_finding(severity=Severity.LOW, rule_id="LOW-001"),
            make_finding(severity=Severity.HIGH, rule_id="HIGH-001"),
        )
        verdict = calculate_verdict(findings)
        assert verdict == Verdict.BLOCK

    def test_calculate_verdict_returns_flag_for_mixed_info_and_medium(self) -> None:
        findings = (
            make_finding(severity=Severity.INFO, rule_id="INFO-001"),
            make_finding(severity=Severity.MEDIUM, rule_id="MED-001"),
        )
        verdict = calculate_verdict(findings)
        assert verdict == Verdict.FLAG

    def test_calculate_verdict_returns_block_for_mixed_medium_and_critical(
        self,
    ) -> None:
        findings = (
            make_finding(severity=Severity.MEDIUM, rule_id="MED-001"),
            make_finding(severity=Severity.CRITICAL, rule_id="CRIT-001"),
        )
        verdict = calculate_verdict(findings)
        assert verdict == Verdict.BLOCK

    def test_calculate_verdict_returns_block_for_all_severities(self) -> None:
        findings = (
            make_finding(severity=Severity.INFO, rule_id="INFO-001"),
            make_finding(severity=Severity.LOW, rule_id="LOW-001"),
            make_finding(severity=Severity.MEDIUM, rule_id="MED-001"),
            make_finding(severity=Severity.HIGH, rule_id="HIGH-001"),
            make_finding(severity=Severity.CRITICAL, rule_id="CRIT-001"),
        )
        verdict = calculate_verdict(findings)
        assert verdict == Verdict.BLOCK


class TestCountBySeverity:
    """Tests for count_by_severity function."""

    def test_count_by_severity_returns_empty_dict_for_empty_findings(self) -> None:
        counts = count_by_severity(())
        assert counts == {}

    def test_count_by_severity_counts_single_finding(self) -> None:
        findings = (make_finding(severity=Severity.HIGH),)
        counts = count_by_severity(findings)
        assert counts == {"high": 1}

    def test_count_by_severity_counts_multiple_findings_same_severity(self) -> None:
        findings = (
            make_finding(severity=Severity.CRITICAL, rule_id="CRIT-001"),
            make_finding(severity=Severity.CRITICAL, rule_id="CRIT-002"),
            make_finding(severity=Severity.CRITICAL, rule_id="CRIT-003"),
        )
        counts = count_by_severity(findings)
        assert counts == {"critical": 3}

    def test_count_by_severity_counts_multiple_findings_mixed_severities(self) -> None:
        findings = (
            make_finding(severity=Severity.INFO, rule_id="INFO-001"),
            make_finding(severity=Severity.INFO, rule_id="INFO-002"),
            make_finding(severity=Severity.LOW, rule_id="LOW-001"),
            make_finding(severity=Severity.MEDIUM, rule_id="MED-001"),
            make_finding(severity=Severity.MEDIUM, rule_id="MED-002"),
            make_finding(severity=Severity.HIGH, rule_id="HIGH-001"),
            make_finding(severity=Severity.CRITICAL, rule_id="CRIT-001"),
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
        findings = (make_finding(severity=Severity.HIGH),)
        counts = count_by_severity(findings)
        # Verify we get the string value "high", not "HIGH" or the enum
        assert "high" in counts
        assert counts["high"] == 1


class TestCoverageAwareVerdict:
    """Tests for coverage_aware_verdict function."""

    def test_returns_pass_when_no_degradation(self) -> None:
        verdict = coverage_aware_verdict(
            findings=(),
            files_skipped=0,
            degraded_reasons=(),
        )
        assert verdict == Verdict.PASS

    def test_upgrades_pass_to_flag_when_files_skipped(self) -> None:
        verdict = coverage_aware_verdict(
            findings=(),
            files_skipped=1,
            degraded_reasons=(),
        )
        assert verdict == Verdict.FLAG

    def test_upgrades_pass_to_flag_when_degraded_reasons(self) -> None:
        verdict = coverage_aware_verdict(
            findings=(),
            files_skipped=0,
            degraded_reasons=("Large file excluded",),
        )
        assert verdict == Verdict.FLAG

    def test_preserves_block_even_with_degradation(self) -> None:
        findings = (make_finding(severity=Severity.HIGH),)
        verdict = coverage_aware_verdict(
            findings=findings,
            files_skipped=1,
            degraded_reasons=(),
        )
        assert verdict == Verdict.BLOCK

    def test_preserves_flag_from_findings(self) -> None:
        findings = (make_finding(severity=Severity.MEDIUM),)
        verdict = coverage_aware_verdict(
            findings=findings,
            files_skipped=0,
            degraded_reasons=(),
        )
        assert verdict == Verdict.FLAG

    def test_returns_flag_with_both_skips_and_degraded_reasons(self) -> None:
        verdict = coverage_aware_verdict(
            findings=(),
            files_skipped=2,
            degraded_reasons=("Binary file", "Large file"),
        )
        assert verdict == Verdict.FLAG
