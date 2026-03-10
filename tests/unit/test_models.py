"""Unit tests for skill_scan.models data structures.

Tests for enums (Severity, Verdict) and frozen dataclasses (Finding, Rule, ScanResult).
"""

from __future__ import annotations

import pytest

from skill_scan.models import Finding, Rule, ScanResult, Severity, Verdict


class TestFindingDataclass:
    """Tests for the Finding frozen dataclass."""

    def test_finding_is_frozen(self) -> None:
        finding = Finding(
            rule_id="TEST",
            severity=Severity.INFO,
            category="test",
            file="test.txt",
            line=1,
            matched_text="test",
            description="test",
            recommendation="test",
        )

        with pytest.raises(AttributeError, match="cannot assign to field"):
            finding.rule_id = "MODIFIED"  # type: ignore[misc]


class TestRuleDataclass:
    """Tests for the Rule frozen dataclass."""

    def test_rule_is_frozen(self) -> None:
        rule = Rule(
            rule_id="TEST",
            severity=Severity.INFO,
            category="test",
            description="test",
            recommendation="test",
            patterns=(),
            exclude_patterns=(),
        )

        with pytest.raises(AttributeError, match="cannot assign to field"):
            rule.rule_id = "MODIFIED"  # type: ignore[misc]


class TestScanResultDataclass:
    """Tests for the ScanResult frozen dataclass."""

    def test_scan_result_is_frozen(self) -> None:
        result = ScanResult(
            findings=(),
            counts={},
            verdict=Verdict.PASS,
            duration=0.0,
        )

        with pytest.raises(AttributeError, match="cannot assign to field"):
            result.verdict = Verdict.BLOCK  # type: ignore[misc]
