"""Unit tests for skill_scan.models data structures.

Tests for enums (Severity, Verdict) and frozen dataclasses (Finding, Rule, ScanResult).
"""

from __future__ import annotations

import re

import pytest

from skill_scan.models import Finding, Rule, ScanResult, Severity, Verdict


class TestSeverityEnum:
    """Tests for the Severity enum."""

    def test_severity_has_critical_value(self) -> None:
        assert Severity.CRITICAL.value == "critical"

    def test_severity_has_high_value(self) -> None:
        assert Severity.HIGH.value == "high"

    def test_severity_has_medium_value(self) -> None:
        assert Severity.MEDIUM.value == "medium"

    def test_severity_has_low_value(self) -> None:
        assert Severity.LOW.value == "low"

    def test_severity_has_info_value(self) -> None:
        assert Severity.INFO.value == "info"

    def test_severity_has_exactly_five_members(self) -> None:
        assert len(Severity) == 5


class TestVerdictEnum:
    """Tests for the Verdict enum."""

    def test_verdict_has_pass_value(self) -> None:
        assert Verdict.PASS.value == "pass"

    def test_verdict_has_flag_value(self) -> None:
        assert Verdict.FLAG.value == "flag"

    def test_verdict_has_block_value(self) -> None:
        assert Verdict.BLOCK.value == "block"

    def test_verdict_has_invalid_value(self) -> None:
        assert Verdict.INVALID.value == "invalid"

    def test_verdict_has_exactly_four_members(self) -> None:
        assert len(Verdict) == 4


class TestFindingDataclass:
    """Tests for the Finding frozen dataclass."""

    def test_finding_construction_with_all_fields(self) -> None:
        finding = Finding(
            rule_id="PI-001",
            severity=Severity.CRITICAL,
            category="prompt-injection",
            file="skill.md",
            line=42,
            matched_text="ignore previous instructions",
            description="Potential prompt injection detected",
            recommendation="Review and sanitize input",
        )

        assert finding.rule_id == "PI-001"
        assert finding.severity == Severity.CRITICAL
        assert finding.category == "prompt-injection"
        assert finding.file == "skill.md"
        assert finding.line == 42
        assert finding.matched_text == "ignore previous instructions"
        assert finding.description == "Potential prompt injection detected"
        assert finding.recommendation == "Review and sanitize input"

    def test_finding_construction_with_none_line(self) -> None:
        finding = Finding(
            rule_id="MC-002",
            severity=Severity.HIGH,
            category="malicious-code",
            file="skill.py",
            line=None,
            matched_text="eval(user_input)",
            description="Dangerous eval usage",
            recommendation="Avoid eval with untrusted input",
        )

        assert finding.line is None
        assert finding.rule_id == "MC-002"

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

    def test_rule_construction_with_compiled_patterns(self) -> None:
        patterns = (re.compile(r"ignore.*instructions"), re.compile(r"skip.*checks"))
        exclude_patterns = (re.compile(r"#.*comment"),)

        rule = Rule(
            rule_id="PI-001",
            severity=Severity.CRITICAL,
            category="prompt-injection",
            description="Detects prompt injection attempts",
            recommendation="Review flagged content",
            patterns=patterns,
            exclude_patterns=exclude_patterns,
        )

        assert rule.rule_id == "PI-001"
        assert rule.severity == Severity.CRITICAL
        assert rule.category == "prompt-injection"
        assert rule.description == "Detects prompt injection attempts"
        assert rule.recommendation == "Review flagged content"
        assert len(rule.patterns) == 2
        assert len(rule.exclude_patterns) == 1
        assert isinstance(rule.patterns[0], re.Pattern)

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

    def test_scan_result_construction(self) -> None:
        finding = Finding(
            rule_id="TEST",
            severity=Severity.LOW,
            category="test",
            file="test.txt",
            line=1,
            matched_text="test",
            description="test",
            recommendation="test",
        )
        findings = (finding,)
        counts = {"low": 1}
        verdict = Verdict.FLAG
        duration = 0.123

        result = ScanResult(
            findings=findings,
            counts=counts,
            verdict=verdict,
            duration=duration,
        )

        assert result.findings == findings
        assert result.counts == counts
        assert result.verdict == verdict
        assert result.duration == pytest.approx(0.123)

    def test_scan_result_error_message_defaults_to_none(self) -> None:
        result = ScanResult(
            findings=(),
            counts={},
            verdict=Verdict.PASS,
            duration=0.0,
        )

        assert result.error_message is None

    def test_scan_result_error_message_can_be_set(self) -> None:
        result = ScanResult(
            findings=(),
            counts={},
            verdict=Verdict.INVALID,
            duration=0.0,
            error_message="Missing SKILL.md",
        )

        assert result.error_message == "Missing SKILL.md"

    def test_scan_result_is_frozen(self) -> None:
        result = ScanResult(
            findings=(),
            counts={},
            verdict=Verdict.PASS,
            duration=0.0,
        )

        with pytest.raises(AttributeError, match="cannot assign to field"):
            result.verdict = Verdict.BLOCK  # type: ignore[misc]
