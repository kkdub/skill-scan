"""Unit tests for skill_scan.formatters summary section.

Tests format_text() summary output with counts, verdict, and duration.
"""

from __future__ import annotations

from skill_scan.formatters import format_text
from skill_scan.models import ScanResult, Severity, Verdict
from tests.unit.formatter_helpers import make_finding


class TestFormatTextSummary:
    """Tests for format_text summary section."""

    def test_format_text_summary_shows_correct_severity_counts(self) -> None:
        finding1 = make_finding(severity=Severity.CRITICAL)
        finding2 = make_finding(severity=Severity.CRITICAL)
        finding3 = make_finding(severity=Severity.MEDIUM)
        result = ScanResult(
            findings=(finding1, finding2, finding3),
            counts={"critical": 2, "medium": 1},
            verdict=Verdict.BLOCK,
            duration=0.5,
        )

        output = format_text(result)

        assert "critical: 2" in output
        assert "medium: 1" in output

    def test_format_text_summary_shows_verdict_in_uppercase(self) -> None:
        finding = make_finding()
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.1,
        )

        output = format_text(result)

        assert "Verdict: FLAG" in output

    def test_format_text_summary_shows_duration_with_two_decimal_places(self) -> None:
        finding = make_finding()
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=1.23456,
        )

        output = format_text(result)

        assert "Duration: 1.23s" in output

    def test_format_text_summary_only_shows_non_zero_severity_counts(self) -> None:
        finding = make_finding(severity=Severity.CRITICAL)
        result = ScanResult(
            findings=(finding,),
            counts={"critical": 1},
            verdict=Verdict.BLOCK,
            duration=0.1,
        )

        output = format_text(result)

        assert "critical: 1" in output
        assert "high:" not in output
        assert "medium:" not in output
        assert "low:" not in output
        assert "info:" not in output

    def test_format_text_summary_shows_counts_in_severity_order(self) -> None:
        findings = (
            make_finding(severity=Severity.INFO),
            make_finding(severity=Severity.CRITICAL),
            make_finding(severity=Severity.LOW),
            make_finding(severity=Severity.MEDIUM),
        )
        result = ScanResult(
            findings=findings,
            counts={"critical": 1, "medium": 1, "low": 1, "info": 1},
            verdict=Verdict.BLOCK,
            duration=0.1,
        )

        output = format_text(result)

        critical_pos = output.find("critical: 1")
        medium_pos = output.find("medium: 1")
        low_pos = output.find("low: 1")
        info_pos = output.find("info: 1")

        assert critical_pos < medium_pos < low_pos < info_pos
