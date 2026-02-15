"""Unit tests for skill_scan.formatters text output formatting.

Tests format_text() with various ScanResult configurations.
Focus: basic output structure and finding formatting.
"""

from __future__ import annotations

from skill_scan.formatters import format_text
from skill_scan.models import ScanResult, Severity, Verdict
from tests.unit.formatter_helpers import make_finding


class TestFormatTextInvalid:
    """Tests for format_text with INVALID verdict."""

    def test_format_text_returns_error_message_when_invalid_verdict(self) -> None:
        result = ScanResult(
            findings=(),
            counts={},
            verdict=Verdict.INVALID,
            duration=0.0,
        )

        output = format_text(result)

        assert output == "Scan failed: invalid skill schema."

    def test_format_text_includes_detail_when_error_message_present(self) -> None:
        result = ScanResult(
            findings=(),
            counts={},
            verdict=Verdict.INVALID,
            duration=0.0,
            error_message="Missing required field: name",
        )

        output = format_text(result)

        assert "Scan failed: invalid skill schema." in output
        assert "Detail: Missing required field: name" in output


class TestFormatTextNoFindings:
    """Tests for format_text with no findings."""

    def test_format_text_returns_success_message_when_no_findings(self) -> None:
        result = ScanResult(
            findings=(),
            counts={},
            verdict=Verdict.PASS,
            duration=0.0,
        )

        output = format_text(result)

        assert output == "No security issues found."


class TestFormatTextWithFindings:
    """Tests for format_text with findings present."""

    def test_format_text_contains_header_when_findings_present(self) -> None:
        finding = make_finding()
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.42,
        )

        output = format_text(result)

        assert output.startswith("skill-scan results\n==================\n\n")

    def test_format_text_contains_severity_tag_in_uppercase(self) -> None:
        finding = make_finding(severity=Severity.CRITICAL, rule_id="PI-001")
        result = ScanResult(
            findings=(finding,),
            counts={"critical": 1},
            verdict=Verdict.BLOCK,
            duration=0.1,
        )

        output = format_text(result)

        assert "[CRITICAL] PI-001:" in output

    def test_format_text_contains_rule_id(self) -> None:
        finding = make_finding(rule_id="MC-042")
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.1,
        )

        output = format_text(result)

        assert "MC-042:" in output

    def test_format_text_contains_description(self) -> None:
        finding = make_finding(description="Potential security issue detected")
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.1,
        )

        output = format_text(result)

        assert "Potential security issue detected" in output

    def test_format_text_contains_file_and_line_reference(self) -> None:
        finding = make_finding(file="SKILL.md", line=42)
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.1,
        )

        output = format_text(result)

        assert "File: SKILL.md:42" in output

    def test_format_text_contains_file_reference_without_line_when_line_is_none(
        self,
    ) -> None:
        finding = make_finding(file="script.py", line=None)
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.1,
        )

        output = format_text(result)

        assert "File: script.py\n" in output
        assert "script.py:" not in output

    def test_format_text_contains_matched_text(self) -> None:
        finding = make_finding(matched_text="ignore previous instructions")
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.1,
        )

        output = format_text(result)

        assert 'Match: "ignore previous instructions"' in output

    def test_format_text_truncates_matched_text_longer_than_80_chars(self) -> None:
        long_text = "a" * 100
        finding = make_finding(matched_text=long_text)
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.1,
        )

        output = format_text(result)

        assert 'Match: "' + ("a" * 77) + '..."' in output
        assert long_text not in output

    def test_format_text_contains_recommendation(self) -> None:
        finding = make_finding(recommendation="Remove this pattern")
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.1,
        )

        output = format_text(result)

        assert "→ Remove this pattern" in output


class TestPublicAPIImports:
    """Tests for public API exports from skill_scan package."""

    def test_public_api_exports_all_required_names(self) -> None:
        from skill_scan import Finding, Rule, ScanResult, Severity, Verdict, scan

        assert Finding is not None
        assert Rule is not None
        assert ScanResult is not None
        assert Severity is not None
        assert Verdict is not None
        assert scan is not None
        assert callable(scan)
