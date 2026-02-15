"""Unit tests for skill_scan.formatters text output formatting.

Tests format_text() with default, quiet, and verbose modes.
"""

from __future__ import annotations

from skill_scan.formatters import OutputMode, format_text
from skill_scan.models import ScanResult, Severity, Verdict
from tests.unit.formatter_helpers import make_finding


class TestFormatTextDefaultNoFindings:
    """Tests for default mode with no findings."""

    def test_includes_report_header(self) -> None:
        result = ScanResult(
            findings=(),
            counts={},
            verdict=Verdict.PASS,
            duration=0.5,
            files_scanned=3,
            skill_name="my-skill",
        )
        output = format_text(result)
        assert "skill-scan report: my-skill" in output
        assert "Scanned 3 files in 0.50s" in output

    def test_includes_no_issues_message(self) -> None:
        result = ScanResult(
            findings=(),
            counts={},
            verdict=Verdict.PASS,
            duration=0.0,
        )
        output = format_text(result)
        assert "No security issues found." in output

    def test_includes_verdict_banner(self) -> None:
        result = ScanResult(
            findings=(),
            counts={},
            verdict=Verdict.PASS,
            duration=0.1,
        )
        output = format_text(result)
        assert "Verdict: PASS" in output


class TestFormatTextDefaultWithFindings:
    """Tests for default mode with findings present."""

    def test_contains_severity_section(self) -> None:
        finding = make_finding(severity=Severity.MEDIUM)
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.1,
        )
        output = format_text(result)
        assert "MEDIUM (1 findings, 1 rules)" in output

    def test_contains_severity_tag_in_finding(self) -> None:
        finding = make_finding(severity=Severity.CRITICAL, rule_id="PI-001")
        result = ScanResult(
            findings=(finding,),
            counts={"critical": 1},
            verdict=Verdict.BLOCK,
            duration=0.1,
        )
        output = format_text(result)
        assert "[CRITICAL] PI-001:" in output

    def test_contains_file_and_line_reference(self) -> None:
        finding = make_finding(file="SKILL.md", line=42)
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.1,
        )
        output = format_text(result)
        assert "SKILL.md:42" in output

    def test_contains_matched_text(self) -> None:
        finding = make_finding(matched_text="ignore previous instructions")
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.1,
        )
        output = format_text(result)
        assert '"ignore previous instructions"' in output

    def test_contains_recommendation(self) -> None:
        finding = make_finding(recommendation="Remove this pattern")
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.1,
        )
        output = format_text(result)
        assert "-> Remove this pattern" in output

    def test_empty_severity_sections_omitted(self) -> None:
        finding = make_finding(severity=Severity.MEDIUM)
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.1,
        )
        output = format_text(result)
        assert "CRITICAL" not in output
        assert "HIGH" not in output

    def test_verdict_banner_includes_counts(self) -> None:
        finding = make_finding()
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.65,
        )
        output = format_text(result)
        assert "Verdict: FLAG" in output
        assert "1 medium" in output
        assert "Scanned in 0.65s" in output


class TestFormatTextQuiet:
    """Tests for quiet mode output."""

    def test_quiet_pass(self) -> None:
        result = ScanResult(
            findings=(),
            counts={},
            verdict=Verdict.PASS,
            duration=0.0,
        )
        output = format_text(result, mode=OutputMode.QUIET)
        assert output == "Verdict: PASS"

    def test_quiet_with_findings(self) -> None:
        finding = make_finding()
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.1,
        )
        output = format_text(result, mode=OutputMode.QUIET)
        assert output == "Verdict: FLAG (1 medium)"


class TestFormatTextVerbose:
    """Tests for verbose mode output."""

    def test_verbose_shows_all_findings(self) -> None:
        findings = tuple(make_finding(rule_id="PI-004", file=f"f{i}.md", line=i) for i in range(5))
        result = ScanResult(
            findings=findings,
            counts={"medium": 5},
            verdict=Verdict.FLAG,
            duration=0.1,
        )
        output = format_text(result, mode=OutputMode.VERBOSE)
        for i in range(5):
            assert f"f{i}.md:{i}" in output
        assert "occurrences" not in output

    def test_verbose_has_header_and_banner(self) -> None:
        result = ScanResult(
            findings=(),
            counts={},
            verdict=Verdict.PASS,
            duration=0.0,
            skill_name="test",
        )
        output = format_text(result, mode=OutputMode.VERBOSE)
        assert "skill-scan report: test" in output
        assert "Verdict: PASS" in output


class TestFormatTextAsciiSafe:
    """Tests for ASCII-only output."""

    def test_output_is_ascii(self) -> None:
        finding = make_finding(recommendation="Review and remove this pattern")
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.1,
        )
        output = format_text(result)
        non_ascii = [c for c in output if ord(c) > 127]
        assert non_ascii == [], f"Non-ASCII chars found: {non_ascii}"

    def test_uses_ascii_arrow(self) -> None:
        finding = make_finding(recommendation="Fix this issue")
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.1,
        )
        output = format_text(result)
        assert "-> Fix this issue" in output


class TestPublicAPIImports:
    """Tests for public API exports from skill_scan package."""

    def test_public_api_exports_all_required_names(self) -> None:
        from skill_scan import (
            Finding,
            OutputMode,
            Rule,
            ScanResult,
            Severity,
            Verdict,
            scan,
        )

        assert all(
            x is not None
            for x in (
                Finding,
                OutputMode,
                Rule,
                ScanResult,
                Severity,
                Verdict,
                scan,
            )
        )
