"""Unit tests for skill_scan.formatters verdict banner and header.

Tests format_text() header, severity sections, and verdict banner output.
"""

from __future__ import annotations

from skill_scan.formatters import OutputMode, format_text
from skill_scan.models import ScanResult, Severity, Verdict
from tests.unit.formatter_helpers import make_finding


class TestFormatTextVerdictBanner:
    """Tests for the verdict banner section."""

    def test_verdict_banner_shows_counts(self) -> None:
        finding1 = make_finding(severity=Severity.CRITICAL, rule_id="PI-001")
        finding2 = make_finding(severity=Severity.MEDIUM, rule_id="PI-004")
        result = ScanResult(
            findings=(finding1, finding1, finding2),
            counts={"critical": 2, "medium": 1},
            verdict=Verdict.BLOCK,
            duration=0.5,
        )
        output = format_text(result)
        assert "2 critical, 1 medium" in output

    def test_verdict_shown_in_uppercase(self) -> None:
        finding = make_finding()
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.1,
        )
        output = format_text(result)
        assert "Verdict: FLAG" in output

    def test_duration_shown(self) -> None:
        finding = make_finding()
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=1.23456,
        )
        output = format_text(result)
        assert "Scanned in 1.23s" in output

    def test_only_nonzero_counts_shown(self) -> None:
        finding = make_finding(severity=Severity.CRITICAL, rule_id="PI-001")
        result = ScanResult(
            findings=(finding,),
            counts={"critical": 1},
            verdict=Verdict.BLOCK,
            duration=0.1,
        )
        output = format_text(result)
        assert "1 critical" in output
        assert "high" not in output.split("Verdict")[1]
        assert "medium" not in output.split("Verdict")[1]

    def test_counts_in_severity_order(self) -> None:
        findings = (
            make_finding(severity=Severity.INFO, rule_id="SV-001"),
            make_finding(severity=Severity.CRITICAL, rule_id="PI-001"),
            make_finding(severity=Severity.LOW, rule_id="PI-LO"),
            make_finding(severity=Severity.MEDIUM, rule_id="PI-004"),
        )
        result = ScanResult(
            findings=findings,
            counts={"critical": 1, "medium": 1, "low": 1, "info": 1},
            verdict=Verdict.BLOCK,
            duration=0.1,
        )
        output = format_text(result)
        banner = output.split("------------------")[-1]
        crit_pos = banner.find("1 critical")
        med_pos = banner.find("1 medium")
        low_pos = banner.find("1 low")
        info_pos = banner.find("1 info")
        assert crit_pos < med_pos < low_pos < info_pos


class TestFormatTextSeveritySections:
    """Tests for severity-grouped sections in default mode."""

    def test_severity_sections_appear_in_order(self) -> None:
        findings = (
            make_finding(severity=Severity.LOW, rule_id="R-LO"),
            make_finding(severity=Severity.CRITICAL, rule_id="R-CR"),
        )
        result = ScanResult(
            findings=findings,
            counts={"critical": 1, "low": 1},
            verdict=Verdict.BLOCK,
            duration=0.1,
        )
        output = format_text(result)
        crit_pos = output.find("CRITICAL (")
        low_pos = output.find("LOW (")
        assert crit_pos < low_pos

    def test_header_shows_skill_name(self) -> None:
        result = ScanResult(
            findings=(),
            counts={},
            verdict=Verdict.PASS,
            duration=0.1,
            skill_name="my-cool-skill",
        )
        output = format_text(result)
        assert "skill-scan report: my-cool-skill" in output

    def test_header_shows_unknown_when_no_skill_name(self) -> None:
        result = ScanResult(
            findings=(),
            counts={},
            verdict=Verdict.PASS,
            duration=0.1,
        )
        output = format_text(result)
        assert "skill-scan report: unknown" in output


class TestFormatTextCoverageMetadata:
    """Tests for coverage metadata display in formatted output."""

    def test_header_shows_bytes_scanned(self) -> None:
        result = ScanResult(findings=(), counts={}, verdict=Verdict.PASS, duration=0.1, bytes_scanned=1024)
        output = format_text(result)
        assert "1024 bytes" in output

    def test_header_shows_skipped_files(self) -> None:
        result = ScanResult(findings=(), counts={}, verdict=Verdict.PASS, duration=0.1, files_skipped=2)
        output = format_text(result)
        assert "Skipped: 2 files" in output

    def test_header_shows_degraded_reasons(self) -> None:
        result = ScanResult(
            findings=(),
            counts={},
            verdict=Verdict.FLAG,
            duration=0.1,
            degraded_reasons=("2 binary files excluded",),
        )
        output = format_text(result)
        assert "Warning: 2 binary files excluded" in output

    def test_quiet_mode_shows_skipped_suffix(self) -> None:
        result = ScanResult(findings=(), counts={}, verdict=Verdict.PASS, duration=0.1, files_skipped=3)
        output = format_text(result, mode=OutputMode.QUIET)
        assert "[3 files skipped]" in output

    def test_quiet_mode_no_suffix_when_no_skips(self) -> None:
        result = ScanResult(findings=(), counts={}, verdict=Verdict.PASS, duration=0.1, files_skipped=0)
        output = format_text(result, mode=OutputMode.QUIET)
        assert "skipped" not in output
