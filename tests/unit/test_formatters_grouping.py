"""Unit tests for output deduplication and grouping (OD1-OD5).

Tests format_text() grouping behavior when multiple findings share a rule_id.
"""

from __future__ import annotations

from skill_scan.formatters import format_text
from skill_scan.models import ScanResult, Severity, Verdict
from tests.unit.formatter_helpers import make_finding


class TestFormatTextGrouping:
    """Tests for OD1-OD5: grouped/deduplicated output."""

    def test_single_finding_uses_original_format(self) -> None:
        finding = make_finding(rule_id="PI-001")
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.1,
        )
        output = format_text(result)
        assert "File: test.md:10" in output
        assert "occurrences" not in output

    def test_multiple_same_rule_grouped_with_count(self) -> None:
        findings = tuple(make_finding(rule_id="PI-004", file=f"f{i}.md", line=i) for i in range(5))
        result = ScanResult(
            findings=findings,
            counts={"medium": 5},
            verdict=Verdict.FLAG,
            duration=0.1,
        )
        output = format_text(result)
        assert "5 occurrences across 5 files" in output
        assert output.count("[MEDIUM] PI-004:") == 1

    def test_grouped_shows_max_three_samples(self) -> None:
        findings = tuple(make_finding(rule_id="PI-004", file=f"f{i}.md", line=i) for i in range(10))
        result = ScanResult(
            findings=findings,
            counts={"medium": 10},
            verdict=Verdict.FLAG,
            duration=0.1,
        )
        output = format_text(result)
        assert "... and 7 more" in output
        assert "f0.md:0" in output
        assert "f2.md:2" in output

    def test_grouped_includes_recommendation_once(self) -> None:
        findings = tuple(make_finding(rule_id="PI-004", recommendation="Fix it") for _ in range(4))
        result = ScanResult(
            findings=findings,
            counts={"medium": 4},
            verdict=Verdict.FLAG,
            duration=0.1,
        )
        output = format_text(result)
        assert output.count("-> Fix it") == 1

    def test_two_different_rules_get_separate_groups(self) -> None:
        f1 = make_finding(rule_id="PI-001", severity=Severity.CRITICAL)
        f2 = make_finding(rule_id="PI-004", severity=Severity.MEDIUM)
        result = ScanResult(
            findings=(f1, f2),
            counts={"critical": 1, "medium": 1},
            verdict=Verdict.BLOCK,
            duration=0.1,
        )
        output = format_text(result)
        assert "[CRITICAL] PI-001:" in output
        assert "[MEDIUM] PI-004:" in output

    def test_three_findings_all_shown_no_more_line(self) -> None:
        findings = tuple(make_finding(rule_id="PI-004", file=f"f{i}.md", line=i) for i in range(3))
        result = ScanResult(
            findings=findings,
            counts={"medium": 3},
            verdict=Verdict.FLAG,
            duration=0.1,
        )
        output = format_text(result)
        assert "3 occurrences" in output
        assert "... and" not in output
        assert "f0.md:0" in output
        assert "f2.md:2" in output

    def test_scan_result_findings_preserved_unchanged(self) -> None:
        findings = tuple(make_finding(rule_id="PI-004", file=f"f{i}.md", line=i) for i in range(50))
        result = ScanResult(
            findings=findings,
            counts={"medium": 50},
            verdict=Verdict.FLAG,
            duration=0.1,
        )
        format_text(result)
        assert len(result.findings) == 50
