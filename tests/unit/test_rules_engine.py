"""Unit tests for skill_scan.rules.engine — pattern matching engine.

Tests line-by-line rule matching, exclude patterns, and finding generation.
"""

from __future__ import annotations

import re

import pytest

from skill_scan.models import Finding, Severity
from skill_scan.rules.engine import match_file, match_line
from tests.unit.rule_helpers import make_rule


class TestMatchLine:
    """Tests for match_line function — applying rules to a single line."""

    def test_match_line_with_matching_pattern_returns_finding(self) -> None:
        rule = make_rule(patterns=["dangerous"])

        findings = match_line("This is a dangerous operation", 42, "test.py", [rule])

        assert len(findings) == 1
        assert findings[0].rule_id == "TEST-001"
        assert findings[0].severity == Severity.INFO
        assert findings[0].matched_text == "dangerous"

    def test_match_line_with_no_matching_pattern_returns_empty_list(self) -> None:
        rule = make_rule(patterns=["dangerous"])

        findings = match_line("This is a safe operation", 1, "test.py", [rule])

        assert findings == []

    def test_match_line_with_exclude_pattern_matching_skips_rule(self) -> None:
        rule = make_rule(patterns=["dangerous"], exclude_patterns=["# safe:"])

        findings = match_line("dangerous operation # safe: reviewed", 1, "test.py", [rule])

        assert findings == []

    def test_match_line_with_exclude_pattern_not_matching_applies_rule(self) -> None:
        rule = make_rule(patterns=["dangerous"], exclude_patterns=["# safe:"])

        findings = match_line("dangerous operation without comment", 1, "test.py", [rule])

        assert len(findings) == 1
        assert findings[0].matched_text == "dangerous"

    def test_match_line_truncates_matched_text_to_200_chars(self) -> None:
        long_pattern = "a" * 250
        rule = make_rule(patterns=[long_pattern])

        findings = match_line(long_pattern, 1, "test.py", [rule])

        assert len(findings[0].matched_text) == 200

    def test_match_line_preserves_line_num_in_finding(self) -> None:
        rule = make_rule(patterns=["test"])

        findings = match_line("test line", 99, "test.py", [rule])

        assert findings[0].line == 99

    def test_match_line_preserves_file_path_in_finding(self) -> None:
        rule = make_rule(patterns=["test"])

        findings = match_line("test line", 1, "/path/to/file.py", [rule])

        assert findings[0].file == "/path/to/file.py"

    def test_match_line_with_multiple_rules_returns_findings_from_all(self) -> None:
        rule1 = make_rule(rule_id="RULE-001", patterns=["danger"])
        rule2 = make_rule(rule_id="RULE-002", patterns=["warning"])

        findings = match_line("danger and warning here", 1, "test.py", [rule1, rule2])

        assert len(findings) == 2
        assert {f.rule_id for f in findings} == {"RULE-001", "RULE-002"}

    def test_match_line_with_multiple_patterns_creates_finding_for_each(self) -> None:
        rule = make_rule(patterns=["danger", "warning", "error"])

        findings = match_line("danger warning error", 1, "test.py", [rule])

        assert len(findings) == 3
        assert {f.matched_text for f in findings} == {"danger", "warning", "error"}

    def test_match_line_with_case_insensitive_pattern(self) -> None:
        rule = make_rule(patterns=["Test"], flags=re.IGNORECASE)

        findings = match_line("this is a test line", 1, "test.py", [rule])

        assert len(findings) == 1
        assert findings[0].matched_text == "test"

    def test_match_line_sets_description_from_rule(self) -> None:
        rule = make_rule(patterns=["test"], description="Custom description text")

        findings = match_line("test line", 1, "test.py", [rule])

        assert findings[0].description == "Custom description text"

    def test_match_line_sets_recommendation_from_rule(self) -> None:
        rule = make_rule(patterns=["test"], recommendation="Custom recommendation text")

        findings = match_line("test line", 1, "test.py", [rule])

        assert findings[0].recommendation == "Custom recommendation text"

    def test_match_line_sets_category_from_rule(self) -> None:
        rule = make_rule(patterns=["test"], category="custom-category")

        findings = match_line("test line", 1, "test.py", [rule])

        assert findings[0].category == "custom-category"

    def test_match_line_with_no_rules_returns_empty_list(self) -> None:
        findings = match_line("any line content", 1, "test.py", [])

        assert findings == []

    def test_match_line_with_empty_line_returns_empty_list(self) -> None:
        rule = make_rule(patterns=["test"])

        findings = match_line("", 1, "test.py", [rule])

        assert findings == []

    def test_match_line_with_multiple_exclude_patterns_any_match_skips(self) -> None:
        rule = make_rule(
            patterns=["danger"],
            exclude_patterns=["# safe", "# reviewed", "# ignore"],
        )

        findings = match_line("danger here # reviewed by team", 1, "test.py", [rule])

        assert findings == []

    def test_match_line_excludes_rule_but_other_rules_still_match(self) -> None:
        rule1 = make_rule(rule_id="RULE-001", patterns=["danger"], exclude_patterns=["# safe"])
        rule2 = make_rule(rule_id="RULE-002", patterns=["warning"])

        findings = match_line("danger and warning # safe", 1, "test.py", [rule1, rule2])

        assert len(findings) == 1
        assert findings[0].rule_id == "RULE-002"
        assert findings[0].matched_text == "warning"

    def test_match_line_finding_is_instance_of_finding_dataclass(self) -> None:
        rule = make_rule(patterns=["test"])

        findings = match_line("test line", 1, "test.py", [rule])

        assert isinstance(findings[0], Finding)

    @pytest.mark.parametrize(
        "severity,expected",
        [
            (Severity.CRITICAL, Severity.CRITICAL),
            (Severity.HIGH, Severity.HIGH),
            (Severity.MEDIUM, Severity.MEDIUM),
            (Severity.LOW, Severity.LOW),
            (Severity.INFO, Severity.INFO),
        ],
    )
    def test_match_line_preserves_severity_from_rule(self, severity: Severity, expected: Severity) -> None:
        rule = make_rule(patterns=["test"], severity=severity)

        findings = match_line("test line", 1, "test.py", [rule])

        assert findings[0].severity == expected


class TestMatchFile:
    """Tests for match_file function — applying file-scope rules against full content."""

    def test_match_file_detects_pattern_and_maps_line_numbers(self) -> None:
        rule = make_rule(patterns=["target"], match_scope="file")
        content = "line one\nline two\nline target here\nline four"

        findings = match_file(content, "test.py", [rule])

        assert len(findings) == 1
        assert findings[0].line == 3
        assert findings[0].matched_text == "target"

    def test_match_file_with_multiline_pattern(self) -> None:
        rule = make_rule(patterns=[r"eval\(\s*\n\s*code"], match_scope="file")

        findings = match_file("eval(\n    code)", "test.py", [rule])

        assert len(findings) == 1
        assert "eval" in findings[0].matched_text

    def test_match_file_exclude_pattern_checked_against_match_line(self) -> None:
        rule = make_rule(patterns=["danger"], exclude_patterns=["# safe"], match_scope="file")
        content_excluded = "line one\ndanger here # safe\nline three"
        content_not_excluded = "line one # safe\ndanger here\nline three"

        assert match_file(content_excluded, "test.py", [rule]) == []
        assert len(match_file(content_not_excluded, "test.py", [rule])) == 1

    def test_match_file_truncates_matched_text(self) -> None:
        long_pattern = "a" * 250
        rule = make_rule(patterns=[long_pattern], match_scope="file")

        findings = match_file(long_pattern, "test.py", [rule])

        assert len(findings[0].matched_text) == 200

    def test_match_file_multiple_matches_returns_all_findings(self) -> None:
        rule = make_rule(patterns=["danger"], match_scope="file")
        content = "danger on line 1\nline 2\ndanger on line 3"

        findings = match_file(content, "test.py", [rule])

        assert len(findings) == 2
        assert findings[0].line == 1
        assert findings[1].line == 3
