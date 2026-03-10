"""Tests for inline suppression via # noqa: RULE-ID comments.

Covers: parse_noqa extraction, filter_suppressed filtering, case insensitivity,
whitespace tolerance, and bare noqa rejection.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_scan.content_scanner import scan_all_files
from skill_scan.rules import load_default_rules
from skill_scan.suppression import filter_suppressed, parse_noqa
from tests.unit.formatter_helpers import make_finding


# ---------------------------------------------------------------------------
# parse_noqa
# ---------------------------------------------------------------------------


class TestParseNoqa:
    """Tests for parse_noqa rule ID extraction."""

    def test_single_rule_id(self) -> None:
        result = parse_noqa("eval(x)  # noqa: EXEC-002")
        assert result == frozenset({"EXEC-002"})

    def test_multiple_rule_ids(self) -> None:
        result = parse_noqa("eval(x)  # noqa: PI-001, EXEC-002")
        assert result == frozenset({"PI-001", "EXEC-002"})

    def test_bare_noqa_returns_empty(self) -> None:
        result = parse_noqa("eval(x)  # noqa")
        assert result == frozenset()

    def test_no_noqa_returns_empty(self) -> None:
        result = parse_noqa("eval(x)")
        assert result == frozenset()

    def test_empty_line_returns_empty(self) -> None:
        result = parse_noqa("")
        assert result == frozenset()

    def test_case_insensitive_noqa_keyword(self) -> None:
        result = parse_noqa("eval(x)  # NOQA: EXEC-002")
        assert result == frozenset({"EXEC-002"})

    def test_case_insensitive_mixed(self) -> None:
        result = parse_noqa("eval(x)  # Noqa: exec-002")
        assert result == frozenset({"EXEC-002"})

    def test_no_space_after_hash(self) -> None:
        result = parse_noqa("eval(x)  #noqa: PI-001")
        assert result == frozenset({"PI-001"})

    def test_no_space_after_colon(self) -> None:
        result = parse_noqa("eval(x)  # noqa:PI-001")
        assert result == frozenset({"PI-001"})

    def test_spaces_between_comma_separated_ids(self) -> None:
        result = parse_noqa("code  # noqa: PI-001 , EXEC-002")
        assert result == frozenset({"PI-001", "EXEC-002"})

    def test_noqa_in_middle_of_comment(self) -> None:
        result = parse_noqa("x = 1  # some comment noqa: EXEC-002")
        assert result == frozenset()

    @pytest.mark.parametrize(
        "line",
        [
            "# NOQA: PI-001",
            "#noqa:PI-001",
            "# noqa:  PI-001",
        ],
        ids=["CAPS_spaced", "no_spaces", "extra_space_after_colon"],
    )
    def test_whitespace_tolerance_variants(self, line: str) -> None:
        result = parse_noqa(line)
        assert "PI-001" in result


# ---------------------------------------------------------------------------
# filter_suppressed
# ---------------------------------------------------------------------------


class TestFilterSuppressed:
    """Tests for filter_suppressed finding removal."""

    def test_matching_rule_is_suppressed(self) -> None:
        findings = [make_finding(rule_id="EXEC-002", line=1)]
        lines = ["eval(x)  # noqa: EXEC-002"]
        remaining, suppressed = filter_suppressed(findings, lines)
        assert remaining == []
        assert suppressed == 1

    def test_non_matching_rule_is_kept(self) -> None:
        findings = [make_finding(rule_id="PI-001", line=1)]
        lines = ["eval(x)  # noqa: EXEC-002"]
        remaining, suppressed = filter_suppressed(findings, lines)
        assert len(remaining) == 1
        assert suppressed == 0

    def test_multiple_rules_suppressed(self) -> None:
        findings = [
            make_finding(rule_id="PI-001", line=1),
            make_finding(rule_id="EXEC-002", line=1),
        ]
        lines = ["eval(x)  # noqa: PI-001, EXEC-002"]
        remaining, suppressed = filter_suppressed(findings, lines)
        assert remaining == []
        assert suppressed == 2

    def test_partial_suppression_keeps_unmatched(self) -> None:
        findings = [
            make_finding(rule_id="PI-001", line=1),
            make_finding(rule_id="EXEC-002", line=1),
            make_finding(rule_id="FS-005", line=1),
        ]
        lines = ["eval(x)  # noqa: PI-001, EXEC-002"]
        remaining, suppressed = filter_suppressed(findings, lines)
        assert len(remaining) == 1
        assert remaining[0].rule_id == "FS-005"
        assert suppressed == 2

    def test_bare_noqa_does_not_suppress(self) -> None:
        findings = [make_finding(rule_id="EXEC-002", line=1)]
        lines = ["eval(x)  # noqa"]
        remaining, suppressed = filter_suppressed(findings, lines)
        assert len(remaining) == 1
        assert suppressed == 0

    def test_finding_with_no_line_is_kept(self) -> None:
        findings = [make_finding(rule_id="EXEC-002", line=None)]
        lines = ["eval(x)  # noqa: EXEC-002"]
        remaining, suppressed = filter_suppressed(findings, lines)
        assert len(remaining) == 1
        assert suppressed == 0

    def test_empty_findings_returns_empty(self) -> None:
        remaining, suppressed = filter_suppressed([], ["some line"])
        assert remaining == []
        assert suppressed == 0

    def test_empty_lines_returns_all_findings(self) -> None:
        findings = [make_finding(rule_id="EXEC-002", line=1)]
        remaining, suppressed = filter_suppressed(findings, [])
        assert len(remaining) == 1
        assert suppressed == 0

    def test_case_insensitive_rule_matching(self) -> None:
        findings = [make_finding(rule_id="exec-002", line=1)]
        lines = ["eval(x)  # noqa: EXEC-002"]
        remaining, suppressed = filter_suppressed(findings, lines)
        assert remaining == []
        assert suppressed == 1

    def test_multi_line_file_only_suppresses_matching_line(self) -> None:
        findings = [
            make_finding(rule_id="EXEC-002", line=1),
            make_finding(rule_id="EXEC-002", line=2),
        ]
        lines = [
            "eval(x)  # noqa: EXEC-002",
            "eval(y)",
        ]
        remaining, suppressed = filter_suppressed(findings, lines)
        assert len(remaining) == 1
        assert remaining[0].line == 2
        assert suppressed == 1

    def test_suppressed_count_is_correct_for_three(self) -> None:
        findings = [
            make_finding(rule_id="EXEC-002", line=1),
            make_finding(rule_id="PI-001", line=2),
            make_finding(rule_id="FS-005", line=3),
        ]
        lines = [
            "eval(x)  # noqa: EXEC-002",
            "inject  # noqa: PI-001",
            "big  # noqa: FS-005",
        ]
        remaining, suppressed = filter_suppressed(findings, lines)
        assert remaining == []
        assert suppressed == 3


# ---------------------------------------------------------------------------
# Acceptance scenarios
# ---------------------------------------------------------------------------


class TestAcceptanceInlineNoqa:
    """Acceptance: inline noqa suppresses specific finding and is reported."""

    def test_noqa_suppresses_exec002_and_reports_count(self, tmp_path: Path) -> None:
        """Scan a file where line 5 has eval() with # noqa: EXEC-002."""
        lines = [
            "import os\n",
            "x = 1\n",
            "y = 2\n",
            "z = 3\n",
            "eval(user_input)  # noqa: EXEC-002\n",
            "print('done')\n",
        ]
        py_file = tmp_path / "tool.py"
        py_file.write_text("".join(lines), encoding="utf-8")
        # Need SKILL.md for scanner but we use scan_all_files directly
        rules = load_default_rules()
        findings, _, _, suppressed = scan_all_files([py_file], tmp_path, rules)

        # No EXEC-002 finding for line 5
        exec002_line5 = [f for f in findings if f.rule_id == "EXEC-002" and f.line == 5]
        assert exec002_line5 == [], f"EXEC-002 on line 5 should be suppressed, got: {exec002_line5}"
        # suppressed_count reflects the suppression
        assert suppressed >= 1

    def test_other_findings_on_same_line_unaffected(self, tmp_path: Path) -> None:
        """Suppressing one rule does not suppress other rules on same line."""
        code = "eval(user_input)  # noqa: PI-001\n"
        py_file = tmp_path / "tool.py"
        py_file.write_text(code, encoding="utf-8")

        rules = load_default_rules()
        findings, _, _, _suppressed = scan_all_files([py_file], tmp_path, rules)

        # EXEC-002 should NOT be suppressed (only PI-001 was noqa'd)
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1, "EXEC-002 should still fire"
