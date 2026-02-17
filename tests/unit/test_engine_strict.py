"""Unit tests for strict exclude mode — piggyback suppression hardening.

Tests verify that exclude_mode="strict" prevents piggybacking attacks where
an attacker places an exclude pattern (e.g., comment) on the same line as
malicious code but in a non-overlapping region, attempting to suppress detection.
"""

from __future__ import annotations

from skill_scan.rules.engine import match_file, match_line
from tests.unit.rule_helpers import make_rule


class TestStrictModeMatchLine:
    """Tests for match_line with exclude_mode=strict."""

    def test_piggyback_suppression_blocked_comment_after_eval(self) -> None:
        """Strict mode detects when exclude pattern is in a comment, not overlapping."""
        rule = make_rule(
            patterns=[r"\beval\("],
            exclude_patterns=["never use eval"],
            exclude_mode="strict",
        )

        findings = match_line("eval(code) # never use eval", 1, "test.py", [rule])

        assert len(findings) == 1
        assert findings[0].matched_text == "eval("

    def test_legitimate_exclusion_still_works_safe_eval(self) -> None:
        """Strict mode suppresses when exclude overlaps with primary match."""
        rule = make_rule(
            patterns=[r"\beval\b"],
            exclude_patterns=["safe_eval"],
            exclude_mode="strict",
        )

        findings = match_line("safe_eval(code)", 1, "test.py", [rule])

        assert findings == []

    def test_no_exclude_match_detects(self) -> None:
        """Strict mode detects when exclude pattern doesn't match at all."""
        rule = make_rule(
            patterns=[r"\beval\("],
            exclude_patterns=["safe_eval"],
            exclude_mode="strict",
        )

        findings = match_line("eval(code)", 1, "test.py", [rule])

        assert len(findings) == 1
        assert findings[0].matched_text == "eval("

    def test_default_mode_backwards_compat_piggyback_suppressed(self) -> None:
        """Default mode (existing behavior) suppresses when exclude matches anywhere."""
        rule = make_rule(
            patterns=[r"\beval\("],
            exclude_patterns=["never use eval"],
            exclude_mode="default",
        )

        findings = match_line("eval(code) # never use eval", 1, "test.py", [rule])

        assert findings == []

    def test_multiple_excludes_one_overlapping_suppressed(self) -> None:
        """Multiple excludes: if one overlaps, finding is suppressed."""
        rule = make_rule(
            patterns=[r"\beval\b"],
            exclude_patterns=["safe_eval", "never use eval"],
            exclude_mode="strict",
        )

        findings = match_line("safe_eval(code) # never use eval", 1, "test.py", [rule])

        assert findings == []

    def test_multiple_excludes_none_overlapping_detected(self) -> None:
        """Multiple excludes: if none overlap, finding is detected."""
        rule = make_rule(
            patterns=[r"\beval\("],
            exclude_patterns=["avoid eval", "never eval"],
            exclude_mode="strict",
        )

        findings = match_line("eval(code) # avoid eval", 1, "test.py", [rule])

        assert len(findings) == 1
        assert findings[0].matched_text == "eval("

    def test_strict_mode_partial_overlap_before_primary_suppressed(self) -> None:
        """Exclude starting before primary match with overlap still suppresses."""
        rule = make_rule(
            patterns=[r"danger"],
            exclude_patterns=["safe_danger"],
            exclude_mode="strict",
        )

        findings = match_line("safe_danger_zone", 1, "test.py", [rule])

        assert findings == []

    def test_strict_mode_partial_overlap_after_primary_suppressed(self) -> None:
        """Exclude ending after primary match with overlap still suppresses."""
        rule = make_rule(
            patterns=[r"danger"],
            exclude_patterns=["danger_safe"],
            exclude_mode="strict",
        )

        findings = match_line("danger_safe", 1, "test.py", [rule])

        assert findings == []

    def test_strict_mode_adjacent_but_not_overlapping_detected(self) -> None:
        """Exclude immediately after primary match but no overlap = detect."""
        rule = make_rule(
            patterns=[r"\beval"],
            exclude_patterns=[r"\(code\)"],
            exclude_mode="strict",
        )

        findings = match_line("eval(code)", 1, "test.py", [rule])

        assert len(findings) == 1


class TestStrictModeMatchFile:
    """Tests for match_file with exclude_mode=strict."""

    def test_file_scope_strict_mode_piggyback_blocked(self) -> None:
        """File-scope rule detects when exclude comment doesn't overlap."""
        rule = make_rule(
            patterns=[r"\beval\("],
            exclude_patterns=["never use eval"],
            match_scope="file",
            exclude_mode="strict",
        )
        content = "eval(code) # never use eval"

        findings = match_file(content, "test.py", [rule])

        assert len(findings) == 1
        assert findings[0].line == 1

    def test_file_scope_strict_mode_legitimate_exclusion(self) -> None:
        """File-scope rule suppresses when exclude overlaps."""
        rule = make_rule(
            patterns=[r"\beval\b"],
            exclude_patterns=["safe_eval"],
            match_scope="file",
            exclude_mode="strict",
        )

        findings = match_file("safe_eval(code)", "test.py", [rule])

        assert findings == []

    def test_file_scope_strict_mode_multiline_piggyback(self) -> None:
        """File-scope strict mode with pattern and exclude on same line."""
        rule = make_rule(
            patterns=[r"\beval\("],
            exclude_patterns=["reviewed"],
            match_scope="file",
            exclude_mode="strict",
        )
        content = "line 1\neval(x) # reviewed\nline 3"

        findings = match_file(content, "test.py", [rule])

        assert len(findings) == 1
        assert findings[0].line == 2

    def test_file_scope_strict_mode_exclude_on_different_line(self) -> None:
        """File-scope strict mode: exclude on different line doesn't suppress."""
        rule = make_rule(
            patterns=[r"\beval\("],
            exclude_patterns=["safe context"],
            match_scope="file",
            exclude_mode="strict",
        )
        content = "# safe context\neval(code)"

        findings = match_file(content, "test.py", [rule])

        assert len(findings) == 1
        assert findings[0].line == 2
