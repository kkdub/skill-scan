"""Bypass regression tests — exclusion pattern abuse.

Verifies that exclusion patterns cannot be piggybacked to suppress
real attacks, confirming P0 strict-mode hardening works correctly.
"""

from __future__ import annotations

import re

import pytest

from skill_scan.models import Rule, Severity
from skill_scan.rules.engine import match_content, match_line


def _make_rule(
    rule_id: str = "TEST-001",
    patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
    flags: re.RegexFlag = re.RegexFlag(0),  # noqa: B008
    match_scope: str = "line",
    exclude_mode: str = "default",
) -> Rule:
    """Helper to build Rule objects for testing."""
    compiled = tuple(re.compile(p, flags) for p in (patterns or []))
    compiled_exc = tuple(re.compile(p, flags) for p in (exclude_patterns or []))
    return Rule(
        rule_id=rule_id,
        severity=Severity.CRITICAL,
        category="malicious-code",
        description="Test rule",
        recommendation="Fix it",
        patterns=compiled,
        exclude_patterns=compiled_exc,
        match_scope=match_scope,
        exclude_mode=exclude_mode,
    )


class TestPiggybackSuppressionStrict:
    """Strict mode blocks piggybacked exclude patterns."""

    @pytest.mark.parametrize(
        "line,desc",
        [
            pytest.param(
                "eval(malicious_code) # never use eval",
                "comment-appended-exclude",
                id="comment-after-attack",
            ),
            pytest.param(
                "exec(payload); # avoid exec in production",
                "semicolon-then-exclude-comment",
                id="semicolon-then-comment",
            ),
            pytest.param(
                "eval(data) /* do not use eval */",
                "block-comment-exclude",
                id="block-comment-piggyback",
            ),
        ],
    )
    def test_match_line_strict_detects_piggybacked_comment(self, line: str, desc: str) -> None:
        rule = _make_rule(
            patterns=[r"\beval\(", r"\bexec\("],
            exclude_patterns=["never use eval", "avoid exec", "do not use eval"],
            exclude_mode="strict",
        )
        findings = match_line(line, 1, "test.py", [rule])
        assert len(findings) >= 1, f"Strict mode should detect: {desc}"

    def test_match_content_strict_detects_piggyback_across_content(self) -> None:
        rule = _make_rule(
            patterns=[r"(?i)\beval\s*\("],
            exclude_patterns=["never use eval"],
            exclude_mode="strict",
        )
        content = "eval(user_input)  # never use eval"
        findings = match_content(content, "test.py", [rule])
        assert len(findings) >= 1

    def test_match_line_strict_detects_exclude_on_far_side(self) -> None:
        """Exclude text placed far from the match region is not suppressive."""
        rule = _make_rule(
            patterns=[r"\beval\("],
            exclude_patterns=["safe_eval"],
            exclude_mode="strict",
        )
        line = "eval(code)                                    safe_eval"
        findings = match_line(line, 1, "test.py", [rule])
        assert len(findings) >= 1


class TestDefaultModeBackwardsCompat:
    """Default exclude mode suppresses when exclude matches anywhere on line."""

    @pytest.mark.parametrize(
        "line",
        [
            pytest.param(
                "eval(code) # never use eval",
                id="exclude-in-trailing-comment",
            ),
            pytest.param(
                "# never use eval -- eval(code)",
                id="exclude-before-attack",
            ),
        ],
    )
    def test_match_line_default_suppresses_piggybacked(self, line: str) -> None:
        rule = _make_rule(
            patterns=[r"\beval\("],
            exclude_patterns=["never use eval"],
            exclude_mode="default",
        )
        findings = match_line(line, 1, "test.py", [rule])
        assert findings == [], "Default mode should suppress when exclude matches"


class TestLegitimateExclusions:
    """Real exclusions should still suppress correctly in both modes."""

    @pytest.mark.parametrize(
        "mode",
        [
            pytest.param("strict", id="strict-mode"),
            pytest.param("default", id="default-mode"),
        ],
    )
    def test_match_line_overlapping_exclude_suppresses(self, mode: str) -> None:
        rule = _make_rule(
            patterns=[r"eval"],
            exclude_patterns=["safe_eval"],
            exclude_mode=mode,
        )
        findings = match_line("safe_eval(code)", 1, "test.py", [rule])
        assert findings == [], f"Overlapping exclude should suppress in {mode} mode"

    @pytest.mark.parametrize(
        "mode",
        [
            pytest.param("strict", id="strict-mode"),
            pytest.param("default", id="default-mode"),
        ],
    )
    def test_match_content_overlapping_exclude_suppresses(self, mode: str) -> None:
        rule = _make_rule(
            patterns=[r"eval"],
            exclude_patterns=["safe_eval"],
            exclude_mode=mode,
        )
        findings = match_content("result = safe_eval(data)", "test.py", [rule])
        assert findings == []

    def test_match_line_strict_partial_overlap_suppresses(self) -> None:
        """Exclude that partially overlaps the match region still suppresses."""
        rule = _make_rule(
            patterns=[r"danger"],
            exclude_patterns=["safe_danger"],
            exclude_mode="strict",
        )
        findings = match_line("safe_danger_zone", 1, "test.py", [rule])
        assert findings == []


class TestExclusionWithFileScope:
    """Exclusion behavior for file-scope rules."""

    def test_match_content_file_scope_strict_piggyback_blocked(self) -> None:
        rule = _make_rule(
            patterns=[r"\beval\("],
            exclude_patterns=["reviewed"],
            match_scope="file",
            exclude_mode="strict",
        )
        content = "line 1\neval(x) # reviewed\nline 3"
        findings = match_content(content, "test.py", [rule])
        assert len(findings) >= 1
        assert any(f.rule_id == "TEST-001" for f in findings)

    def test_match_content_file_scope_legit_exclude_suppresses(self) -> None:
        rule = _make_rule(
            patterns=[r"eval"],
            exclude_patterns=["safe_eval"],
            match_scope="file",
            exclude_mode="strict",
        )
        content = "line 1\nsafe_eval(x)\nline 3"
        findings = match_content(content, "test.py", [rule])
        assert findings == []

    def test_match_content_file_scope_default_piggyback_suppressed(self) -> None:
        """Default file-scope: exclude anywhere on match line suppresses."""
        rule = _make_rule(
            patterns=[r"\beval\("],
            exclude_patterns=["reviewed"],
            match_scope="file",
            exclude_mode="default",
        )
        content = "line 1\neval(x) # reviewed\nline 3"
        findings = match_content(content, "test.py", [rule])
        assert findings == []
