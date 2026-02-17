"""Tests for normalization integration in the matching engine."""

from __future__ import annotations

import re

from skill_scan.models import Rule, Severity
from skill_scan.rules.engine import match_content, match_line


def _make_rule(
    rule_id: str = "TEST-001",
    severity: Severity = Severity.CRITICAL,
    category: str = "malicious-code",
    description: str = "Test rule",
    recommendation: str = "Fix it",
    patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
    flags: re.RegexFlag = re.RegexFlag(0),  # noqa: B008
    match_scope: str = "line",
) -> Rule:
    """Helper to build Rule objects for testing."""
    compiled = tuple(re.compile(p, flags) for p in (patterns or []))
    compiled_exc = tuple(re.compile(p, flags) for p in (exclude_patterns or []))
    return Rule(
        rule_id=rule_id,
        severity=severity,
        category=category,
        description=description,
        recommendation=recommendation,
        patterns=compiled,
        exclude_patterns=compiled_exc,
        match_scope=match_scope,
    )


class TestNormalizationDetectsObfuscated:
    """Normalization in match_content catches evasion via invisible chars."""

    def test_eval_with_zero_width_spaces_detected(self) -> None:
        rule = _make_rule(
            rule_id="EXEC-002",
            patterns=[r"(?i)\beval\s*\("],
        )
        # "eval(" with ZWSP between each letter
        content = "e\u200bv\u200ba\u200bl("
        findings = match_content(content, "test.py", [rule])
        assert len(findings) >= 1
        assert any(f.rule_id == "EXEC-002" for f in findings)

    def test_import_with_zero_width_chars_detected(self) -> None:
        rule = _make_rule(
            rule_id="EXEC-006",
            patterns=[r"(?i)\b__import__\s*\("],
        )
        # "__import__(" with ZWNJ between letters
        content = "_\u200c_import_\u200c_('os')"
        findings = match_content(content, "test.py", [rule])
        assert len(findings) >= 1
        assert any(f.rule_id == "EXEC-006" for f in findings)

    def test_pickle_loads_with_non_breaking_spaces_detected(self) -> None:
        rule = _make_rule(
            rule_id="EXEC-007",
            patterns=[r"(?i)\bpickle\.loads?\s*\("],
        )
        # "pickle.loads(" with NBSP before the opening paren
        content = "pickle.loads\u00a0(data)"
        findings = match_content(content, "test.py", [rule])
        assert len(findings) >= 1
        assert any(f.rule_id == "EXEC-007" for f in findings)

    def test_exec_with_word_joiner_detected(self) -> None:
        rule = _make_rule(
            rule_id="EXEC-002",
            patterns=[r"(?i)\bexec\s*\("],
        )
        content = "e\u2060x\u2060e\u2060c(code)"
        findings = match_content(content, "test.py", [rule])
        assert len(findings) >= 1
        assert any(f.rule_id == "EXEC-002" for f in findings)

    def test_os_system_with_soft_hyphen_detected(self) -> None:
        rule = _make_rule(
            rule_id="EXEC-002",
            patterns=[r"(?i)\bos\.system\s*\("],
        )
        content = "o\u00ads.sy\u00adstem('rm -rf /')"
        findings = match_content(content, "test.py", [rule])
        assert len(findings) >= 1

    def test_eval_with_ideographic_space_detected(self) -> None:
        rule = _make_rule(
            rule_id="EXEC-002",
            patterns=[r"(?i)\beval\s*\("],
        )
        # "eval (" where the space is an ideographic space
        content = "eval\u3000(user_input)"
        findings = match_content(content, "test.py", [rule])
        assert len(findings) >= 1


class TestNormalizationNoRegression:
    """Clean content produces the same findings with normalization enabled."""

    def test_clean_eval_still_detected(self) -> None:
        rule = _make_rule(patterns=[r"(?i)\beval\s*\("])
        findings = match_content("eval(x)", "test.py", [rule])
        assert len(findings) == 1

    def test_clean_text_no_false_positives(self) -> None:
        rule = _make_rule(patterns=[r"(?i)\beval\s*\("])
        findings = match_content("print('hello')", "test.py", [rule])
        assert findings == []

    def test_no_duplicate_when_original_already_matches(self) -> None:
        rule = _make_rule(patterns=[r"(?i)\beval\s*\("])
        # Clean line that matches -- normalization is a no-op, so no dup
        findings = match_content("eval(x)", "test.py", [rule])
        assert len(findings) == 1
        assert findings[0].rule_id == "TEST-001"


class TestNormalizationDedup:
    """Deduplication: same rule_id on same line is not reported twice."""

    def test_no_duplicate_when_both_original_and_normalized_match(self) -> None:
        # A rule that matches both the obfuscated and normalized forms
        # because the pattern is broad enough to match with zero-width chars
        rule = _make_rule(
            rule_id="BROAD-001",
            patterns=["eval"],
        )
        # "eval" with ZWSP -- original contains "eval" substring after
        # stripping, but the original line also contains e-ZWSP-val which
        # does NOT match "eval" literally. Only the normalized form matches.
        content = "e\u200bval"
        findings = match_content(content, "test.py", [rule])
        # Only one finding (from normalized pass)
        assert len(findings) == 1

    def test_multiple_rules_each_deduplicated_independently(self) -> None:
        rule1 = _make_rule(rule_id="R-001", patterns=[r"\beval\b"])
        rule2 = _make_rule(rule_id="R-002", patterns=[r"\bexec\b"])
        content = "e\u200bval and e\u200bxec"
        findings = match_content(content, "test.py", [rule1, rule2])
        rule_ids = [f.rule_id for f in findings]
        assert rule_ids.count("R-001") == 1
        assert rule_ids.count("R-002") == 1


class TestFileScopeNormalization:
    """File-scope rules also benefit from normalization."""

    def test_file_scope_rule_catches_obfuscated_multiline(self) -> None:
        rule = _make_rule(
            rule_id="FILE-001",
            patterns=[r"eval\(\s*\n\s*code"],
            match_scope="file",
        )
        # "eval(\n    code)" with zero-width chars in "eval"
        content = "e\u200bval(\n    code)"
        findings = match_content(content, "test.py", [rule])
        assert len(findings) >= 1
        assert any(f.rule_id == "FILE-001" for f in findings)

    def test_file_scope_dedup_same_rule_same_line(self) -> None:
        rule = _make_rule(
            rule_id="FILE-001",
            patterns=["target"],
            match_scope="file",
        )
        # "target" on line 2 -- clean content, normalization is no-op
        content = "line1\ntarget here\nline3"
        findings = match_content(content, "test.py", [rule])
        assert len(findings) == 1

    def test_file_scope_preserves_newlines_during_normalization(self) -> None:
        rule = _make_rule(
            rule_id="FILE-001",
            patterns=[r"line1\nline2"],
            match_scope="file",
        )
        content = "line1\u200b\nline2"
        findings = match_content(content, "test.py", [rule])
        # After normalization: "line1\nline2" -- should match
        assert len(findings) >= 1


class TestMatchLineNotAffected:
    """match_line itself does not normalize -- only match_content does."""

    def test_match_line_does_not_normalize(self) -> None:
        rule = _make_rule(patterns=[r"\beval\b"])
        # Obfuscated line -- match_line alone should NOT find it
        findings = match_line("e\u200bval", 1, "test.py", [rule])
        assert findings == []
