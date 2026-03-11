"""Tests for obfuscation detection rules (OBFS-002..005)."""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_scan.models import Rule, Severity
from skill_scan.rules.loader import load_rules
from tests.unit.rule_helpers import match_rule, rule_findings

RULES_PATH = (
    Path(__file__).resolve().parents[2] / "src" / "skill_scan" / "rules" / "data" / "obfuscation.toml"
)


@pytest.fixture(scope="module")
def rules() -> list[Rule]:
    """Load obfuscation rules once for the module."""
    return load_rules(RULES_PATH)


class TestObfs002ConsecutivePercentEncoding:
    """Tests for OBFS-002 -- 3+ consecutive %XX bytes."""

    @pytest.mark.parametrize(
        "line",
        [
            "%48%65%6C",
            "%48%65%6C%6C%6F",
            "http://evil.com/%2e%2e%2f%2e%2e%2f",
            "path=%48%65%6C%6C%6F%20%57%6F%72%6C%64",
            "%00%00%00",
            "%FF%FE%FD",
        ],
    )
    def test_detects_consecutive_encoding(self, rules: list[Rule], line: str) -> None:
        findings = rule_findings(line, rules, "OBFS-002")
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].category == "obfuscation"

    @pytest.mark.parametrize(
        "line",
        [
            "%20",
            "a single %20 space",
            "%48%65",
            "just two %48%65 bytes",
            "normal text without encoding",
            "100% complete and 50% done",
        ],
    )
    def test_allows_non_matching(self, rules: list[Rule], line: str) -> None:
        assert not match_rule(line, rules, "OBFS-002")


class TestObfs003DoubleEncoding:
    """Tests for OBFS-003 -- double URL-encoding (%25XX)."""

    @pytest.mark.parametrize(
        "line",
        [
            "%2541",
            "%252F",
            "http://example.com/%2541dmin",
            "path=%2520value",
            "%25FF",
            "%2500",
        ],
    )
    def test_detects_double_encoding(self, rules: list[Rule], line: str) -> None:
        findings = rule_findings(line, rules, "OBFS-003")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].category == "obfuscation"

    @pytest.mark.parametrize(
        "line",
        [
            "%41",
            "normal %20 encoding",
            "%25 alone",
            "25% off sale",
            "plain text no encoding",
        ],
    )
    def test_allows_non_matching(self, rules: list[Rule], line: str) -> None:
        assert not match_rule(line, rules, "OBFS-003")


class TestObfs004UnreservedCharEncoding:
    """Tests for OBFS-004 -- unnecessarily encoded RFC 3986 unreserved chars."""

    @pytest.mark.parametrize(
        "line,desc",
        [
            ("%41", "uppercase A"),
            ("%5A", "uppercase Z"),
            ("%5a", "uppercase Z lowercase hex"),
            ("%61", "lowercase a"),
            ("%7A", "lowercase z"),
            ("%7a", "lowercase z lowercase hex"),
            ("%30", "digit 0"),
            ("%39", "digit 9"),
            ("%42", "uppercase B"),
            ("%4F", "uppercase O"),
            ("%69", "lowercase i"),
        ],
    )
    def test_detects_unreserved_encoding(self, rules: list[Rule], line: str, desc: str) -> None:
        findings = rule_findings(line, rules, "OBFS-004")
        assert len(findings) == 1, f"Should detect encoded unreserved char: {desc}"
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].category == "obfuscation"

    @pytest.mark.parametrize(
        "line,desc",
        [
            ("%2F", "reserved slash"),
            ("%3A", "reserved colon"),
            ("%3F", "reserved question mark"),
            ("%23", "reserved hash"),
            ("%5B", "reserved left bracket"),
            ("%5C", "reserved backslash"),
            ("%5D", "reserved right bracket"),
            ("%5E", "reserved caret"),
            ("%5F", "reserved underscore"),
            ("%60", "reserved backtick"),
            ("%20", "space"),
            ("%0A", "newline"),
            ("%7B", "left brace"),
            ("%7F", "DEL control char"),
            ("plain text", "no encoding at all"),
        ],
    )
    def test_rejects_reserved_and_special(self, rules: list[Rule], line: str, desc: str) -> None:
        assert not match_rule(line, rules, "OBFS-004"), f"Should NOT match reserved/special char: {desc}"


class TestObfs005UnicodeEscapes:
    """Tests for OBFS-005 -- 3+ consecutive \\uXXXX / \\UXXXXXXXX escapes."""

    @pytest.mark.parametrize(
        "line,desc",
        [
            (r"\u0048\u0065\u006C", "three \\uXXXX"),
            (r"\u0048\u0065\u006C\u006C\u006F", "five \\uXXXX"),
            (r"\U00000048\U00000065\U0000006C", "three \\UXXXXXXXX"),
            (r"\u0048\U00000065\u006C", "mixed \\u and \\U (R-ADV003)"),
            (r"\U00000048\u0065\U0000006C", "mixed \\U and \\u (R-ADV003)"),
            (r"\u0041\u0042\U00000043\u0044", "four mixed escapes"),
            ("prefix" + r"\u0048\u0065\u006C" + "suffix", "adjacent text (R-ADV003)"),
            ("var x = " + r'"\u0048\u0065\u006C"', "in string assignment"),
            (r"\u0000\u0000\u0000", "null chars escaped"),
            (r"\uFFFF\uFFFE\uFFFD", "high code points"),
        ],
    )
    def test_detects_unicode_escapes(self, rules: list[Rule], line: str, desc: str) -> None:
        findings = rule_findings(line, rules, "OBFS-005")
        assert len(findings) == 1, f"Should detect: {desc}"
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].category == "obfuscation"

    @pytest.mark.parametrize(
        "line,desc",
        [
            (r"\u0048", "single \\uXXXX"),
            (r"\u0048\u0065", "two \\uXXXX (below threshold)"),
            (r"\U00000048", "single \\UXXXXXXXX"),
            (r"\U00000048\U00000065", "two \\UXXXXXXXX"),
            (r"\u0048\U00000065", "one of each (two total)"),
            ("normal text without escapes", "no escapes"),
            ("unicode is great", "word unicode, no escapes"),
            (r"\u004", "truncated \\u (only 3 hex digits)"),
            (r"\U0000004", "truncated \\U (only 7 hex digits)"),
        ],
    )
    def test_rejects_non_matching(self, rules: list[Rule], line: str, desc: str) -> None:
        assert not match_rule(line, rules, "OBFS-005"), f"Should NOT match: {desc}"


class TestObfuscationRuleMetadata:
    """Verify rule metadata is correct."""

    def test_rule_count(self, rules: list[Rule]) -> None:
        assert len(rules) == 4

    def test_rule_ids(self, rules: list[Rule]) -> None:
        ids = {r.rule_id for r in rules}
        assert ids == {"OBFS-002", "OBFS-003", "OBFS-004", "OBFS-005"}

    def test_categories_all_obfuscation(self, rules: list[Rule]) -> None:
        for rule in rules:
            assert rule.category == "obfuscation"
