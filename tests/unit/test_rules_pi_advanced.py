"""Tests for advanced prompt injection rules (PI-008, PI-009)."""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_scan.models import Finding, Rule, Severity
from skill_scan.rules.engine import match_line
from skill_scan.rules.loader import load_rules

RULES_PATH = (
    Path(__file__).resolve().parents[2] / "src" / "skill_scan" / "rules" / "data" / "prompt_injection.toml"
)


@pytest.fixture(scope="module")
def rules() -> list[Rule]:
    """Load prompt injection rules once for the module."""
    return load_rules(RULES_PATH)


def _match(line: str, rules: list[Rule], rule_id: str) -> bool:
    findings = match_line(line, 1, "test.md", rules)
    return any(f.rule_id == rule_id for f in findings)


def _findings(line: str, rules: list[Rule], rule_id: str) -> list[Finding]:
    return [f for f in match_line(line, 1, "test.md", rules) if f.rule_id == rule_id]


# -- PI-008: Short base64 decode patterns ------------------------------------


class TestPI008Base64Decode:
    """Tests for PI-008 -- base64-encoded payload in decode call."""

    @pytest.mark.parametrize(
        "line",
        [
            "b64decode('cHJpbnQoJ2hlbGxvJyk=')",
            "atob('Y29uc29sZS5sb2coJ3B3bmVkJyk=')",
            "base64.decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0=')",
            "base64_decode('ZXZhbChiYXNlNjRfZGVjb2Rl')",
            'b64decode("cHJpbnQoJ2hlbGxvIHdvcmxkJyk=")',
            "ATOB('Y29uc29sZS5sb2coInB3bmVkIik=')",
        ],
    )
    def test_detects_base64_decode(self, rules: list[Rule], line: str) -> None:
        findings = _findings(line, rules, "PI-008")
        assert len(findings) >= 1
        assert findings[0].severity == Severity.MEDIUM

    @pytest.mark.parametrize(
        "line",
        [
            "b64decode('abc')",
            "# b64decode('cHJpbnQoJ2hlbGxvJyk=')",
            "jwt payload = b64decode('eyJhbGciOiJIUzI1NiJ9aaa')",
            "token = atob('ZXlKaGJHY2lPaUpJVXpJaaa')",
            "config = b64decode('c29tZUNvbmZpZ1ZhbHVlYQ==')",
            "assert b64decode('cHJpbnQoJ2hlbGxvJyk=') == expected",
        ],
    )
    def test_allows_safe_base64(self, rules: list[Rule], line: str) -> None:
        assert not _match(line, rules, "PI-008")


# -- PI-009: Greek homoglyph detection --------------------------------------


class TestPI009GreekHomoglyphs:
    """Tests for PI-009 -- Greek characters adjacent to Latin (homoglyph attack)."""

    @pytest.mark.parametrize(
        "line",
        [
            "e\u03b1vil",
            "p\u03b1yload",
            "\u03b1dmin",
            "r\u03bfot",
            "ex\u03b5c",
        ],
    )
    def test_detects_greek_homoglyphs(self, rules: list[Rule], line: str) -> None:
        findings = _findings(line, rules, "PI-009")
        assert len(findings) >= 1
        assert findings[0].severity == Severity.MEDIUM

    @pytest.mark.parametrize(
        "line",
        [
            "normal english text",
            "admin root exec payload",
            "function call with arguments",
        ],
    )
    def test_allows_pure_latin_text(self, rules: list[Rule], line: str) -> None:
        assert not _match(line, rules, "PI-009")
