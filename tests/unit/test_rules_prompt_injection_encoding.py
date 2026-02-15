"""Unit tests for PI-006 steganographic encoding detection.

Tests verify that base64, hex, and other encoded payloads are detected
while legitimate data URIs and BOM sequences are excluded.
"""

from __future__ import annotations

import pytest

from skill_scan.models import Rule, Severity
from skill_scan.rules import load_default_rules, match_line
from skill_scan.scanner import _is_path_excluded


@pytest.fixture(scope="module")
def pi_rules() -> list[Rule]:
    """Load all prompt injection rules once for the test module."""
    all_rules = load_default_rules()
    return [r for r in all_rules if r.rule_id.startswith("PI-")]


class TestPI006SteganographicEncoding:
    """Tests for PI-006 -- Steganographic encoding detection."""

    @pytest.mark.parametrize(
        "malicious_input",
        [
            "A" * 200,
            "QmFzZTY0RW5jb2RlZFBheWxvYWQ=" * 8,
            "VGhpc0lzQVZlcnlMb25nQmFzZTY0U3RyaW5n" * 8,
        ],
    )
    def test_pi006_detects_base64_encoded_content(self, pi_rules: list[Rule], malicious_input: str) -> None:
        rule = [r for r in pi_rules if r.rule_id == "PI-006"]
        findings = match_line(malicious_input, 1, "test.md", rule)
        assert len(findings) >= 1
        assert findings[0].rule_id == "PI-006"
        assert findings[0].severity == Severity.MEDIUM

    @pytest.mark.parametrize(
        "safe_input",
        [
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA",
            "data:font/woff2;base64,d09GMgABAAAAABBMAA0AAAAAGVQAA",
        ],
    )
    def test_pi006_excludes_legitimate_base64_data_uris(self, pi_rules: list[Rule], safe_input: str) -> None:
        rule = [r for r in pi_rules if r.rule_id == "PI-006"]
        findings = match_line(safe_input, 1, "test.md", rule)
        assert findings == []

    def test_pi006_allows_base64_under_200_chars(self, pi_rules: list[Rule]) -> None:
        rule = [r for r in pi_rules if r.rule_id == "PI-006"]
        # 199-char base64 string should not trigger
        findings = match_line("A" * 199, 1, "test.md", rule)
        assert findings == []

    def test_pi006_allows_short_base64_strings(self, pi_rules: list[Rule]) -> None:
        rule = [r for r in pi_rules if r.rule_id == "PI-006"]
        # Short base64 strings should not trigger
        findings = match_line("dGVzdA==", 1, "test.md", rule)
        assert findings == []

    def test_pi006_detects_hex_escape_sequences(self, pi_rules: list[Rule]) -> None:
        rule = [r for r in pi_rules if r.rule_id == "PI-006"]
        # Four or more consecutive \xNN hex escapes should trigger
        findings = match_line(r"\x69\x67\x6e\x6f\x72\x65", 1, "test.md", rule)
        assert len(findings) >= 1
        assert findings[0].rule_id == "PI-006"
        assert findings[0].severity == Severity.MEDIUM

    @pytest.mark.parametrize(
        "bom_input",
        [
            "\xef\xbb\xbf",
            "\xfe\xff",
            "\xff\xfe",
        ],
    )
    def test_pi006_excludes_bom_sequences(self, pi_rules: list[Rule], bom_input: str) -> None:
        rule = [r for r in pi_rules if r.rule_id == "PI-006"]
        findings = match_line(bom_input, 1, "test.md", rule)
        assert findings == []


class TestPI006PathExclusions:
    """Tests for PI-006 path-based exclusions."""

    def test_pi006_excluded_for_test_directory(self, pi_rules: list[Rule]) -> None:
        rule = next(r for r in pi_rules if r.rule_id == "PI-006")
        assert _is_path_excluded("tests/unit/test_example.py", rule) is True

    def test_pi006_excluded_for_test_file(self, pi_rules: list[Rule]) -> None:
        rule = next(r for r in pi_rules if r.rule_id == "PI-006")
        assert _is_path_excluded("test_example.py", rule) is True

    def test_pi006_not_excluded_for_source_files(self, pi_rules: list[Rule]) -> None:
        rule = next(r for r in pi_rules if r.rule_id == "PI-006")
        assert _is_path_excluded("src/skill_scan/rules/engine.py", rule) is False
