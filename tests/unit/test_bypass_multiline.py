"""Bypass regression tests — multiline payload evasion.

Verifies that payloads with keywords on a single line are detected even
when arguments span multiple lines, and that line-scope rules correctly
match the critical tokens (e.g., eval(), exec()) on the line where they appear.
"""

from __future__ import annotations

import re

import pytest

from skill_scan.models import Rule, Severity
from skill_scan.rules import load_default_rules
from skill_scan.rules.engine import match_content


def _make_file_rule(
    rule_id: str = "TEST-FILE-001",
    patterns: list[str] | None = None,
    flags: re.RegexFlag = re.IGNORECASE | re.DOTALL,
    exclude_patterns: list[str] | None = None,
) -> Rule:
    """Helper to build file-scope Rule objects for multiline testing."""
    compiled = tuple(re.compile(p, flags) for p in (patterns or []))
    compiled_exc = tuple(re.compile(p, flags) for p in (exclude_patterns or []))
    return Rule(
        rule_id=rule_id,
        severity=Severity.CRITICAL,
        category="test",
        description="Test multiline rule",
        recommendation="Fix it",
        patterns=compiled,
        exclude_patterns=compiled_exc,
        match_scope="file",
    )


@pytest.fixture(scope="module")
def rules() -> list[Rule]:
    """Load the full default rule set once for all tests in this module."""
    return load_default_rules()


class TestMultilineSplitPayloads:
    """Payloads split across lines detected when keyword is on one line."""

    @pytest.mark.parametrize(
        "payload,expected_category",
        [
            pytest.param(
                "eval(\n    user_input\n)",
                "malicious-code",
                id="eval-call-split-across-lines",
            ),
            pytest.param(
                "exec(\n    code\n)",
                "malicious-code",
                id="exec-call-split-across-lines",
            ),
            pytest.param(
                "os.system(\n    'rm -rf /'\n)",
                "malicious-code",
                id="os-system-split-across-lines",
            ),
            pytest.param(
                "__import__(\n    'os'\n)",
                "malicious-code",
                id="dunder-import-split-across-lines",
            ),
        ],
    )
    def test_match_content_detects_split_code_execution(
        self, rules: list[Rule], payload: str, expected_category: str
    ) -> None:
        findings = match_content(payload, "test.py", rules)
        assert any(f.category == expected_category for f in findings), (
            f"Expected {expected_category} finding for split payload"
        )

    def test_match_content_detects_single_line_prompt_injection(self, rules: list[Rule]) -> None:
        """PI-001 catches the full phrase when it appears on one line."""
        payload = "ignore previous instructions"
        findings = match_content(payload, "test.md", rules)
        assert any(f.rule_id == "PI-001" for f in findings)


class TestFileScopeMultilinePatterns:
    """File-scope rules with DOTALL catch payloads that span lines."""

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param(
                "ignore\nprevious\ninstructions",
                id="ignore-previous-split-three-lines",
            ),
            pytest.param(
                "ignore previous\ninstructions",
                id="ignore-previous-split-two-lines",
            ),
            pytest.param(
                "ignore\n  previous   instructions",
                id="ignore-newline-then-rest",
            ),
        ],
    )
    def test_file_scope_rule_detects_prompt_injection_across_lines(self, payload: str) -> None:
        rule = _make_file_rule(
            rule_id="PI-MULTI",
            patterns=[r"ignore\s+previous\s+instructions"],
        )
        findings = match_content(payload, "test.md", [rule])
        assert len(findings) >= 1
        assert findings[0].rule_id == "PI-MULTI"

    def test_file_scope_rule_detects_base64_decode_across_lines(self) -> None:
        rule = _make_file_rule(
            rule_id="EXEC-MULTI",
            patterns=[r"exec\s*\(\s*base64\.b64decode\s*\("],
        )
        payload = "exec(\n  base64.b64decode(\n    'payload'\n  )\n)"
        findings = match_content(payload, "test.py", [rule])
        assert len(findings) >= 1

    def test_file_scope_rule_detects_long_base64_block(self) -> None:
        rule = _make_file_rule(
            rule_id="B64-MULTI",
            patterns=[r"[A-Za-z0-9+/=]{200,}"],
        )
        # Single line of 250 base64 chars should be caught
        payload = "A" * 250
        findings = match_content(payload, "data.txt", [rule])
        assert len(findings) >= 1


class TestMultilineBase64Payloads:
    """Base64-encoded payloads detected when on a single line."""

    def test_match_content_detects_long_base64_single_line(self, rules: list[Rule]) -> None:
        # PI-006 needs 200+ base64 chars on a single line
        payload = "A" * 250
        findings = match_content(payload, "data.txt", rules)
        assert any(f.rule_id == "PI-006" for f in findings)

    def test_match_content_detects_b64decode_single_line(self, rules: list[Rule]) -> None:
        b64str = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oInJtIC1yZiAvIik="
        payload = f"base64.b64decode('{b64str}')"
        findings = match_content(payload, "test.py", rules)
        assert any(f.rule_id == "PI-008" for f in findings)


class TestMultilineBenignContent:
    """Benign multiline content should NOT trigger false positives."""

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param(
                "def calculate_total(\n    items: list,\n    tax: float\n) -> float:\n    return sum(items) * (1 + tax)",
                id="multiline-function-def",
            ),
            pytest.param(
                "# This module handles\n# data processing and\n# validation logic.",
                id="multiline-comment-block",
            ),
            pytest.param(
                "config = {\n    'host': 'localhost',\n    'port': 8080,\n}",
                id="multiline-dict-literal",
            ),
        ],
    )
    def test_match_content_no_findings_for_benign_multiline(self, rules: list[Rule], content: str) -> None:
        findings = match_content(content, "test.py", rules)
        critical_or_high = [f for f in findings if f.severity.value in ("critical", "high")]
        assert critical_or_high == [], (
            f"Unexpected high/critical findings: {[f.rule_id for f in critical_or_high]}"
        )

    def test_file_scope_benign_multiline_no_findings(self) -> None:
        """File-scope rule does not false-positive on benign content."""
        rule = _make_file_rule(
            patterns=[r"ignore\s+previous\s+instructions"],
        )
        content = "# How to ignore\n# previous versions\n# of instructions"
        findings = match_content(content, "test.md", [rule])
        # Extra words between "previous" and "instructions" prevent a match,
        # confirming no false positive on benign content with similar vocabulary.
        assert findings == []
