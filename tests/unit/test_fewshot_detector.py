"""Tests for few-shot prompt injection detector (_fewshot_pi.py).

Covers R003: Dedicated few-shot attack detector (2+ exchange pairs).
Covers R-IMP001: Existing PI-001..009 behavior unaffected.
"""

from __future__ import annotations

import re

from skill_scan.models import Finding, Rule, Severity
from skill_scan.rules._fewshot_pi import _fewshot_pi_findings
from tests.unit.rule_helpers import make_rule

_TWO_PAIRS = "User: q1?\nAssistant: a1\nUser: q2?\nAssistant: a2"


def _pi030_rule() -> Rule:
    """Create a PI-030 rule with patterns=[] for few-shot detection."""
    return make_rule(
        rule_id="PI-030",
        severity=Severity.CRITICAL,
        category="prompt-injection",
        description="Few-shot prompt injection attack detected",
        recommendation="Remove conversational exchange patterns",
        patterns=[],
    )


def _make_finding_stub(rule: Rule, file_path: str, line_num: int, match: re.Match[str]) -> Finding:
    """Test stub matching the make_finding callback signature."""
    return Finding(
        rule_id=rule.rule_id,
        severity=rule.severity,
        category=rule.category,
        file=file_path,
        line=line_num,
        matched_text=match.group()[:200],
        description=rule.description,
        recommendation=rule.recommendation,
    )


def _no_exclude(_line: str, _rule: Rule) -> bool:
    return False


def _always_exclude(_line: str, _rule: Rule) -> bool:
    return True


def _run_detector(content: str) -> list[Finding]:
    """Helper: run _fewshot_pi_findings on content and return findings."""
    rule = _pi030_rule()
    lines = content.split("\n")
    return _fewshot_pi_findings(
        lines,
        "test.md",
        [rule],
        [],
        _make_finding_stub,
        _no_exclude,
    )


# --- Zero exchanges: no finding ---


class TestNoExchanges:
    def test_empty_content(self) -> None:
        findings = _run_detector("")
        assert findings == []

    def test_plain_text(self) -> None:
        findings = _run_detector("This is just some normal text.\nNo attacks here.")
        assert findings == []

    def test_single_user_label_no_assistant(self) -> None:
        findings = _run_detector("User: Hello there\nSome other text")
        assert findings == []


# --- Single exchange (1 pair): no finding ---


class TestSingleExchange:
    def test_one_user_assistant_pair(self) -> None:
        content = "User: What is 2+2?\nAssistant: 4"
        findings = _run_detector(content)
        assert findings == []

    def test_one_human_ai_pair(self) -> None:
        content = "Human: What is 2+2?\nAI: 4"
        findings = _run_detector(content)
        assert findings == []

    def test_one_heading_pair(self) -> None:
        content = "### User\nWhat is 2+2?\n### Assistant\n4"
        findings = _run_detector(content)
        assert findings == []


# --- Two exchanges: finding fires ---


class TestTwoExchanges:
    def test_two_user_assistant_pairs(self) -> None:
        content = "User: What is 2+2?\nAssistant: 4\nUser: What is 3+3?\nAssistant: 6"
        findings = _run_detector(content)
        assert len(findings) == 1
        assert findings[0].rule_id == "PI-030"

    def test_two_human_ai_pairs(self) -> None:
        content = "Human: What is 2+2?\nAI: 4\nHuman: What is 3+3?\nAI: 6"
        findings = _run_detector(content)
        assert len(findings) == 1
        assert findings[0].rule_id == "PI-030"

    def test_two_heading_pairs(self) -> None:
        content = "### User\nWhat is 2+2?\n### Assistant\n4\n### User\nWhat is 3+3?\n### Assistant\n6"
        findings = _run_detector(content)
        assert len(findings) == 1
        assert findings[0].rule_id == "PI-030"


# --- Three+ exchanges: finding fires ---


class TestThreeOrMoreExchanges:
    def test_three_user_assistant_pairs(self) -> None:
        content = "User: q1?\nAssistant: a1\nUser: q2?\nAssistant: a2\nUser: q3?\nAssistant: a3"
        findings = _run_detector(content)
        assert len(findings) == 1
        assert findings[0].rule_id == "PI-030"

    def test_five_exchanges(self) -> None:
        pairs = [f"User: q{i}?\nAssistant: a{i}" for i in range(5)]
        content = "\n".join(pairs)
        findings = _run_detector(content)
        assert len(findings) == 1
        assert findings[0].rule_id == "PI-030"


# --- Mixed variant labels ---


class TestMixedVariants:
    def test_user_with_heading_assistant(self) -> None:
        content = "User: q1?\n### Assistant\na1\nUser: q2?\n### Assistant\na2"
        findings = _run_detector(content)
        assert len(findings) == 1
        assert findings[0].rule_id == "PI-030"

    def test_human_with_heading_user(self) -> None:
        content = "Human: q1?\nAI: a1\n### User\nq2?\n### Assistant\na2"
        findings = _run_detector(content)
        assert len(findings) == 1
        assert findings[0].rule_id == "PI-030"


# --- Finding metadata ---


class TestFindingMetadata:
    def test_finding_has_correct_category(self) -> None:
        findings = _run_detector(_TWO_PAIRS)
        assert len(findings) == 1
        assert findings[0].category == "prompt-injection"

    def test_finding_has_correct_severity(self) -> None:
        findings = _run_detector(_TWO_PAIRS)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_finding_file_path(self) -> None:
        findings = _run_detector(_TWO_PAIRS)
        assert len(findings) == 1
        assert findings[0].file == "test.md"


# --- PI-030 not in pi_rules: no crash ---


class TestMissingRule:
    def test_no_pi030_in_rules(self) -> None:
        """If PI-030 is not in the rule list, detector returns empty."""
        other_rule = make_rule(
            rule_id="PI-001",
            category="prompt-injection",
            patterns=[r"ignore previous"],
        )
        lines = _TWO_PAIRS.split("\n")
        findings = _fewshot_pi_findings(
            lines,
            "test.md",
            [other_rule],
            [],
            _make_finding_stub,
            _no_exclude,
        )
        assert findings == []


# --- Exclusion callback respected ---


class TestExclusion:
    def test_excluded_returns_empty(self) -> None:
        """If is_excluded returns True for the content, no finding produced."""
        findings = _fewshot_pi_findings(
            _TWO_PAIRS.split("\n"),
            "test.md",
            [_pi030_rule()],
            [],
            _make_finding_stub,
            _always_exclude,
        )
        assert findings == []


# --- Existing findings dedup ---


class TestExistingDedup:
    def test_already_reported_pi030_skipped(self) -> None:
        """If PI-030 already in existing findings, do not duplicate."""
        rule = _pi030_rule()
        lines = _TWO_PAIRS.split("\n")
        existing = [
            Finding(
                rule_id="PI-030",
                severity=Severity.HIGH,
                category="prompt-injection",
                file="test.md",
                line=1,
                matched_text="User:",
                description="Already found",
                recommendation="n/a",
            )
        ]
        findings = _fewshot_pi_findings(
            lines,
            "test.md",
            [rule],
            existing,
            _make_finding_stub,
            _no_exclude,
        )
        assert findings == []
