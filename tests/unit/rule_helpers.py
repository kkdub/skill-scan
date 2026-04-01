"""Shared test helpers for building Rule and EncodedPayload objects."""

from __future__ import annotations

import re
from pathlib import Path

from skill_scan.decoder import EncodedPayload
from skill_scan.models import Finding, Rule, Severity
from skill_scan.rules.engine import match_line

# Path to the agent_manipulation TOML used by multiple test modules.
AGENT_MANIPULATION_RULES_PATH = (
    Path(__file__).resolve().parents[2] / "src" / "skill_scan" / "rules" / "data" / "agent_manipulation.toml"
)


def filter_by_rule(rule_id: str, findings: list[Finding]) -> list[Finding]:
    """Filter a findings list to only those matching rule_id."""
    return [f for f in findings if f.rule_id == rule_id]


def make_rule(
    rule_id: str = "TEST-001",
    severity: Severity = Severity.INFO,
    category: str = "test",
    description: str = "Test rule",
    recommendation: str = "Fix it",
    patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
    flags: re.RegexFlag = re.RegexFlag(0),  # noqa: B008
    match_scope: str = "line",
    exclude_mode: str = "default",
) -> Rule:
    """Helper to build Rule objects for testing."""
    compiled_patterns = tuple(re.compile(p, flags) for p in (patterns or []))
    compiled_exclude = tuple(re.compile(p, flags) for p in (exclude_patterns or []))

    return Rule(
        rule_id=rule_id,
        severity=severity,
        category=category,
        description=description,
        recommendation=recommendation,
        patterns=compiled_patterns,
        exclude_patterns=compiled_exclude,
        match_scope=match_scope,
        exclude_mode=exclude_mode,
    )


def match_rule(line: str, rules: list[Rule], rule_id: str) -> bool:
    """Check if a rule matches a line. Returns True/False."""
    return any(f.rule_id == rule_id for f in match_line(line, 1, "test.md", rules))


def rule_findings(line: str, rules: list[Rule], rule_id: str) -> list[Finding]:
    """Get all findings for a specific rule on a line."""
    return [f for f in match_line(line, 1, "test.md", rules) if f.rule_id == rule_id]


def make_encoded_payload(text: str, encoding: str) -> EncodedPayload:
    """Construct an EncodedPayload with default line/offset for unit tests."""
    return EncodedPayload(encoded_text=text, encoding_type=encoding, line_num=1, start_offset=0)


def make_agent_finding(
    *,
    line: int | None = 1,
    matched_text: str = "write to ~/.bashrc",
    category: str = "agent-manipulation",
    rule_id: str = "AGENT-001",
    file: str = "skill.md",
) -> Finding:
    """Helper to build an agent-manipulation Finding with sensible defaults."""
    return Finding(
        rule_id=rule_id,
        severity=Severity.CRITICAL,
        category=category,
        file=file,
        line=line,
        matched_text=matched_text,
        description="File-write coercion detected",
        recommendation="Review intent",
    )
