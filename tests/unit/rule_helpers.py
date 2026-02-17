"""Shared test helpers for building Rule objects."""

from __future__ import annotations

import re

from skill_scan.models import Rule, Severity


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
