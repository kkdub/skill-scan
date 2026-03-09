"""Inline suppression support via # noqa: RULE-ID comments.

Pure logic -- no I/O, no side effects.
Parses noqa comments and filters findings whose rule_id is suppressed
on the matching line.
"""

from __future__ import annotations

import re

from skill_scan.models import Finding

_NOQA_PATTERN = re.compile(r"#\s*noqa:\s*([\w-]+(?:\s*,\s*[\w-]+)*)", re.IGNORECASE)


def parse_noqa(line: str) -> frozenset[str]:
    """Extract suppressed rule IDs from a # noqa: RULE-ID comment.

    Returns a frozenset of uppercase rule IDs found after ``# noqa:``.
    Returns an empty frozenset when the line has no noqa directive or
    contains a bare ``# noqa`` without rule IDs.
    """
    match = _NOQA_PATTERN.search(line)
    if match is None:
        return frozenset()
    raw_ids = match.group(1)
    return frozenset(rid.strip().upper() for rid in raw_ids.split(","))


def filter_suppressed(findings: list[Finding], lines: list[str]) -> tuple[list[Finding], int]:
    """Remove findings suppressed by noqa comments on the matching line.

    Args:
        findings: Findings produced by rule matching / AST analysis.
        lines: Source lines of the scanned file (0-indexed).

    Returns:
        A tuple of (remaining_findings, suppressed_count).
    """
    if not findings or not lines:
        return findings, 0

    # Pre-compute noqa sets only for lines that have findings.
    noqa_cache: dict[int, frozenset[str]] = {}
    remaining: list[Finding] = []
    suppressed = 0

    for finding in findings:
        line_num = finding.line
        if line_num is None:
            remaining.append(finding)
            continue

        idx = line_num - 1  # findings use 1-based line numbers
        if idx < 0 or idx >= len(lines):
            remaining.append(finding)
            continue

        if idx not in noqa_cache:
            noqa_cache[idx] = parse_noqa(lines[idx])

        suppressed_ids = noqa_cache[idx]
        if finding.rule_id.upper() in suppressed_ids:
            suppressed += 1
        else:
            remaining.append(finding)

    return remaining, suppressed
