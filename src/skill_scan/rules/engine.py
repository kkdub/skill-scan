"""Pattern matching engine — pure functions, no I/O.

Applies compiled detection rules against text lines to produce findings.

ReDoS mitigation:
- All patterns are author-controlled (not user-supplied)
- Input is bounded by ScanConfig.max_file_size (default 500KB)
- Line-by-line processing limits blast radius of any single match
- Default patterns reviewed to avoid pathological backtracking
"""

from __future__ import annotations

from skill_scan.models import Finding, Rule

_MAX_MATCHED_TEXT = 200


def match_line(
    line: str,
    line_num: int,
    file_path: str,
    rules: list[Rule],
) -> list[Finding]:
    """Apply all rules to a single line of text.

    For each rule, exclude patterns are checked first. If any exclude pattern
    matches the line, that rule is skipped entirely. Otherwise, each pattern
    is tested and a Finding is created for every match.

    Args:
        line: The text line to scan.
        line_num: 1-indexed line number in the source file.
        file_path: Path to the file being scanned (used in findings).
        rules: List of compiled Rule objects to apply.

    Returns:
        List of Finding objects for all matches on this line.
    """
    findings: list[Finding] = []

    for rule in rules:
        if _is_excluded(line, rule):
            continue

        for pattern in rule.patterns:
            match = pattern.search(line)
            if match:
                matched_text = match.group()[:_MAX_MATCHED_TEXT]
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        file=file_path,
                        line=line_num,
                        matched_text=matched_text,
                        description=rule.description,
                        recommendation=rule.recommendation,
                    )
                )

    return findings


def _is_excluded(line: str, rule: Rule) -> bool:
    """Check whether any exclude pattern matches the line."""
    return any(ep.search(line) for ep in rule.exclude_patterns)
