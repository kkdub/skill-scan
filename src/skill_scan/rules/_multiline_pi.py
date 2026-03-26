"""Multi-line prompt injection scanning."""

from __future__ import annotations

import re
from collections.abc import Callable

from skill_scan.models import Finding, Rule


def _multiline_pi_findings(
    lines: list[str],
    file_path: str,
    pi_rules: list[Rule],
    existing: list[Finding],
    make_finding: Callable[[Rule, str, int, re.Match[str]], Finding],
    is_excluded: Callable[[str, Rule], bool],
) -> list[Finding]:
    """Scan sliding windows of 3-5 consecutive lines for multi-line PI."""
    if len(lines) < 3:
        return []
    seen: dict[str, set[int]] = {}
    for f in existing:
        if f.line is not None:
            seen.setdefault(f.rule_id, set()).add(f.line)
    out: list[Finding] = []
    for ws in (3, 4, 5):
        for s in range(len(lines) - ws + 1):
            first = s + 1
            win = set(range(first, first + ws))
            window_lines = lines[s : s + ws]
            joined = " ".join(window_lines)
            line_lengths = [len(ln) for ln in window_lines]
            for r in pi_rules:
                _scan_window_rule(
                    r,
                    joined,
                    file_path,
                    first,
                    win,
                    line_lengths,
                    seen,
                    out,
                    make_finding,
                    is_excluded,
                )
    return out


def _match_line_num(match_start: int, first_line_num: int, line_lengths: list[int]) -> int:
    """Map a char offset in the joined string to its 1-based source line."""
    offset = 0
    for i, length in enumerate(line_lengths):
        # End of this line's region in the joined string (includes the trailing space)
        end = offset + length
        if match_start < end:
            return first_line_num + i
        offset = end + 1  # +1 for the space separator
    return first_line_num + len(line_lengths) - 1


def _scan_window_rule(
    rule: Rule,
    joined: str,
    file_path: str,
    first_line_num: int,
    window_line_nums: set[int],
    line_lengths: list[int],
    found_lines: dict[str, set[int]],
    results: list[Finding],
    make_finding: Callable[[Rule, str, int, re.Match[str]], Finding],
    is_excluded: Callable[[str, Rule], bool],
) -> None:
    """Check one rule against a joined window."""
    rid = rule.rule_id
    if rid in found_lines and found_lines[rid] & window_line_nums:
        return
    if is_excluded(joined, rule):
        return
    for pat in rule.patterns:
        m = pat.search(joined)
        if m:
            line_num = _match_line_num(m.start(), first_line_num, line_lengths)
            results.append(make_finding(rule, file_path, line_num, m))
            found_lines.setdefault(rid, set()).update(window_line_nums)
            break
