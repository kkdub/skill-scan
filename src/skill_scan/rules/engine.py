"""Pattern matching engine — pure functions, no I/O.

Applies compiled detection rules against text lines to produce findings.

ReDoS mitigation:
- All patterns are author-controlled (not user-supplied)
- Input is bounded by ScanConfig.max_file_size (default 500KB)
- Line-by-line processing limits blast radius of any single match
- Default patterns reviewed to avoid pathological backtracking
"""

from __future__ import annotations

import re
from dataclasses import replace

from skill_scan.decoder import MAX_DECODE_DEPTH, decode_payload, extract_encoded_strings
from skill_scan.models import Finding, Rule
from skill_scan.normalizer import normalize_text

_MAX_MATCHED_TEXT = 200
MAX_PAYLOADS_PER_FILE = 100


def match_line(
    line: str,
    line_num: int,
    file_path: str,
    rules: list[Rule],
) -> list[Finding]:
    """Apply all rules to a single line of text.

    For each rule, exclude patterns are checked first (in default mode) or
    checked for overlap with primary matches (in strict mode). In default
    mode, if any exclude pattern matches the line, that rule is skipped
    entirely. In strict mode, an exclude only suppresses a finding when
    the exclude match does overlap with the primary match region.

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
        if rule.exclude_mode != "strict":
            if _is_excluded(line, rule):
                continue
            for pattern in rule.patterns:
                match = pattern.search(line)
                if match:
                    findings.append(_make_finding(rule, file_path, line_num, match))
        else:
            for pattern in rule.patterns:
                match = pattern.search(line)
                if match:
                    if not _should_suppress_strict(line, rule, match.span()):
                        findings.append(_make_finding(rule, file_path, line_num, match))

    return findings


def match_file(
    content: str,
    file_path: str,
    rules: list[Rule],
) -> list[Finding]:
    """Apply file-scope rules against the full file content.

    For each rule, every pattern is searched across the entire content string.
    Match offsets are mapped back to 1-indexed line numbers by counting
    newlines in the content before the match start.

    Exclude patterns are checked against the line containing the match,
    not the entire file content. In strict mode, overlap checking uses
    the match position relative to the line.

    Args:
        content: The full file text to scan.
        file_path: Path to the file being scanned (used in findings).
        rules: List of compiled Rule objects to apply (only file-scope
            rules should be passed, but line-scope rules are harmless).

    Returns:
        List of Finding objects for all matches in the file.
    """
    findings: list[Finding] = []
    lines = content.split("\n")

    for rule in rules:
        for pattern in rule.patterns:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                line_text = lines[line_num - 1] if line_num <= len(lines) else ""
                if rule.exclude_mode != "strict":
                    if _is_excluded(line_text, rule):
                        continue
                else:
                    line_start = content.rfind("\n", 0, match.start()) + 1
                    local_span = (match.start() - line_start, match.end() - line_start)
                    if _should_suppress_strict(line_text, rule, local_span):
                        continue
                findings.append(_make_finding(rule, file_path, line_num, match))

    return findings


def match_content(content: str, file_path: str, rules: list[Rule], *, _depth: int = 0) -> list[Finding]:
    """Apply line-scope, file-scope, and decoded-content rules to file content.

    Line endings normalized to LF. Each line matched in original and (if
    different) normalized form. Encoded payloads decoded and scanned
    recursively up to MAX_DECODE_DEPTH.
    """
    content = content.replace("\r\n", "\n").replace("\r", "\n")
    line_rules = [r for r in rules if r.match_scope == "line"]
    file_rules = [r for r in rules if r.match_scope == "file"]

    findings: list[Finding] = []

    for line_num, line in enumerate(content.split("\n"), start=1):
        line_findings = match_line(line, line_num, file_path, line_rules)
        findings.extend(line_findings)
        findings.extend(_normalized_line_findings(line, line_num, file_path, line_rules, line_findings))

    if file_rules:
        file_findings = match_file(content, file_path, file_rules)
        findings.extend(file_findings)
        findings.extend(_normalized_file_findings(content, file_path, file_rules, file_findings))

    if _depth < MAX_DECODE_DEPTH:
        findings.extend(_decoded_content_findings(content, file_path, rules, _depth))

    return findings


def _normalized_line_findings(
    line: str, line_num: int, file_path: str, rules: list[Rule], originals: list[Finding]
) -> list[Finding]:
    """Match normalized form of a line and return deduplicated new findings."""
    normalized = normalize_text(line)
    if normalized == line:
        return []
    seen = {f.rule_id for f in originals}
    return [f for f in match_line(normalized, line_num, file_path, rules) if f.rule_id not in seen]


def _normalized_file_findings(
    content: str, file_path: str, rules: list[Rule], originals: list[Finding]
) -> list[Finding]:
    """Match normalized form of full content and return deduplicated new findings."""
    norm_content = normalize_text(content)
    if norm_content == content:
        return []
    seen = {(f.rule_id, f.line) for f in originals}
    return [f for f in match_file(norm_content, file_path, rules) if (f.rule_id, f.line) not in seen]


def _decoded_content_findings(
    content: str,
    file_path: str,
    rules: list[Rule],
    depth: int,
) -> list[Finding]:
    """Decode encoded payloads and recursively scan decoded text."""
    results: list[Finding] = []
    for p in extract_encoded_strings(normalize_text(content))[:MAX_PAYLOADS_PER_FILE]:
        decoded = decode_payload(p)
        if decoded is None:
            continue
        for f in match_content(decoded, file_path, rules, _depth=depth + 1):
            desc = f.description if f.description.startswith("[decoded]") else f"[decoded] {f.description}"
            results.append(replace(f, file=file_path, line=p.line_num, description=desc))
    return results


def _make_finding(rule: Rule, file_path: str, line_num: int, match: re.Match[str]) -> Finding:
    """Create a Finding from a rule and regex match."""
    return Finding(
        rule_id=rule.rule_id,
        severity=rule.severity,
        category=rule.category,
        file=file_path,
        line=line_num,
        matched_text=match.group()[:_MAX_MATCHED_TEXT],
        description=rule.description,
        recommendation=rule.recommendation,
    )


def _is_excluded(line: str, rule: Rule) -> bool:
    """Check whether any exclude pattern matches the line."""
    return any(ep.search(line) for ep in rule.exclude_patterns)


def _should_suppress_strict(line: str, rule: Rule, primary_span: tuple[int, int]) -> bool:
    """In strict mode, suppress only if an overlapping exclude exists.

    Returns True (suppress) when an exclude pattern matches a region that
    overlaps with the primary match. This means the exclusion genuinely
    covers the detected text (e.g., ``safe_eval`` covering ``eval``).

    Returns False (detect) when all exclude matches are non-overlapping
    (piggybacking from a comment or unrelated part of the line) or when
    no exclude pattern matches at all.
    """
    p_start, p_end = primary_span
    for ep in rule.exclude_patterns:
        for em in ep.finditer(line):
            e_start, e_end = em.span()
            if e_end > p_start and e_start < p_end:
                return True
    return False
