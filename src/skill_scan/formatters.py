"""Text output formatters for scan results.

Pure formatting logic — no I/O, no side effects.
Supports three output modes: default (grouped), quiet, and verbose.
"""

from __future__ import annotations

from collections import defaultdict
from enum import Enum

from skill_scan.models import Finding, ScanResult, Severity

_MAX_MATCH_LEN = 80
_MAX_SAMPLES = 3

_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


class OutputMode(Enum):
    """Output verbosity mode for text formatting."""

    DEFAULT = "default"
    QUIET = "quiet"
    VERBOSE = "verbose"


def format_text(result: ScanResult, mode: OutputMode = OutputMode.DEFAULT) -> str:
    """Format a ScanResult as human-readable text output.

    Args:
        result: The scan result to format.
        mode: Output verbosity mode.

    Returns:
        Formatted text string.
    """
    if mode == OutputMode.QUIET:
        return _format_quiet(result)
    if mode == OutputMode.VERBOSE:
        return _format_verbose(result)
    return _format_default(result)


def _format_default(result: ScanResult) -> str:
    """Default mode: header, severity sections, grouped findings, verdict."""
    parts: list[str] = [_header(result), ""]
    if not result.findings:
        parts.append("No security issues found.")
        parts.append("")
    else:
        groups = _group_by_rule(result.findings)
        by_severity = _groups_by_severity(groups)
        for severity in _SEVERITY_ORDER:
            sev_groups = by_severity.get(severity, [])
            if not sev_groups:
                continue
            total = sum(len(g) for g in sev_groups)
            parts.append(f"{severity.value.upper()} ({total} findings, {len(sev_groups)} rules)")
            for group in sev_groups:
                if len(group) == 1:
                    parts.append(_format_finding_indented(group[0]))
                else:
                    parts.append(_format_group_indented(group))
            parts.append("")

    parts.append(_verdict_banner(result))
    return "\n".join(parts)


def _format_quiet(result: ScanResult) -> str:
    """Quiet mode: single verdict summary line."""
    counts_str = _nonzero_counts_str(result.counts)
    suffix = f" ({counts_str})" if counts_str else ""
    line = f"Verdict: {result.verdict.value.upper()}{suffix}"
    if result.files_skipped:
        line += f" [{result.files_skipped} files skipped]"
    return line


def _format_verbose(result: ScanResult) -> str:
    """Verbose mode: header + all findings expanded individually."""
    parts: list[str] = [_header(result), ""]
    if not result.findings:
        parts.append("No security issues found.")
    else:
        for finding in result.findings:
            parts.append(_format_finding_full(finding))
    parts.append(_verdict_banner(result))
    return "\n".join(parts)


# --- Structural helpers ---


def _nonzero_counts_str(counts: dict[str, int]) -> str:
    """Format non-zero severity counts as a comma-separated string."""
    return ", ".join(
        f"{counts.get(s.value, 0)} {s.value}" for s in _SEVERITY_ORDER if counts.get(s.value, 0) > 0
    )


def _header(result: ScanResult) -> str:
    name = result.skill_name or "unknown"
    parts = [f"skill-scan report: {name}"]
    parts.append(
        f"Scanned {result.files_scanned} files ({result.bytes_scanned} bytes) in {result.duration:.2f}s"
    )
    if result.files_skipped:
        parts.append(f"  Skipped: {result.files_skipped} files")
    if result.suppressed_count > 0:
        parts.append(f"  Suppressed: {result.suppressed_count} findings via noqa")
    for reason in result.degraded_reasons:
        parts.append(f"  Warning: {reason}")
    return "\n".join(parts)


def _verdict_banner(result: ScanResult) -> str:
    lines: list[str] = ["------------------", f"Verdict: {result.verdict.value.upper()}"]
    counts_str = _nonzero_counts_str(result.counts)
    if counts_str:
        lines.append(f"  {counts_str}")
    lines.append(f"  Scanned in {result.duration:.2f}s")
    return "\n".join(lines)


# --- Grouping helpers ---


def _group_by_rule(findings: tuple[Finding, ...]) -> list[list[Finding]]:
    """Group findings by rule_id, preserving first-occurrence order."""
    grouped: dict[str, list[Finding]] = defaultdict(list)
    order: list[str] = []
    for f in findings:
        if f.rule_id not in grouped:
            order.append(f.rule_id)
        grouped[f.rule_id].append(f)
    return [grouped[rid] for rid in order]


def _groups_by_severity(
    groups: list[list[Finding]],
) -> dict[Severity, list[list[Finding]]]:
    """Organize rule groups by severity level."""
    result: dict[Severity, list[list[Finding]]] = defaultdict(list)
    for group in groups:
        result[group[0].severity].append(group)
    return result


# --- Finding formatters ---


def _format_finding_indented(finding: Finding) -> str:
    """Format a single finding indented within a severity section."""
    tag = finding.severity.value.upper()
    ref = _file_ref(finding)
    matched = _truncate(finding.matched_text, _MAX_MATCH_LEN)
    return (
        f"  [{tag}] {finding.rule_id}: {finding.description}\n"
        f"    File: {ref}\n"
        f'    Match: "{matched}"\n'
        f"    -> {finding.recommendation}"
    )


def _format_group_indented(group: list[Finding]) -> str:
    """Format a grouped set of findings within a severity section."""
    first = group[0]
    tag = first.severity.value.upper()
    file_set = {f.file for f in group}
    lines: list[str] = [
        f"  [{tag}] {first.rule_id}: {first.description}",
        f"    {len(group)} occurrences across {len(file_set)} files",
    ]
    for sample in group[:_MAX_SAMPLES]:
        ref = _file_ref(sample)
        matched = _truncate(sample.matched_text, _MAX_MATCH_LEN)
        lines.append(f'    {ref}    "{matched}"')
    remaining = len(group) - _MAX_SAMPLES
    if remaining > 0:
        lines.append(f"    ... and {remaining} more")
    lines.append(f"    -> {first.recommendation}")
    return "\n".join(lines)


def _format_finding_full(finding: Finding) -> str:
    """Format a single finding fully (verbose mode, no indentation)."""
    tag = finding.severity.value.upper()
    ref = _file_ref(finding)
    matched = _truncate(finding.matched_text, _MAX_MATCH_LEN)
    return (
        f"[{tag}] {finding.rule_id}: {finding.description}\n"
        f"  File: {ref}\n"
        f'  Match: "{matched}"\n'
        f"  -> {finding.recommendation}\n"
    )


def _file_ref(finding: Finding) -> str:
    if finding.line is not None:
        return f"{finding.file}:{finding.line}"
    return finding.file


def _truncate(text: str, max_len: int) -> str:
    """Truncate text to max_len characters, appending '...' if needed."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."
