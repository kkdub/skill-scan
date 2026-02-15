"""Text output formatters for scan results.

Pure formatting logic — no I/O, no side effects.
"""

from __future__ import annotations

from skill_scan.models import Finding, ScanResult, Severity, Verdict

_MAX_MATCH_LEN = 80

_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def format_text(result: ScanResult) -> str:
    """Format a ScanResult as human-readable text output.

    Produces a report with severity indicators, file:line references,
    matched text (truncated to 80 chars), and recommendations.
    Includes a summary section with counts, verdict, and duration.

    Args:
        result: The scan result to format.

    Returns:
        Formatted text string.
    """
    if result.verdict == Verdict.INVALID:
        msg = "Scan failed: invalid skill schema."
        if result.error_message:
            msg += f"\n  Detail: {result.error_message}"
        return msg

    if not result.findings:
        return "No security issues found."

    parts: list[str] = []
    parts.append("skill-scan results")
    parts.append("==================")
    parts.append("")

    for finding in result.findings:
        parts.append(_format_finding(finding))

    parts.append(_format_summary(result))
    return "\n".join(parts)


def _format_finding(finding: Finding) -> str:
    """Format a single finding as a text block."""
    severity_tag = finding.severity.value.upper()
    lines: list[str] = []

    lines.append(f"[{severity_tag}] {finding.rule_id}: {finding.description}")

    file_ref = finding.file
    if finding.line is not None:
        file_ref = f"{finding.file}:{finding.line}"
    lines.append(f"  File: {file_ref}")

    matched = _truncate(finding.matched_text, _MAX_MATCH_LEN)
    lines.append(f'  Match: "{matched}"')

    lines.append(f"  \u2192 {finding.recommendation}")
    lines.append("")

    return "\n".join(lines)


def _truncate(text: str, max_len: int) -> str:
    """Truncate text to max_len characters, appending '...' if needed."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _format_summary(result: ScanResult) -> str:
    """Format the summary section with counts, verdict, and duration."""
    lines: list[str] = []
    lines.append("------------------")
    lines.append("Summary")

    for severity in _SEVERITY_ORDER:
        count = result.counts.get(severity.value, 0)
        if count > 0:
            lines.append(f"  {severity.value}: {count}")

    lines.append(f"  Verdict: {result.verdict.value.upper()}")
    lines.append(f"  Duration: {result.duration:.2f}s")

    return "\n".join(lines)
