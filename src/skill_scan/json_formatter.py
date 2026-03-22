"""JSON output formatter for scan results.

Pure formatting logic -- no I/O, no side effects.
Converts ScanResult to deterministic JSON output.
"""

from __future__ import annotations

import json

from skill_scan.models import Finding, PackageRiskSummary, ScanResult

_SEVERITY_LEVELS: tuple[str, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
)


def format_json(result: ScanResult) -> str:
    """Format a ScanResult as a deterministic JSON string.

    Args:
        result: The scan result to format.

    Returns:
        JSON string with sorted keys for deterministic output.
    """
    data = {
        "counts": _build_counts(result.counts),
        "duration": result.duration,
        "files_scanned": result.files_scanned,
        "findings": [_serialize_finding(f) for f in result.findings],
        "package_risk": _serialize_package_risk(result.package_risk),
        "skill_name": result.skill_name,
        "suppressed_count": result.suppressed_count,
        "verdict": result.verdict.value,
    }
    return json.dumps(data, sort_keys=True)


def _build_counts(counts: dict[str, int]) -> dict[str, int]:
    """Build counts dict with all 5 severity levels, defaulting missing to 0."""
    return {level: counts.get(level, 0) for level in _SEVERITY_LEVELS}


def _serialize_finding(finding: Finding) -> dict[str, str | int | None]:
    """Serialize a single Finding to a JSON-compatible dict."""
    return {
        "category": finding.category,
        "description": finding.description,
        "file": finding.file,
        "line": finding.line,
        "matched_text": finding.matched_text,
        "recommendation": finding.recommendation,
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
    }


def _serialize_package_risk(summary: PackageRiskSummary | None) -> dict[str, object] | None:
    """Serialize package-level risk summary for JSON output."""
    if summary is None:
        return None
    return {
        "band": summary.band,
        "correlated_signal_count": summary.correlated_signal_count,
        "counts_by_role": dict(summary.counts_by_role),
        "score": summary.score,
        "suspicious_url_count": summary.suspicious_url_count,
        "top_drivers": list(summary.top_drivers),
    }
