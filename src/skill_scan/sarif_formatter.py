"""SARIF output formatter for scan results.

Pure formatting logic -- no I/O, no side effects.
Converts ScanResult to SARIF 2.1.0 JSON output.
"""

from __future__ import annotations

import json
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from skill_scan.models import Finding, ScanResult, Severity

type JsonObject = dict[str, object]

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


def _get_version() -> str:
    """Get the installed skill-scan version, falling back to 'unknown'."""
    try:
        return _pkg_version("skill-scan")
    except PackageNotFoundError:
        return "unknown"


def format_sarif(result: ScanResult) -> str:
    """Format a ScanResult as a SARIF 2.1.0 JSON string.

    Args:
        result: The scan result to format.

    Returns:
        SARIF 2.1.0 JSON string.
    """
    data = {
        "version": "2.1.0",
        "$schema": _SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "skill-scan",
                        "version": _get_version(),
                        "rules": _build_driver_rules(result.findings),
                    }
                },
                "results": [_build_sarif_result(f) for f in result.findings],
            }
        ],
    }
    return json.dumps(data, indent=2)


def _severity_to_level(severity: Severity) -> str:
    """Map a Severity enum value to a SARIF level string."""
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def _build_sarif_result(finding: Finding) -> JsonObject:
    """Convert one Finding to a SARIF result dict."""
    result: JsonObject = {
        "ruleId": finding.rule_id,
        "level": _severity_to_level(finding.severity),
        "message": {"text": finding.description},
        "locations": [_build_location(finding)],
    }
    return result


def _build_location(finding: Finding) -> JsonObject:
    """Build a SARIF location entry for a finding."""
    artifact_location: JsonObject = {"uri": finding.file}
    physical_location: JsonObject = {"artifactLocation": artifact_location}
    if finding.line is not None:
        physical_location["region"] = {"startLine": finding.line}
    return {"physicalLocation": physical_location}


def _build_driver_rules(findings: tuple[Finding, ...]) -> list[JsonObject]:
    """Build deduplicated tool.driver.rules list from findings."""
    seen: set[str] = set()
    rules: list[JsonObject] = []
    for finding in findings:
        if finding.rule_id not in seen:
            seen.add(finding.rule_id)
            rules.append(
                {
                    "id": finding.rule_id,
                    "shortDescription": {"text": finding.description},
                    "fullDescription": {"text": finding.recommendation},
                }
            )
    return rules
