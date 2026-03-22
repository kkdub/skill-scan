"""Correlation rules for package-level risk analysis."""

from __future__ import annotations

from skill_scan._package_risk_policy import CATEGORY_DRIVER, IGNORED_CATEGORIES
from skill_scan._package_text import TextSignal, classify_file_role
from skill_scan.models import Finding, Severity

_CORRELATION_BONUS = 6.0
_MEDIUM_OR_HIGHER = {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}

# Table-driven correlation rules: (condition_a, condition_b, driver_points)
_CORRELATION_RULES: tuple[tuple[str, str, dict[str, float]], ...] = (
    ("doc_bootstrap", "script_danger", {"execution": 6.0, "operator-manipulation": 6.0}),
    ("config_remote", "script_danger", {"execution": 4.0, "remote-bootstrap": 6.0}),
    ("secret_request", "outbound_danger", {"exfiltration": 6.0, "credential-access": 6.0}),
)


def apply_correlations(
    text_signals: tuple[TextSignal, ...],
    findings: tuple[Finding, ...],
    role_map: dict[str, str],
    driver_scores: dict[str, float],
) -> int:
    """Apply cross-file risk correlations and return the number of matches."""
    facts = _collect_facts(text_signals, findings, role_map)
    count = 0
    for fact_a, fact_b, points in _CORRELATION_RULES:
        if facts.get(fact_a) and facts.get(fact_b):
            for driver, score in points.items():
                driver_scores[driver] += score
            count += 1
    return count


def has_multi_role_medium_risk(
    findings: tuple[Finding, ...],
    text_signals: tuple[TextSignal, ...],
    role_map: dict[str, str],
) -> bool:
    """Return whether medium-or-higher signals span multiple package roles."""
    roles: set[str] = set()
    for finding in findings:
        if finding.category not in IGNORED_CATEGORIES and finding.severity in _MEDIUM_OR_HIGHER:
            roles.add(role_map.get(finding.file, classify_file_role(finding.file)))
    for signal in text_signals:
        if signal.severity in _MEDIUM_OR_HIGHER:
            roles.add(signal.role)
    return len(roles) >= 2


def _collect_facts(
    text_signals: tuple[TextSignal, ...],
    findings: tuple[Finding, ...],
    role_map: dict[str, str],
) -> dict[str, bool]:
    return {
        "doc_bootstrap": any(
            signal.driver in {"operator-manipulation", "remote-bootstrap"}
            and signal.role in {"entrypoint", "support-doc"}
            for signal in text_signals
        ),
        "config_remote": any(
            signal.driver == "remote-bootstrap" and signal.role == "config" for signal in text_signals
        ),
        "secret_request": any(signal.driver == "credential-access" for signal in text_signals),
        "script_danger": any(
            CATEGORY_DRIVER.get(f.category) in {"execution", "exfiltration"}
            and role_map.get(f.file, "support-doc") == "script"
            for f in findings
        ),
        "outbound_danger": any(CATEGORY_DRIVER.get(f.category) == "exfiltration" for f in findings),
    }


def correlation_bonus(count: int) -> float:
    """Return the score bonus for the number of matched correlations."""
    return count * _CORRELATION_BONUS
