"""Shared scoring policy for package-level risk analysis."""

from __future__ import annotations

from skill_scan.models import Severity

ROLE_WEIGHT: dict[str, float] = {
    "entrypoint": 1.4,
    "script": 1.35,
    "config": 1.1,
    "support-doc": 0.8,
    "reference": 0.35,
}

SEVERITY_POINTS: dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 2.0,
    Severity.INFO: 0.5,
}

CATEGORY_DRIVER: dict[str, str] = {
    "prompt-injection": "operator-manipulation",
    "malicious-code": "execution",
    "data-exfiltration": "exfiltration",
    "credential-exposure": "credential-access",
    "supply-chain": "remote-bootstrap",
    "tool-abuse": "execution",
    "obfuscation": "stealth/obfuscation",
    "agent-manipulation": "operator-manipulation",
}

IGNORED_CATEGORIES = frozenset({"analysis", "file-safety", "schema-validation"})
DIRECT_DANGER_DRIVERS = frozenset({"execution", "exfiltration", "remote-bootstrap", "operator-manipulation"})


def weighted_points(driver: str, severity: Severity, role: str) -> float:
    """Return weighted package-risk points for one signal."""
    points = SEVERITY_POINTS[severity] * ROLE_WEIGHT[role]
    if role == "reference" and driver in {"operator-manipulation", "remote-bootstrap"}:
        points *= 0.6
    return points


def is_direct_danger(role: str, driver: str, severity: Severity) -> bool:
    """Return whether a signal should force the package into direct-danger handling."""
    return (
        role in {"entrypoint", "script"}
        and driver in DIRECT_DANGER_DRIVERS
        and severity in {Severity.HIGH, Severity.CRITICAL}
    )


def top_drivers(driver_scores: dict[str, float]) -> tuple[str, ...]:
    """Return the strongest scoring risk drivers."""
    ordered = sorted(driver_scores.items(), key=lambda item: (-item[1], item[0]))
    return tuple(driver for driver, score in ordered[:3] if score > 0)


def risk_band(score: float) -> str:
    """Map a numeric score to a package-risk band."""
    if score >= 40:
        return "severe"
    if score >= 20:
        return "high"
    if score >= 8:
        return "guarded"
    return "low"


def final_band(score: float, direct_danger: bool, severe_direct_danger: bool) -> str:
    """Apply direct-danger overrides to the numeric risk band."""
    band = risk_band(score)
    if severe_direct_danger and band != "severe":
        return "severe"
    if direct_danger and band in {"low", "guarded"}:
        return "high"
    return band
