"""Package-level risk analysis for complete skill packages."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from skill_scan._package_risk_correlations import (
    apply_correlations,
    correlation_bonus,
    has_multi_role_medium_risk,
)
from skill_scan._package_risk_inventory import analyze_text_files, build_role_map, count_roles
from skill_scan._package_risk_policy import (
    CATEGORY_DRIVER,
    IGNORED_CATEGORIES,
    final_band,
    is_direct_danger,
    top_drivers,
    weighted_points,
)
from skill_scan._package_text import TextSignal, classify_file_role
from skill_scan.models import Finding, PackageRiskSummary, Severity


class _RiskState:
    """Mutable scoring state for one package analysis pass."""

    __slots__ = ("direct_danger", "driver_scores", "score", "severe_direct_danger", "suspicious_url_count")

    def __init__(self) -> None:
        self.score = 0.0
        self.driver_scores: dict[str, float] = defaultdict(float)
        self.direct_danger = False
        self.severe_direct_danger = False
        self.suspicious_url_count = 0


def analyze_package(
    skill_dir: Path,
    files: list[Path],
    findings: tuple[Finding, ...],
) -> PackageRiskSummary:
    """Assess package-level risk from all scanned files and findings."""
    role_map = build_role_map(skill_dir, files)
    role_counts = count_roles(role_map)
    state = _RiskState()
    _score_findings(findings, role_map, state)
    text_signals = analyze_text_files(skill_dir, files)
    _score_text_signals(text_signals, state)
    correlated_signal_count = apply_correlations(text_signals, findings, role_map, state.driver_scores)
    state.score += correlation_bonus(correlated_signal_count)
    _apply_multi_role_bonus(findings, text_signals, role_map, state)
    band = final_band(state.score, state.direct_danger, state.severe_direct_danger)

    return PackageRiskSummary(
        score=round(state.score),
        band=band,
        top_drivers=top_drivers(state.driver_scores),
        counts_by_role=role_counts,
        suspicious_url_count=state.suspicious_url_count,
        correlated_signal_count=correlated_signal_count,
    )


def _score_findings(findings: tuple[Finding, ...], role_map: dict[str, str], state: _RiskState) -> None:
    for finding in findings:
        if finding.category in IGNORED_CATEGORIES:
            continue
        role = role_map.get(finding.file, classify_file_role(finding.file))
        driver = CATEGORY_DRIVER.get(finding.category)
        if driver is None:
            continue
        points = weighted_points(driver, finding.severity, role)
        state.score += points
        state.driver_scores[driver] += points
        _mark_direct_danger(role, driver, finding.severity, state)


def _score_text_signals(text_signals: tuple[TextSignal, ...], state: _RiskState) -> None:
    for signal in text_signals:
        points = weighted_points(signal.driver, signal.severity, signal.role)
        state.score += points
        state.driver_scores[signal.driver] += points
        state.suspicious_url_count += signal.suspicious_urls
        _mark_direct_danger(signal.role, signal.driver, signal.severity, state)


def _mark_direct_danger(role: str, driver: str, severity: Severity, state: _RiskState) -> None:
    if not is_direct_danger(role, driver, severity):
        return
    state.direct_danger = True
    state.severe_direct_danger = state.severe_direct_danger or severity == Severity.CRITICAL


def _apply_multi_role_bonus(
    findings: tuple[Finding, ...],
    text_signals: tuple[TextSignal, ...],
    role_map: dict[str, str],
    state: _RiskState,
) -> None:
    if not has_multi_role_medium_risk(findings, text_signals, role_map):
        return
    state.score += 6.0
    state.driver_scores["operator-manipulation"] += 3.0
    state.driver_scores["remote-bootstrap"] += 3.0
