"""Radon-based complexity and maintainability checks.

Extracted from analyzer.py to keep files under 300 lines.
Provides cyclomatic complexity and maintainability index analysis.
"""

from __future__ import annotations

import sys

from scripts.complexity.models import (
    AnalysisResult,
    FileMetrics,
    Severity,
    Violation,
)

# Try to import radon for complexity and maintainability checking
try:
    from radon.complexity import cc_visit  # type: ignore[import-untyped]
    from radon.metrics import mi_visit  # type: ignore[import-untyped]

    RADON_AVAILABLE = True
except ImportError:
    RADON_AVAILABLE = False


class ThresholdsRadon:
    """Radon-specific threshold values. Injected from Thresholds."""

    __slots__ = (
        "cc_critical",
        "cc_high",
        "cc_medium",
        "mi_critical",
        "mi_high",
        "mi_low",
        "mi_medium",
    )

    def __init__(
        self,
        *,
        cc_medium: int = 10,
        cc_high: int = 15,
        cc_critical: int = 20,
        mi_low: int = 50,
        mi_medium: int = 40,
        mi_high: int = 35,
        mi_critical: int = 25,
    ) -> None:
        self.cc_medium = cc_medium
        self.cc_high = cc_high
        self.cc_critical = cc_critical
        self.mi_low = mi_low
        self.mi_medium = mi_medium
        self.mi_high = mi_high
        self.mi_critical = mi_critical


def _classify_cc_severity(
    complexity: int,
    cc_medium: int,
    cc_high: int,
    cc_critical: int,
) -> Severity | None:
    """Return the severity for a cyclomatic complexity value, or None if below threshold."""
    if complexity > cc_critical:
        return Severity.CRITICAL
    if complexity > cc_high:
        return Severity.HIGH
    if complexity > cc_medium:
        return Severity.MEDIUM
    return None


def _update_function_cc_metrics(
    metrics: FileMetrics,
    name: str,
    line: int,
    complexity: int,
    grade: str,
) -> None:
    """Attach complexity and grade to the matching function entry in metrics."""
    for func in metrics.functions:
        if func["name"] == name and func["line"] == line:
            func["complexity"] = complexity
            func["grade"] = grade
            break


def check_cyclomatic_complexity(
    content: str,
    relative_path: str,
    result: AnalysisResult,
    metrics: FileMetrics,
    cc_medium: int,
    cc_high: int,
    cc_critical: int,
) -> None:
    """Check cyclomatic complexity using radon."""
    try:
        cc_results = cc_visit(content)

        for cc_result in cc_results:
            complexity = cc_result.complexity
            name = cc_result.name
            line = cc_result.lineno
            grade = cc_result.letter

            _update_function_cc_metrics(metrics, name, line, complexity, grade)

            severity = _classify_cc_severity(complexity, cc_medium, cc_high, cc_critical)
            if severity is None:
                continue

            result.add_violation(
                Violation(
                    severity=severity,
                    file_path=relative_path,
                    violation_type="cyclomatic_complexity",
                    message=(
                        f"Function '{name}' has complexity {complexity} (grade {grade}, max {cc_medium})"
                    ),
                    line=line,
                    function_name=name,
                    value=float(complexity),
                    threshold=float(cc_medium),
                    grade=grade,
                )
            )

    except Exception as e:
        print(
            f"Warning: Could not analyze complexity of {relative_path}: {e}",
            file=sys.stderr,
        )


def _classify_mi_severity(
    mi_score: float,
    mi_low: int,
    mi_medium: int,
    mi_high: int,
    mi_critical: int,
) -> tuple[Severity, int] | None:
    """Return (severity, threshold) for an MI score, or None if above all thresholds."""
    if mi_score < mi_critical:
        return Severity.CRITICAL, mi_critical
    if mi_score < mi_high:
        return Severity.HIGH, mi_high
    if mi_score < mi_medium:
        return Severity.MEDIUM, mi_medium
    if mi_score < mi_low:
        return Severity.LOW, mi_low
    return None


def check_maintainability_index(
    content: str,
    relative_path: str,
    result: AnalysisResult,
    metrics: FileMetrics,
    mi_scores: list[float],
    mi_low: int,
    mi_medium: int,
    mi_high: int,
    mi_critical: int,
) -> None:
    """Check maintainability index using radon."""
    try:
        mi_score = mi_visit(content, multi=True)
        mi_scores.append(float(mi_score))
        metrics.maintainability_index = round(float(mi_score), 1)

        classification = _classify_mi_severity(mi_score, mi_low, mi_medium, mi_high, mi_critical)
        if classification is None:
            return

        severity, mi_threshold = classification
        result.add_violation(
            Violation(
                severity=severity,
                file_path=relative_path,
                violation_type="maintainability_index",
                message=(
                    f"Maintainability Index {mi_score:.1f} is below "
                    f"{severity.name.lower()} threshold of {mi_threshold}"
                ),
                value=round(float(mi_score), 1),
                threshold=float(mi_threshold),
            )
        )

    except Exception as e:
        print(
            f"Warning: Could not analyze maintainability of {relative_path}: {e}",
            file=sys.stderr,
        )
