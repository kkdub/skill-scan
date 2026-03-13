"""Data models for complexity analysis.

Defines severity levels, violation types, and result structures used
throughout the complexity analysis module.
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Literal


class Severity(IntEnum):
    """Severity levels for violations, ordered from most to least critical.

    Using IntEnum allows direct comparison and sorting by severity.
    Lower values = more critical (sorted first).
    """

    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


ViolationType = Literal[
    "file_length",
    "function_length",
    "cyclomatic_complexity",
    "maintainability_index",
]


@dataclass(frozen=True, order=True)
class Violation:
    """A single code quality violation."""

    severity: Severity
    file_path: str
    violation_type: ViolationType = field(compare=False)
    message: str = field(compare=False)
    line: int | None = field(default=None, compare=False)
    function_name: str | None = field(default=None, compare=False)
    value: float | None = field(default=None, compare=False)
    threshold: float | None = field(default=None, compare=False)
    grade: str | None = field(default=None, compare=False)

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary for JSON serialization."""
        result: dict[str, object] = {
            "severity": self.severity.name.lower(),
            "file": self.file_path,
            "type": self.violation_type,
            "message": self.message,
        }
        if self.line is not None:
            result["line"] = self.line
        if self.function_name is not None:
            result["function"] = self.function_name
        if self.value is not None:
            result["value"] = self.value
        if self.threshold is not None:
            result["threshold"] = self.threshold
        if self.grade is not None:
            result["grade"] = self.grade
        return result


@dataclass
class FileMetrics:
    """Metrics collected for a single file."""

    file_path: str
    lines: int = 0
    maintainability_index: float | None = None
    functions: list[dict[str, object]] = field(default_factory=list)


@dataclass
class AnalysisResult:
    """Complete analysis result for a codebase or set of files."""

    total_files: int = 0
    total_lines: int = 0
    violations: list[Violation] = field(default_factory=list)
    file_metrics: list[FileMetrics] = field(default_factory=list)
    average_mi: float = 0.0
    radon_available: bool = False

    def add_violation(self, violation: Violation) -> None:
        """Add a violation to the result."""
        self.violations.append(violation)

    def get_sorted_violations(self) -> list[Violation]:
        """Return violations sorted by severity (most critical first)."""
        return sorted(self.violations)

    def get_violations_by_file(self) -> dict[str, list[Violation]]:
        """Group violations by file path."""
        by_file: dict[str, list[Violation]] = {}
        for v in self.get_sorted_violations():
            if v.file_path not in by_file:
                by_file[v.file_path] = []
            by_file[v.file_path].append(v)
        return by_file

    def has_critical_violations(self) -> bool:
        """Check if there are any critical or high severity violations."""
        return any(v.severity <= Severity.HIGH for v in self.violations)

    def summary(self) -> dict[str, int]:
        """Return count of violations by severity."""
        counts: dict[str, int] = {s.name.lower(): 0 for s in Severity}
        for v in self.violations:
            counts[v.severity.name.lower()] += 1
        return counts

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_files": self.total_files,
            "total_lines": self.total_lines,
            "average_mi": round(self.average_mi, 1),
            "summary": self.summary(),
            "violations": [v.to_dict() for v in self.get_sorted_violations()],
        }
