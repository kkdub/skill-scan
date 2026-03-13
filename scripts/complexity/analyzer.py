"""Shared code analysis logic for complexity checking.

Provides the CodeAnalyzer class that performs all complexity analysis:
- File length
- Function length (via AST)
- Cyclomatic complexity (via radon, in radon_checks.py)
- Maintainability Index (via radon, in radon_checks.py)

See .agent/standards/CODE-PATTERNS.md SIZE-001, SIZE-002 for standards.
"""

from __future__ import annotations

import ast
import fnmatch
import sys
from dataclasses import dataclass
from pathlib import Path

from scripts.complexity.models import (
    AnalysisResult,
    FileMetrics,
    Severity,
    Violation,
)
from scripts.complexity.radon_checks import (
    RADON_AVAILABLE,
    check_cyclomatic_complexity,
    check_maintainability_index,
)


@dataclass
class Thresholds:
    """Configurable thresholds for code quality checks."""

    max_file_lines: int = 300
    max_function_lines: int = 50
    cc_medium: int = 10
    cc_high: int = 15
    cc_critical: int = 20
    mi_low: int = 50
    mi_medium: int = 40
    mi_high: int = 35
    mi_critical: int = 25


DEFAULT_EXCLUDE_PATTERNS: list[str] = [
    "**/migrations/**",
    "**/alembic/**",
    "**/__pycache__/**",
    "**/*.pyc",
    "**/node_modules/**",
    "**/.venv/**",
    "**/venv/**",
    "**/build/**",
    "**/dist/**",
]


class CodeAnalyzer:
    """Analyzes Python code for complexity violations."""

    def __init__(
        self,
        thresholds: Thresholds | None = None,
        exclude_patterns: list[str] | None = None,
        exclude_files: list[str] | None = None,
    ) -> None:
        self.thresholds = thresholds or Thresholds()
        self.exclude_patterns = DEFAULT_EXCLUDE_PATTERNS.copy()
        if exclude_patterns:
            self.exclude_patterns.extend(exclude_patterns)
        self.exclude_files = set(exclude_files or [])

    def should_check_file(self, file_path: Path) -> bool:
        """Determine if a file should be analyzed."""
        if file_path.suffix != ".py":
            return False

        file_str = str(file_path).replace("\\", "/")

        if file_str in self.exclude_files:
            return False

        for pattern in self.exclude_patterns:
            if self._matches_exclude_pattern(pattern, file_str, file_path):
                return False

        return True

    def _matches_exclude_pattern(self, pattern: str, file_str: str, file_path: Path) -> bool:
        """Check if a file matches an exclude pattern."""
        if "**" not in pattern:
            return fnmatch.fnmatch(file_str, pattern)

        parts = pattern.split("**")

        # Directory wrapper pattern like **/migrations/**
        if len(parts) == 3 and not parts[0] and not parts[2]:
            middle = parts[1].strip("/")
            if not middle:
                return False
            return f"/{middle}/" in f"/{file_str}/" or file_str.startswith(f"{middle}/")

        # Recursive filename pattern like **/*.pyc
        if len(parts) == 2:
            return fnmatch.fnmatch(file_path.name, pattern.replace("**/", ""))

        return fnmatch.fnmatch(file_str, pattern.replace("**", "*"))

    def analyze_files(
        self,
        files: list[Path],
        base_dir: Path | None = None,
    ) -> AnalysisResult:
        """Analyze a list of Python files."""
        result = AnalysisResult(radon_available=RADON_AVAILABLE)
        mi_scores: list[float] = []

        for file_path in files:
            if not self.should_check_file(file_path):
                continue

            result.total_files += 1

            try:
                content = file_path.read_text(encoding="utf-8")
                relative_path = str(file_path.relative_to(base_dir)) if base_dir else str(file_path)

                file_metrics = self._analyze_file(content, file_path, relative_path, result, mi_scores)
                result.file_metrics.append(file_metrics)

            except Exception as e:
                print(f"Warning: Could not analyze {file_path}: {e}", file=sys.stderr)

        if mi_scores:
            result.average_mi = sum(mi_scores) / len(mi_scores)

        return result

    def _analyze_file(
        self,
        content: str,
        file_path: Path,
        relative_path: str,
        result: AnalysisResult,
        mi_scores: list[float],
    ) -> FileMetrics:
        """Analyze a single file and update the result."""
        metrics = FileMetrics(file_path=relative_path)

        lines = len(content.splitlines())
        metrics.lines = lines
        result.total_lines += lines

        self._check_file_length(lines, relative_path, result)
        self._parse_and_check_functions(content, file_path, relative_path, result, metrics)

        if RADON_AVAILABLE:
            self._run_radon_checks(content, relative_path, result, metrics, mi_scores)

        return metrics

    def _check_file_length(
        self,
        lines: int,
        relative_path: str,
        result: AnalysisResult,
    ) -> None:
        """Add a violation if the file exceeds the max line threshold."""
        if lines > self.thresholds.max_file_lines:
            result.add_violation(
                Violation(
                    severity=Severity.HIGH,
                    file_path=relative_path,
                    violation_type="file_length",
                    message=f"File has {lines} lines (max {self.thresholds.max_file_lines})",
                    value=float(lines),
                    threshold=float(self.thresholds.max_file_lines),
                )
            )

    def _parse_and_check_functions(
        self,
        content: str,
        file_path: Path,
        relative_path: str,
        result: AnalysisResult,
        metrics: FileMetrics,
    ) -> None:
        """Parse the file AST and check function lengths."""
        try:
            tree = ast.parse(content, filename=str(file_path))
            self._check_functions(tree, relative_path, result, metrics)
        except SyntaxError as e:
            print(f"Warning: Syntax error in {file_path}: {e}", file=sys.stderr)

    def _run_radon_checks(
        self,
        content: str,
        relative_path: str,
        result: AnalysisResult,
        metrics: FileMetrics,
        mi_scores: list[float],
    ) -> None:
        """Run radon cyclomatic complexity and maintainability index checks."""
        t = self.thresholds
        check_cyclomatic_complexity(
            content,
            relative_path,
            result,
            metrics,
            t.cc_medium,
            t.cc_high,
            t.cc_critical,
        )
        check_maintainability_index(
            content,
            relative_path,
            result,
            metrics,
            mi_scores,
            t.mi_low,
            t.mi_medium,
            t.mi_high,
            t.mi_critical,
        )

    def _check_functions(
        self,
        tree: ast.AST,
        relative_path: str,
        result: AnalysisResult,
        metrics: FileMetrics,
    ) -> None:
        """Check function lengths in the AST."""
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                func_length = self._calculate_function_length(node)

                metrics.functions.append(
                    {
                        "name": node.name,
                        "line": node.lineno,
                        "length": func_length,
                    }
                )

                if func_length > self.thresholds.max_function_lines:
                    result.add_violation(
                        Violation(
                            severity=Severity.MEDIUM,
                            file_path=relative_path,
                            violation_type="function_length",
                            message=(
                                f"Function '{node.name}' has {func_length} lines "
                                f"(max {self.thresholds.max_function_lines})"
                            ),
                            line=node.lineno,
                            function_name=node.name,
                            value=float(func_length),
                            threshold=float(self.thresholds.max_function_lines),
                        )
                    )

    def _calculate_function_length(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
        """Calculate function length using end_lineno if available."""
        if hasattr(node, "end_lineno") and node.end_lineno is not None:
            return node.end_lineno - node.lineno + 1

        if not node.body:
            return 1

        last_line = node.lineno
        for stmt in ast.walk(node):
            if hasattr(stmt, "lineno") and stmt.lineno:
                last_line = max(last_line, stmt.lineno)
            if hasattr(stmt, "end_lineno") and stmt.end_lineno:
                last_line = max(last_line, stmt.end_lineno)
        return last_line - node.lineno + 1
