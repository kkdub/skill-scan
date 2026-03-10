"""Shared code analysis logic for complexity checking.

Provides the CodeAnalyzer class that performs all complexity analysis:
- File length
- Function length (via AST)
- Cyclomatic complexity (via radon)
- Maintainability Index (via radon)

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

# Try to import radon for complexity and maintainability checking
try:
    from radon.complexity import cc_visit  # type: ignore[import-untyped]
    from radon.metrics import mi_visit  # type: ignore[import-untyped]

    RADON_AVAILABLE = True
except ImportError:
    RADON_AVAILABLE = False


@dataclass
class Thresholds:
    """Configurable thresholds for code quality checks.

    Based on CLAUDE.md and .agent/standards/CODE-PATTERNS.md standards.
    """

    # File length
    max_file_lines: int = 500

    # Function length
    max_function_lines: int = 100

    # Cyclomatic complexity thresholds
    # A (1-5): Simple | B (6-10): Moderate | C (11-20): Complex | D/E/F (21+): Very complex
    cc_medium: int = 10  # Above this = MEDIUM severity
    cc_high: int = 15  # Above this = HIGH severity
    cc_critical: int = 20  # Above this = CRITICAL severity

    # Maintainability Index thresholds (0-100, higher is better)
    # 100-75: Highly maintainable | 74-50: Moderate | 49-25: Difficult | 24-0: Very difficult
    mi_low: int = 50  # Below this = LOW severity (warning)
    mi_medium: int = 40  # Below this = MEDIUM severity
    mi_high: int = 35  # Below this = HIGH severity
    mi_critical: int = 25  # Below this = CRITICAL severity


# Default exclude patterns for files that shouldn't be checked
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
        """Initialize the analyzer.

        Args:
            thresholds: Custom thresholds (uses defaults if None)
            exclude_patterns: Glob patterns to exclude (merged with defaults)
            exclude_files: Specific file paths to exclude
        """
        self.thresholds = thresholds or Thresholds()
        self.exclude_patterns = DEFAULT_EXCLUDE_PATTERNS.copy()
        if exclude_patterns:
            self.exclude_patterns.extend(exclude_patterns)
        self.exclude_files = set(exclude_files or [])

    def should_check_file(self, file_path: Path) -> bool:
        """Determine if a file should be analyzed.

        Args:
            file_path: Path to check

        Returns:
            True if file should be analyzed, False if excluded
        """
        if file_path.suffix != ".py":
            return False

        # Normalize path separators for cross-platform matching
        # Windows uses backslashes, but patterns use forward slashes
        file_str = str(file_path).replace("\\", "/")

        # Check specific file exclusions
        if file_str in self.exclude_files:
            return False

        # Check against glob patterns using proper fnmatch
        for pattern in self.exclude_patterns:
            if self._matches_exclude_pattern(pattern, file_str, file_path):
                return False

        return True

    def _matches_exclude_pattern(self, pattern: str, file_str: str, file_path: Path) -> bool:
        """Check if a file matches an exclude pattern.

        Args:
            pattern: The exclude pattern to check
            file_str: Normalized file path string (with forward slashes)
            file_path: Original file path object

        Returns:
            True if the file matches the pattern and should be excluded
        """
        if "**" not in pattern:
            return fnmatch.fnmatch(file_str, pattern)

        # Handle patterns containing **
        return self._matches_recursive_pattern(pattern, file_str, file_path)

    def _matches_recursive_pattern(self, pattern: str, file_str: str, file_path: Path) -> bool:
        """Check if a file matches a pattern containing **.

        Args:
            pattern: Pattern containing ** wildcards
            file_str: Normalized file path string
            file_path: Original file path object

        Returns:
            True if the file matches the pattern
        """
        pattern_parts = pattern.split("**")

        if self._is_directory_wrapper_pattern(pattern_parts):
            return self._matches_directory_wrapper(pattern_parts, file_str)

        if self._is_recursive_filename_pattern(pattern_parts):
            return self._matches_recursive_filename(pattern, file_path)

        # Fallback: treat "**" as "*" and match against the full path
        return self._matches_normalized_pattern(pattern, file_str)

    def _is_directory_wrapper_pattern(self, pattern_parts: list[str]) -> bool:
        """Check if pattern is a directory wrapper like **/migrations/**."""
        return len(pattern_parts) == 3 and not pattern_parts[0] and not pattern_parts[2]

    def _is_recursive_filename_pattern(self, pattern_parts: list[str]) -> bool:
        """Check if pattern is a recursive filename pattern like **/*.pyc."""
        return len(pattern_parts) == 2

    def _matches_directory_wrapper(self, pattern_parts: list[str], file_str: str) -> bool:
        """Check if file path contains a specific directory.

        Handles patterns like **/migrations/** or **/venv/**.

        Args:
            pattern_parts: Split pattern parts (3 parts expected)
            file_str: Normalized file path string

        Returns:
            True if the middle directory appears in the path
        """
        middle = pattern_parts[1].strip("/")
        if not middle:
            return False

        # Check if directory appears anywhere in path or at the start
        return f"/{middle}/" in f"/{file_str}/" or file_str.startswith(f"{middle}/")

    def _matches_recursive_filename(self, pattern: str, file_path: Path) -> bool:
        """Check if filename matches a recursive pattern like **/*.pyc.

        Args:
            pattern: Pattern with ** prefix
            file_path: File path object

        Returns:
            True if the filename matches the pattern
        """
        simple_pattern = pattern.replace("**/", "")
        return fnmatch.fnmatch(file_path.name, simple_pattern)

    def _matches_normalized_pattern(self, pattern: str, file_str: str) -> bool:
        """Fallback matching by normalizing ** to *.

        Args:
            pattern: Pattern containing **
            file_str: Normalized file path string

        Returns:
            True if the path matches the normalized pattern
        """
        normalized_pattern = pattern.replace("**", "*")
        return fnmatch.fnmatch(file_str, normalized_pattern)

    def analyze_directory(self, directory: Path) -> AnalysisResult:
        """Analyze all Python files in a directory recursively.

        Args:
            directory: Root directory to analyze

        Returns:
            AnalysisResult with all violations and metrics
        """
        # Collect all .py files; filtering happens in analyze_files
        python_files = list(directory.rglob("*.py"))
        return self.analyze_files(python_files, base_dir=directory.parent)

    def analyze_files(
        self,
        files: list[Path],
        base_dir: Path | None = None,
    ) -> AnalysisResult:
        """Analyze a list of Python files.

        Args:
            files: List of file paths to analyze
            base_dir: Base directory for relative path display (optional)

        Returns:
            AnalysisResult with all violations and metrics
        """
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

        # Calculate average MI
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
        """Analyze a single file and update the result.

        Returns FileMetrics for this file.
        """
        metrics = FileMetrics(file_path=relative_path)

        # Check file length
        lines = len(content.splitlines())
        metrics.lines = lines
        result.total_lines += lines

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

        # Parse AST for function analysis
        try:
            tree = ast.parse(content, filename=str(file_path))
            self._check_functions(tree, relative_path, result, metrics)
        except SyntaxError as e:
            print(f"Warning: Syntax error in {file_path}: {e}", file=sys.stderr)

        # Check complexity metrics with radon
        if RADON_AVAILABLE:
            self._check_cyclomatic_complexity(content, relative_path, result, metrics)
            self._check_maintainability_index(content, relative_path, result, metrics, mi_scores)

        return metrics

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

                # Track in metrics
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

        # Fallback for older Python versions
        if not node.body:
            return 1

        last_line = node.lineno
        for stmt in ast.walk(node):
            lineno = getattr(stmt, "lineno", None)
            if lineno:
                last_line = max(last_line, lineno)
            end_lineno = getattr(stmt, "end_lineno", None)
            if end_lineno:
                last_line = max(last_line, end_lineno)
        return last_line - node.lineno + 1

    def _check_cyclomatic_complexity(
        self,
        content: str,
        relative_path: str,
        result: AnalysisResult,
        metrics: FileMetrics,
    ) -> None:
        """Check cyclomatic complexity using radon."""
        try:
            cc_results = cc_visit(content)

            for cc_result in cc_results:
                complexity = cc_result.complexity
                name = cc_result.name
                line = cc_result.lineno
                grade = cc_result.letter

                # Update function metrics if we have a matching function
                for func in metrics.functions:
                    if func["name"] == name and func["line"] == line:
                        func["complexity"] = complexity
                        func["grade"] = grade
                        break

                # Determine severity based on complexity
                if complexity > self.thresholds.cc_critical:
                    severity = Severity.CRITICAL
                elif complexity > self.thresholds.cc_high:
                    severity = Severity.HIGH
                elif complexity > self.thresholds.cc_medium:
                    severity = Severity.MEDIUM
                else:
                    continue  # Not a violation

                result.add_violation(
                    Violation(
                        severity=severity,
                        file_path=relative_path,
                        violation_type="cyclomatic_complexity",
                        message=(
                            f"Function '{name}' has complexity {complexity} "
                            f"(grade {grade}, max {self.thresholds.cc_medium})"
                        ),
                        line=line,
                        function_name=name,
                        value=float(complexity),
                        threshold=float(self.thresholds.cc_medium),
                        grade=grade,
                    )
                )

        except Exception as e:
            print(
                f"Warning: Could not analyze complexity of {relative_path}: {e}",
                file=sys.stderr,
            )

    def _check_maintainability_index(
        self,
        content: str,
        relative_path: str,
        result: AnalysisResult,
        metrics: FileMetrics,
        mi_scores: list[float],
    ) -> None:
        """Check maintainability index using radon."""
        try:
            # multi=True includes comments in calculation (standard formula)
            mi_score = mi_visit(content, multi=True)
            mi_scores.append(float(mi_score))
            metrics.maintainability_index = round(float(mi_score), 1)

            # Determine severity and threshold based on MI score
            # Lower MI = worse maintainability
            if mi_score < self.thresholds.mi_critical:
                severity = Severity.CRITICAL
                mi_threshold = self.thresholds.mi_critical
            elif mi_score < self.thresholds.mi_high:
                severity = Severity.HIGH
                mi_threshold = self.thresholds.mi_high
            elif mi_score < self.thresholds.mi_medium:
                severity = Severity.MEDIUM
                mi_threshold = self.thresholds.mi_medium
            elif mi_score < self.thresholds.mi_low:
                severity = Severity.LOW
                mi_threshold = self.thresholds.mi_low
            else:
                return  # Not a violation

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
