"""Complexity analysis module for code quality checks.

This module provides shared functionality for analyzing Python code complexity:
- File length checking
- Function length checking (via AST)
- Cyclomatic complexity (via radon)
- Maintainability Index (via radon)

Used by:
- python -m scripts.complexity: Unified pre-commit and CI gate
- complexity_report.py: Reporter for trends and historical tracking
"""

from scripts.complexity.analyzer import CodeAnalyzer, Thresholds
from scripts.complexity.models import (
    AnalysisResult,
    FileMetrics,
    Severity,
    Violation,
)

__all__ = [
    "AnalysisResult",
    "CodeAnalyzer",
    "FileMetrics",
    "Severity",
    "Thresholds",
    "Violation",
]
