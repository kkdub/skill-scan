#!/usr/bin/env python3
"""AST analysis for detecting mixed decision/infrastructure code."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .constants import (
    DECISION_FUNCTIONS,
    DIR_SEVERITY,
    FILE_SEVERITY,
    Severity,
)
from .infra import infra_signals_for_node
from .models import DecisionSignal, InfraSignal

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


# Simple AST node types that always indicate decision logic (no extra checks).
_SIMPLE_DECISION_MAP: list[tuple[type[ast.AST], str]] = [
    (ast.If, "if"),
    (ast.Match, "match"),
    (ast.Raise, "raise"),
    (ast.Assert, "assert"),
    (ast.IfExp, "ternary"),
    (ast.Try, "try"),
]


def get_file_severity(path: Path) -> Severity:
    """Determine severity level for a file based on its path.

    Files in infrastructure/glue layers get lower severity.
    Core domain code gets CRITICAL severity.
    """
    # Check filename first
    if path.name in FILE_SEVERITY:
        return FILE_SEVERITY[path.name]

    # Check directory hierarchy
    for part in path.parts:
        if part in DIR_SEVERITY:
            return DIR_SEVERITY[part]

    # Default to CRITICAL for core domain code
    return Severity.CRITICAL


@dataclass(slots=True)
class FunctionResult:
    """Analysis result for a single function."""

    file: Path
    name: str
    line: int
    end_line: int  # For density calculation
    decision_signals: list[DecisionSignal] = field(default_factory=list)
    infra_signals: list[InfraSignal] = field(default_factory=list)
    severity: Severity = Severity.CRITICAL

    @property
    def is_mixed(self) -> bool:
        """True if function has both decision and infra signals."""
        return bool(self.decision_signals and self.infra_signals)

    @property
    def line_count(self) -> int:
        """Number of lines in the function."""
        return max(self.end_line - self.line + 1, 1)

    @property
    def score(self) -> int:
        """Higher score = more mixing. Weight by variety and count."""
        if not self.is_mixed:
            return 0
        decision_count = len(self.decision_signals)
        infra_count = len(self.infra_signals)
        infra_categories = len({s.category for s in self.infra_signals})
        # Score: infra variety matters more than raw counts
        return (infra_categories * 10) + (decision_count * infra_count)

    @property
    def density(self) -> float:
        """Smell density: score per 10 lines of code.

        Higher density = more concentrated mixing = worse smell.
        A 10-line function with score 20 (density 20) is worse than
        a 100-line function with score 50 (density 5).
        """
        if not self.is_mixed:
            return 0.0
        return (self.score / self.line_count) * 10

    @property
    def effective_score(self) -> float:
        """Combined score weighted by severity and density.

        CRITICAL severity gets 3x weight, WARNING gets 1.5x, INFO gets 1x.
        """
        severity_weight = {
            Severity.CRITICAL: 3.0,
            Severity.WARNING: 1.5,
            Severity.INFO: 1.0,
        }
        weight = severity_weight.get(self.severity, 1.0)
        # Combine raw score with density for effective ranking
        return (self.score + self.density) * weight

    def format_location(self, repo_root: Path) -> str:
        """Format as file:function:line."""
        try:
            rel_path = self.file.relative_to(repo_root)
        except ValueError:
            rel_path = self.file
        return f"{rel_path}:{self.name}:{self.line}"


class FunctionAnalyzer(ast.NodeVisitor):
    """AST visitor that analyzes a single function for mixed signals."""

    def __init__(self) -> None:
        self.decision_signals: list[DecisionSignal] = []
        self.infra_signals: list[InfraSignal] = []
        self._in_function = False

    def analyze(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Analyze a function node for mixed signals."""
        self._in_function = True
        for child in ast.walk(node):
            self._check_decision(child)
            self.infra_signals.extend(infra_signals_for_node(child))
        self._in_function = False

    def _check_decision(self, node: ast.AST) -> None:
        """Check if node represents decision logic. Data-driven for simple cases."""
        for node_type, kind in _SIMPLE_DECISION_MAP:
            if isinstance(node, node_type):
                lineno = getattr(node, "lineno", 0)
                self.decision_signals.append(DecisionSignal(kind, lineno))
                return
        signal = self._decision_from_comprehension(node) or self._decision_from_call(node)
        if signal is not None:
            self.decision_signals.append(signal)

    def _decision_from_comprehension(self, node: ast.AST) -> DecisionSignal | None:
        """Return a decision signal if node is a comprehension with an if clause."""
        if not isinstance(
            node,
            ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp,
        ):
            return None
        if self._has_if_clause(node):
            return DecisionSignal("comprehension", node.lineno)
        return None

    def _decision_from_call(self, node: ast.AST) -> DecisionSignal | None:
        """Return a decision signal if node is a call to any/all/isinstance/etc."""
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            return None
        if node.func.id in DECISION_FUNCTIONS:
            return DecisionSignal(node.func.id, node.lineno)
        return None

    def _has_if_clause(self, node: ast.AST) -> bool:
        """Check if a comprehension/generator has an if clause."""
        generators: list[ast.comprehension] = []
        match node:
            case ast.ListComp(generators=gens):
                generators = gens
            case ast.SetComp(generators=gens):
                generators = gens
            case ast.GeneratorExp(generators=gens):
                generators = gens
            case ast.DictComp(generators=gens):
                generators = gens
        return any(gen.ifs for gen in generators)


def scan_file(path: Path) -> Iterator[FunctionResult]:
    """Scan a Python file for mixed functions."""
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return

    # Get file severity once for all functions
    severity = get_file_severity(path)

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue

        analyzer = FunctionAnalyzer()
        analyzer.analyze(node)

        if analyzer.decision_signals and analyzer.infra_signals:
            yield FunctionResult(
                file=path,
                name=node.name,
                line=node.lineno,
                end_line=node.end_lineno or node.lineno,
                decision_signals=analyzer.decision_signals,
                infra_signals=analyzer.infra_signals,
                severity=severity,
            )
