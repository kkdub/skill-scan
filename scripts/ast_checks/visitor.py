"""AST visitor that detects antipattern violations."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

from . import checks
from .models import Violation


class AntipatternVisitor(ast.NodeVisitor):
    """Visit AST nodes and collect antipattern violations.

    Individual rule logic lives in :mod:`checks`; this class only
    dispatches AST events and records results.
    """

    def __init__(self, filepath: Path) -> None:
        self.filepath = filepath
        self.violations: list[Violation] = []
        self._current_class: str | None = None
        self._class_bases: dict[str, list[str]] = {}
        self._visited_ifs: set[int] = set()

    # -- helpers -------------------------------------------------------------

    def _add(self, rule_id: str, name: str, line: int, message: str, severity: str = "info") -> None:
        self.violations.append(Violation(rule_id, name, self.filepath, line, message, severity))

    def _emit(self, rule_id: str, name: str, node: ast.AST, msg: str | None, severity: str = "info") -> None:
        """Record a violation when *msg* is not ``None``."""
        if msg is not None:
            self._add(rule_id, name, getattr(node, "lineno", 0), msg, severity)

    # -- class visitors ------------------------------------------------------

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        base_names = checks.extract_base_class_names(node.bases)
        self._class_bases[node.name] = base_names

        self._emit("DATA-001", "Dataclass without slots", node, checks.check_dataclass_slots(node))
        self._emit(
            "INHERIT-002",
            "Deep inheritance",
            node,
            checks.check_inheritance_depth(node, base_names),
        )

        prev_class = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = prev_class

    # -- function visitors ---------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function(node)

    def _check_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._emit("SIZE-002", "Function too long", node, checks.check_function_size(node), "warning")
        self._emit(
            "TYPE-003",
            "Use Self type",
            node,
            checks.check_self_return_type(node, self._current_class),
        )
        self._emit(
            "INHERIT-001",
            "Missing @override",
            node,
            checks.check_override_decorator(node, self._current_class, self._class_bases),
        )
        self.generic_visit(node)

    # -- control-flow visitors -----------------------------------------------

    def visit_If(self, node: ast.If) -> None:
        if id(node) not in self._visited_ifs:
            self._emit(
                "CONTROL-001",
                "Consider match",
                node,
                checks.check_elif_chain(node, self._visited_ifs),
            )
        self.generic_visit(node)
