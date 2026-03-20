"""ROT13 branch case analysis helpers (extracted from _ast_rot13.py, PLAN-033).

Determines whether an If-node tests a lowercase or uppercase character range.
"""

from __future__ import annotations

import ast


def _branch_case(if_node: ast.If, is_orelse: bool) -> str | None:
    """Return 'lower'/'upper' from an If-node's test, or None.

    When *is_orelse* is True, inspect the elif branch's test instead.
    """
    test = if_node.test
    if is_orelse and if_node.orelse and isinstance(if_node.orelse[0], ast.If):
        test = if_node.orelse[0].test
    return _compare_case(test)


def _compare_case(node: ast.expr) -> str | None:
    """Extract 'lower' or 'upper' from a Compare node like 'a' <= c <= 'z'."""
    if isinstance(node, ast.Compare):
        return _case_from_comparators(node)
    # Handle BoolOp (e.g., ``c >= 'a' and c <= 'z'``)
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        return _first_case_from_boolop(node)
    return None


def _case_from_comparators(node: ast.Compare) -> str | None:
    """Return 'lower'/'upper' by scanning constant nodes in a Compare."""
    candidates: list[ast.expr] = list(node.comparators)
    if isinstance(node.left, ast.Constant):
        candidates.insert(0, node.left)
    for comp in candidates:
        result = _case_from_constant(comp)
        if result is not None:
            return result
    return None


def _case_from_constant(node: ast.expr) -> str | None:
    """Return 'lower'/'upper' if *node* is a string sentinel for a letter range."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        if node.value in ("a", "z"):
            return "lower"
        if node.value in ("A", "Z"):
            return "upper"
    return None


def _first_case_from_boolop(node: ast.BoolOp) -> str | None:
    """Return the first non-None case result from BoolOp child values."""
    for val in node.values:
        result = _compare_case(val)
        if result is not None:
            return result
    return None
