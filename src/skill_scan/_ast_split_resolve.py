"""AST split resolver -- expression resolution helpers for the split detector.

Resolves Name, Attribute, Subscript, f-string, and BinOp(Add) expressions
to string values via the symbol table. Used by _ast_split_detector to
reconstruct payloads assembled from split variables.
"""

from __future__ import annotations

import ast

from skill_scan._ast_split_helpers import _resolve_subscript_expr, _scoped_lookup

_MAX_BINOP_DEPTH = 50


def resolve_binop_chain(
    node: ast.BinOp,
    symbol_table: dict[str, str],
    scope: str,
    *,
    _depth: int = 0,
) -> str | None:
    """Recursively resolve BinOp(Add) chains, bounded by _MAX_BINOP_DEPTH."""
    if _depth > _MAX_BINOP_DEPTH:
        return None
    left = resolve_operand(node.left, symbol_table, scope, _depth=_depth + 1)
    if left is None:
        return None
    right = resolve_operand(node.right, symbol_table, scope, _depth=_depth + 1)
    if right is None:
        return None
    return left + right


def resolve_operand(
    node: ast.expr,
    symbol_table: dict[str, str],
    scope: str,
    *,
    _depth: int = 0,
) -> str | None:
    """Resolve a single BinOp operand: nested BinOp, expr lookup, or Constant."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return resolve_binop_chain(node, symbol_table, scope, _depth=_depth + 1)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return resolve_expr(node, symbol_table, scope)


def resolve_fstring(node: ast.JoinedStr, symbol_table: dict[str, str], scope: str) -> str | None:
    """Resolve an f-string where all interpolated values are tracked variables."""
    parts: list[str] = []
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            parts.append(value.value)
        elif isinstance(value, ast.FormattedValue):
            resolved = resolve_expr(value.value, symbol_table, scope)
            if resolved is None:
                return None
            parts.append(resolved)
        else:
            return None
    return "".join(parts)


def resolve_expr(node: ast.expr, symbol_table: dict[str, str], scope: str) -> str | None:
    """Resolve a Name, Attribute, or Subscript expression via symbol table."""
    if isinstance(node, ast.Name):
        return _scoped_lookup(node.id, symbol_table, scope)
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return _scoped_lookup(node.attr, symbol_table, scope)
    return _resolve_subscript_lookup(node, symbol_table, scope)


def _resolve_subscript_lookup(node: ast.expr, symbol_table: dict[str, str], scope: str) -> str | None:
    """Resolve ast.Subscript (string key or int index) via composite key lookup."""
    if not isinstance(node, ast.Subscript):
        return None
    return _resolve_subscript_expr(node, symbol_table, scope)
