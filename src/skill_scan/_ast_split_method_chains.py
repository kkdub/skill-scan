"""Replace chain and case method chain resolvers for split-evasion detection.

Extracted from _ast_split_resolve.py to keep files under the 300-line limit.
Handles .replace(old, new) chains and .lower()/.upper()/etc. case method chains.
"""

from __future__ import annotations

import ast

from skill_scan._ast_split_format import _scoped_lookup
from skill_scan._ast_split_resolve import (
    resolve_binop_chain,
    resolve_call,
    resolve_expr,
    resolve_fstring,
)


_MAX_CHAIN_DEPTH = 20


def _is_replace_call(node: ast.expr) -> bool:
    """Check if node is a .replace(old, new) call with two positional args."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "replace"
        and len(node.args) == 2
        and not node.keywords
    )


def _extract_replace_pair(call: ast.Call) -> tuple[str, str] | None:
    """Extract (old, new) string pair from a .replace() call, or None."""
    old_arg, new_arg = call.args
    if (
        isinstance(old_arg, ast.Constant)
        and isinstance(old_arg.value, str)
        and isinstance(new_arg, ast.Constant)
        and isinstance(new_arg.value, str)
    ):
        return (old_arg.value, new_arg.value)
    return None


def _resolve_base_tuple(
    node: ast.expr,
    symbol_table: dict[str, str],
    scope: str,
    *,
    alias_map: dict[str, str] | None = None,
) -> tuple[str, str] | None:
    """Try tuple-returning resolvers for base expression dispatch."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return resolve_binop_chain(node, symbol_table, scope, alias_map=alias_map)
    if isinstance(node, ast.JoinedStr):
        return resolve_fstring(node, symbol_table, scope, alias_map=alias_map)
    if _is_replace_call(node):
        assert isinstance(node, ast.Call)  # narrowed by _is_replace_call
        return _resolve_replace_chain(node, symbol_table, scope, alias_map=alias_map)
    if isinstance(node, ast.Call):
        return resolve_call(node, symbol_table, scope, alias_map=alias_map)
    return None


def _resolve_base_string(
    node: ast.expr,
    symbol_table: dict[str, str],
    scope: str,
    *,
    alias_map: dict[str, str] | None = None,
) -> str | None:
    """Resolve a base expression through all available resolvers."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return _scoped_lookup(node.id, symbol_table, scope)
    pair = _resolve_base_tuple(node, symbol_table, scope, alias_map=alias_map)
    if pair is not None:
        return pair[0]
    return resolve_expr(node, symbol_table, scope, alias_map=alias_map)


def _resolve_replace_chain(
    node: ast.Call,
    symbol_table: dict[str, str],
    scope: str,
    *,
    alias_map: dict[str, str] | None = None,
) -> tuple[str, str] | None:
    """Resolve chained .replace(old, new) calls to a final string."""
    replacements: list[tuple[str, str]] = []
    cur: ast.expr = node
    for _ in range(_MAX_CHAIN_DEPTH):
        if not _is_replace_call(cur):
            break
        assert isinstance(cur, ast.Call)  # narrowing for mypy
        pair = _extract_replace_pair(cur)
        if pair is None:
            return None
        replacements.append(pair)
        assert isinstance(cur.func, ast.Attribute)  # narrowed by _is_replace_call
        cur = cur.func.value
    if not replacements:
        return None
    base = _resolve_base_string(cur, symbol_table, scope, alias_map=alias_map)
    if base is None:
        return None
    # Apply replacements left-to-right (first collected = innermost)
    for old_val, new_val in reversed(replacements):
        base = base.replace(old_val, new_val)
    return (base, "split variable")


_CASE_METHODS = frozenset({"lower", "upper", "title", "swapcase", "capitalize", "casefold"})


def _is_case_method(node: ast.expr) -> bool:
    """Check if node is a .lower()/.upper()/etc. call with no arguments."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _CASE_METHODS
        and not node.args
        and not node.keywords
    )


def _resolve_case_method_chain(
    node: ast.Call,
    symbol_table: dict[str, str],
    scope: str,
    *,
    alias_map: dict[str, str] | None = None,
) -> tuple[str, str] | None:
    """Resolve chained .lower()/.upper()/etc. calls to a final string."""
    methods: list[str] = []
    cur: ast.expr = node
    for _ in range(_MAX_CHAIN_DEPTH):
        if not _is_case_method(cur):
            break
        assert isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute)
        methods.append(cur.func.attr)
        cur = cur.func.value
    if not methods:
        return None
    base = _resolve_base_string(cur, symbol_table, scope, alias_map=alias_map)
    if base is None:
        return None
    for method_name in reversed(methods):
        base = getattr(base, method_name)()
    return (base, "split variable")
