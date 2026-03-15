"""AST split resolver -- expression resolution helpers for the split detector.

Resolves Name, Attribute, Subscript, Call, f-string, BinOp(Add), .replace()
chain expressions to string values via the symbol table.
"""

from __future__ import annotations

import ast

from skill_scan._ast_split_chr import _resolve_chr_call
from skill_scan._ast_split_helpers import _resolve_subscript_expr, _scoped_lookup

_MAX_BINOP_DEPTH = 50


def resolve_binop_chain(
    node: ast.BinOp,
    symbol_table: dict[str, str],
    scope: str,
    *,
    _depth: int = 0,
    alias_map: dict[str, str] | None = None,
) -> str | None:
    """Recursively resolve BinOp(Add) chains, bounded by _MAX_BINOP_DEPTH."""
    if _depth > _MAX_BINOP_DEPTH:
        return None
    left = resolve_operand(node.left, symbol_table, scope, _depth=_depth + 1, alias_map=alias_map)
    if left is None:
        return None
    right = resolve_operand(node.right, symbol_table, scope, _depth=_depth + 1, alias_map=alias_map)
    if right is None:
        return None
    return left + right


def resolve_operand(
    node: ast.expr,
    symbol_table: dict[str, str],
    scope: str,
    *,
    _depth: int = 0,
    alias_map: dict[str, str] | None = None,
) -> str | None:
    """Resolve a single BinOp operand: nested BinOp, expr lookup, or Constant."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return resolve_binop_chain(node, symbol_table, scope, _depth=_depth + 1, alias_map=alias_map)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return resolve_expr(node, symbol_table, scope, alias_map=alias_map)


def resolve_fstring(
    node: ast.JoinedStr,
    symbol_table: dict[str, str],
    scope: str,
    *,
    alias_map: dict[str, str] | None = None,
) -> str | None:
    """Resolve an f-string where all interpolated values are tracked variables."""
    parts: list[str] = []
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            parts.append(value.value)
        elif isinstance(value, ast.FormattedValue):
            resolved = resolve_expr(value.value, symbol_table, scope, alias_map=alias_map)
            if resolved is None:
                return None
            parts.append(resolved)
        else:
            return None
    return "".join(parts)


def resolve_call_return(
    node: ast.Call,
    symbol_table: dict[str, str],
    scope: str,
) -> str | None:
    """Resolve a Call node to a string via tracked return-value composite key.

    Looks up the function's return value in the symbol table using the
    parentheses-suffix convention established by build_symbol_table():
    - ``func()`` for plain function calls
    - ``ClassName.method()`` for self/cls.method() or ClassName.method() calls
    Returns None for unknown/untracked functions.
    """
    func = node.func
    if isinstance(func, ast.Name):
        return symbol_table.get(f"{func.id}()")
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        base, attr = func.value.id, func.attr
        # Direct ClassName.method() lookup
        direct_key = f"{base}.{attr}()"
        if direct_key in symbol_table:
            return symbol_table[direct_key]
        # self/cls.method() -> look up as scope.method()
        if scope and base in ("self", "cls"):
            return symbol_table.get(f"{scope}.{attr}()")
        return None
    return None


def resolve_expr(
    node: ast.expr,
    symbol_table: dict[str, str],
    scope: str,
    alias_map: dict[str, str] | None = None,
) -> str | None:
    """Resolve a Name, Attribute, Subscript, or Call expression via symbol table."""
    if isinstance(node, ast.Name):
        return _scoped_lookup(node.id, symbol_table, scope)
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        base, attr = node.value.id, node.attr
        # Only resolve self/cls.attr or ClassName.attr (not arbitrary obj.attr)
        key = f"{base}.{attr}"
        if key in symbol_table:
            return symbol_table[key]
        if scope and base in ("self", "cls"):
            return symbol_table.get(f"{scope}.{attr}")
        return None
    if isinstance(node, ast.Call):
        chr_result = _resolve_chr_call(node)
        if chr_result is not None:
            return chr_result
        bytes_result = resolve_bytes_constructor(node, alias_map)
        if bytes_result is not None:
            return bytes_result
        return resolve_call_return(node, symbol_table, scope)
    return _resolve_subscript_lookup(node, symbol_table, scope)


def _resolve_subscript_lookup(node: ast.expr, symbol_table: dict[str, str], scope: str) -> str | None:
    """Resolve ast.Subscript (string key or int index) via composite key lookup."""
    if not isinstance(node, ast.Subscript):
        return None
    return _resolve_subscript_expr(node, symbol_table, scope)


def resolve_percent_format(
    node: ast.BinOp,
    symbol_table: dict[str, str],
    scope: str,
    *,
    alias_map: dict[str, str] | None = None,
) -> str | None:
    """Resolve BinOp(Mod) %-format expressions. Registry-compatible wrapper."""
    return _resolve_percent_format(node, symbol_table, scope)


def resolve_call(
    node: ast.Call,
    symbol_table: dict[str, str],
    scope: str,
    *,
    alias_map: dict[str, str] | None = None,
) -> str | None:
    """Resolve Call nodes: join, format, bytes-constructor, reduce, or call-return.

    Registry-compatible wrapper that chains all Call sub-resolvers.
    """
    am = alias_map or {}
    result = _resolve_join_call(node, symbol_table, scope, am)
    if result is None:
        result = _resolve_format_call(node, symbol_table, scope)
    if result is not None:
        return result
    bytes_result = resolve_bytes_constructor(node, am)
    if bytes_result is not None:
        return bytes_result
    reduce_result = _resolve_reduce_concat(node, symbol_table, scope, alias_map=am)
    if reduce_result is not None:
        return reduce_result
    return resolve_call_return(node, symbol_table, scope)


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


def _resolve_base_string(node: ast.expr, symbol_table: dict[str, str], scope: str) -> str | None:
    """Resolve the base expression of a replace chain to a string."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return _scoped_lookup(node.id, symbol_table, scope)
    return None


def _resolve_replace_chain(
    node: ast.Call,
    symbol_table: dict[str, str],
    scope: str,
    *,
    alias_map: dict[str, str] | None = None,
) -> str | None:
    """Resolve chained .replace(old, new) calls to a final string."""
    replacements: list[tuple[str, str]] = []
    cur: ast.expr = node
    for _ in range(20):  # MAX_REPLACE_DEPTH
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
    base = _resolve_base_string(cur, symbol_table, scope)
    if base is None:
        return None
    # Apply replacements left-to-right (first collected = innermost)
    for old_val, new_val in reversed(replacements):
        base = base.replace(old_val, new_val)
    return base


# re-export at BOTTOM -- Facade Re-export Pattern
from skill_scan._ast_split_bytes import resolve_bytes_constructor as resolve_bytes_constructor  # noqa: E402
from skill_scan._ast_split_helpers import (  # noqa: E402
    _resolve_format_call as _resolve_format_call,
    _resolve_percent_format as _resolve_percent_format,
)
from skill_scan._ast_split_join_helpers import _resolve_join_call as _resolve_join_call  # noqa: E402
from skill_scan._ast_split_reduce import _resolve_reduce_concat as _resolve_reduce_concat  # noqa: E402
