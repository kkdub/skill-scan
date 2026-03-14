"""AST split resolver -- expression resolution helpers for the split detector.

Resolves Name, Attribute, Subscript, Call, f-string, and BinOp(Add)
expressions to string values via the symbol table. Used by
_ast_split_detector to reconstruct payloads assembled from split variables.
"""

from __future__ import annotations

import ast

from skill_scan._ast_split_helpers import _resolve_subscript_expr, _scoped_lookup

_MAX_BINOP_DEPTH = 50
_MAX_INT_DEPTH = 50


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


def _resolve_chr_call(node: ast.Call) -> str | None:
    """Resolve chr(N), chr(ord('x')), or chr(ord('x') + N) to a character.

    Handles:
    - chr(integer_literal): direct character lookup
    - chr(ord('x')): nested ord() with single-character string
    - chr(ord('x') + N): arithmetic on ord() result (padding resistance)

    Returns None for non-constant arguments (R-IMP003).
    """
    if not (isinstance(node.func, ast.Name) and node.func.id == "chr"):
        return None
    if len(node.args) != 1 or node.keywords:
        return None
    return _resolve_chr_arg(node.args[0])


def _resolve_chr_arg(arg: ast.expr) -> str | None:
    """Resolve the argument to chr() as an integer, then convert to character."""
    val = _resolve_int_arg(arg, _depth=0)
    if val is not None and 0 <= val <= 0x10FFFF:
        return chr(val)
    return None


def _resolve_int_arg(node: ast.expr, *, _depth: int = 0) -> int | None:
    """Resolve an expression to an integer: literal, ord(), or BinOp arithmetic."""
    if _depth > _MAX_INT_DEPTH:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    # ord('x') -> integer
    if isinstance(node, ast.Call):
        return _resolve_ord_call(node)
    # BinOp: e.g. ord('x') + 0, 100 + 1
    if isinstance(node, ast.BinOp):
        return _resolve_int_binop(node, _depth=_depth + 1)
    return None


def _resolve_ord_call(node: ast.Call) -> int | None:
    """Resolve ord('x') to its integer value."""
    if not (isinstance(node.func, ast.Name) and node.func.id == "ord"):
        return None
    if len(node.args) != 1 or node.keywords:
        return None
    arg = node.args[0]
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and len(arg.value) == 1:
        return ord(arg.value)
    return None


def _resolve_int_binop(node: ast.BinOp, *, _depth: int = 0) -> int | None:
    """Resolve integer BinOp (Add, Sub, Mult) on resolvable integer operands."""
    if _depth > _MAX_INT_DEPTH:
        return None
    left = _resolve_int_arg(node.left, _depth=_depth + 1)
    right = _resolve_int_arg(node.right, _depth=_depth + 1)
    if left is None or right is None:
        return None
    if isinstance(node.op, ast.Add):
        return left + right
    if isinstance(node.op, ast.Sub):
        return left - right
    if isinstance(node.op, ast.Mult):
        return left * right
    return None


def _resolve_subscript_lookup(node: ast.expr, symbol_table: dict[str, str], scope: str) -> str | None:
    """Resolve ast.Subscript (string key or int index) via composite key lookup."""
    if not isinstance(node, ast.Subscript):
        return None
    return _resolve_subscript_expr(node, symbol_table, scope)


# re-export at BOTTOM -- Facade Re-export Pattern
from skill_scan._ast_split_bytes import (  # noqa: E402
    resolve_bytes_constructor as resolve_bytes_constructor,
)
