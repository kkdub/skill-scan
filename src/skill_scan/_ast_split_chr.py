"""AST split chr/ord resolver -- resolve chr(), ord(), and integer arithmetic.

Handles chr(N), chr(ord('x')), chr(ord('x') + N) and nested integer
BinOp arithmetic for the split detector.
"""

from __future__ import annotations

import ast

_MAX_INT_DEPTH = 50


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
