"""AST split resolver -- expression resolution helpers for the split detector.

Resolves Name, Attribute, Subscript, Call, f-string, BinOp(Add), .replace(),
and case-method chain expressions to string values via the symbol table.
"""

from __future__ import annotations

import ast

from skill_scan._ast_split_chr import _resolve_chr_call
from skill_scan._ast_split_format import _resolve_subscript_expr, _scoped_lookup

_MAX_BINOP_DEPTH = 50


def _joinedstr_has_call_return(node: ast.JoinedStr, st: dict[str, str], sc: str) -> bool:
    """True when any f-string interpolation resolves via call-return tracking."""
    return any(
        isinstance(v, ast.FormattedValue)
        and isinstance(v.value, ast.Call)
        and resolve_call_return(v.value, st, sc) is not None
        for v in node.values
    )


def _label_from_call_return(node: ast.expr, st: dict[str, str], sc: str) -> bool:
    """True when any leaf of *node* resolves via call-return tracking."""
    if isinstance(node, ast.Call):
        return resolve_call_return(node, st, sc) is not None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _label_from_call_return(node.left, st, sc) or _label_from_call_return(node.right, st, sc)
    if isinstance(node, ast.Tuple):
        return any(_label_from_call_return(e, st, sc) for e in node.elts)
    if isinstance(node, ast.JoinedStr):
        return _joinedstr_has_call_return(node, st, sc)
    return False


def resolve_binop_chain(
    node: ast.BinOp,
    symbol_table: dict[str, str],
    scope: str,
    *,
    _depth: int = 0,
    alias_map: dict[str, str] | None = None,
) -> tuple[str, str] | None:
    """Recursively resolve BinOp(Add) chains, bounded by _MAX_BINOP_DEPTH."""
    if _depth > _MAX_BINOP_DEPTH:
        return None
    left = resolve_operand(node.left, symbol_table, scope, _depth=_depth + 1, alias_map=alias_map)
    if left is None:
        return None
    right = resolve_operand(node.right, symbol_table, scope, _depth=_depth + 1, alias_map=alias_map)
    if right is None:
        return None
    label = "call-return" if _label_from_call_return(node, symbol_table, scope) else "split variable"
    return (left + right, label)


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
        result = resolve_binop_chain(node, symbol_table, scope, _depth=_depth + 1, alias_map=alias_map)
        return result[0] if result is not None else None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return resolve_expr(node, symbol_table, scope, alias_map=alias_map)


def resolve_fstring(
    node: ast.JoinedStr,
    symbol_table: dict[str, str],
    scope: str,
    *,
    alias_map: dict[str, str] | None = None,
) -> tuple[str, str] | None:
    """Resolve an f-string where all interpolated values are tracked variables."""
    parts: list[str] = []
    has_cr = False
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            parts.append(value.value)
        elif isinstance(value, ast.FormattedValue):
            resolved = resolve_expr(value.value, symbol_table, scope, alias_map=alias_map)
            if resolved is None:
                return None
            parts.append(resolved)
            if isinstance(value.value, ast.Call):
                has_cr = has_cr or resolve_call_return(value.value, symbol_table, scope) is not None
        else:
            return None
    return ("".join(parts), "call-return" if has_cr else "split variable")


def resolve_call_return(
    node: ast.Call,
    symbol_table: dict[str, str],
    scope: str,
) -> str | None:
    """Resolve a Call node via tracked return-value composite key."""
    func = node.func
    if isinstance(func, ast.Name):
        # Try scoped key first (nested functions: outer.inner()), then bare
        if scope:
            scoped = symbol_table.get(f"{scope}.{func.id}()")
            if scoped is not None:
                return scoped
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


def _resolve_call_expr(node: ast.Call, st: dict[str, str], sc: str, am: dict[str, str] | None) -> str | None:
    """Resolve a Call expression: chr(), bytes constructor, or call-return."""
    cr = _resolve_chr_call(node)
    if cr is not None:
        return cr
    br = resolve_bytes_constructor(node, am)
    return br if br is not None else resolve_call_return(node, st, sc)


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
        key = f"{base}.{attr}"
        if key in symbol_table:
            return symbol_table[key]
        if scope and base in ("self", "cls"):
            return symbol_table.get(f"{scope}.{attr}")
        return None
    if isinstance(node, ast.Call):
        return _resolve_call_expr(node, symbol_table, scope, alias_map)
    if isinstance(node, ast.Subscript):
        return _resolve_subscript_expr(node, symbol_table, scope)
    return None


def resolve_subscript(
    node: ast.Subscript,
    symbol_table: dict[str, str],
    scope: str,
    *,
    alias_map: dict[str, str] | None = None,
) -> tuple[str, str] | None:
    """Resolve ast.Subscript (key lookup or slice). Registry-compatible wrapper."""
    result = _resolve_subscript_expr(node, symbol_table, scope)
    return (result, "split variable") if result is not None else None


def resolve_percent_format(
    node: ast.BinOp,
    symbol_table: dict[str, str],
    scope: str,
    *,
    alias_map: dict[str, str] | None = None,
) -> tuple[str, str] | None:
    """Resolve BinOp(Mod) %-format expressions. Registry-compatible wrapper."""
    result = _resolve_percent_format(node, symbol_table, scope)
    if result is None:
        return None
    label = "call-return" if _label_from_call_return(node.right, symbol_table, scope) else "split variable"
    return (result, label)


def resolve_call(
    node: ast.Call,
    symbol_table: dict[str, str],
    scope: str,
    *,
    alias_map: dict[str, str] | None = None,
    int_list_table: dict[str, list[int]] | None = None,
    int_list_scope: str = "",
) -> tuple[str, str] | None:
    """Resolve Call nodes: join, format, format_map, bytes, reduce, or call-return."""
    am = alias_map or {}
    result = _resolve_join_call(
        node,
        symbol_table,
        scope,
        am,
        int_list_table=int_list_table,
        int_list_scope=int_list_scope,
    )
    if result is None:
        result = _resolve_format_call(node, symbol_table, scope)
    if result is None:
        result = _resolve_format_map_call(node, symbol_table, scope)
    if result is not None:
        return (result, "split variable")
    bytes_result = resolve_bytes_constructor(node, am)
    if bytes_result is not None:
        return (bytes_result, "split variable")
    reduce_result = _resolve_reduce_concat(node, symbol_table, scope, alias_map=am)
    if reduce_result is not None:
        return (reduce_result, "split variable")
    cr = resolve_call_return(node, symbol_table, scope)
    return (cr, "call-return") if cr is not None else None


# re-export at BOTTOM -- Facade Re-export Pattern
from skill_scan._ast_split_bytes import resolve_bytes_constructor as resolve_bytes_constructor  # noqa: E402
from skill_scan._ast_split_format import (  # noqa: E402
    _resolve_format_call as _resolve_format_call,
    _resolve_percent_format as _resolve_percent_format,
)
from skill_scan._ast_split_comprehension import _resolve_join_call as _resolve_join_call  # noqa: E402
from skill_scan._ast_split_method_chains import (  # noqa: E402
    _is_case_method as _is_case_method,
    _resolve_case_method_chain as _resolve_case_method_chain,
    _resolve_replace_chain as _resolve_replace_chain,
)
from skill_scan._ast_split_format_map import (  # noqa: E402
    _lookup_str_dict as _lookup_str_dict,
    _resolve_format_map_call as _resolve_format_map_call,
)
from skill_scan._ast_split_reduce import _resolve_reduce_concat as _resolve_reduce_concat  # noqa: E402
