"""Call-return tracking helpers for split-evasion detection.

Resolves Call nodes via tracked return-value composite keys in the symbol
table, and provides predicates to check whether any leaf of an expression
resolves via call-return tracking.
"""

from __future__ import annotations

import ast


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
