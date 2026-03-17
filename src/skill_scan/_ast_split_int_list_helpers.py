"""Int-list tracking helpers for the pre-pass collector.

Handles assignment, AugAssign (+=), and .extend() mutations on tracked
int-list variables. Imported by ``_ast_split_join_helpers``.

Shadow marker: ``_SHADOW`` is a module-level sentinel list used to mark
variables that were assigned a non-int-list value.  We compare by identity
(``existing is _SHADOW``) so that a legitimate empty int list (``codes = []``)
is not confused with a shadowed variable.
"""

from __future__ import annotations

import ast

_SHADOW: list[int] = []
"""Identity sentinel -- never mutate.  Used as shadow marker in int-list table."""


def _extract_int_list(elts: list[ast.expr]) -> list[int] | None:
    """Extract a list of int constants, or None if any element is non-int."""
    values: list[int] = []
    for elt in elts:
        if not isinstance(elt, ast.Constant) or not isinstance(elt.value, int):
            return None
        values.append(elt.value)
    return values


def _handle_int_list_stmt(stmt: ast.stmt, scope: str, result: dict[str, list[int]]) -> None:
    """Dispatch a single statement for int-list tracking."""
    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
        _handle_assign(stmt, scope, result)
    elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.op, ast.Add):
        if isinstance(stmt.target, ast.Name):
            _extend_tracked(stmt.target.id, stmt.value, scope, result)
    elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        _handle_extend_call(stmt.value, scope, result)


def _handle_assign(stmt: ast.Assign, scope: str, result: dict[str, list[int]]) -> None:
    """Track Name = <expr> assignments for int-list pre-pass."""
    tgt = stmt.targets[0]
    if not isinstance(tgt, ast.Name):
        return
    key = f"{scope}.{tgt.id}" if scope else tgt.id
    if isinstance(stmt.value, ast.List | ast.Tuple):
        ints = _extract_int_list(stmt.value.elts)
        result[key] = ints if ints is not None else _SHADOW
    else:
        result[key] = _SHADOW


def _handle_extend_call(call: ast.Call, scope: str, result: dict[str, list[int]]) -> None:
    """Handle codes.extend([...]) calls on tracked variables."""
    if not (isinstance(call.func, ast.Attribute) and call.func.attr == "extend"):
        return
    if not (isinstance(call.func.value, ast.Name) and len(call.args) == 1 and not call.keywords):
        return
    arg = call.args[0]
    if isinstance(arg, ast.List | ast.Tuple):
        _extend_tracked(call.func.value.id, arg, scope, result)


def _extend_tracked(name: str, value: ast.expr, scope: str, result: dict[str, list[int]]) -> None:
    """Extend a tracked int-list via += or .extend(); ignore unknown variables."""
    key = f"{scope}.{name}" if scope else name
    if key not in result:
        return
    existing = result[key]
    if not isinstance(value, ast.List | ast.Tuple):
        result[key] = _SHADOW
        return
    if existing is _SHADOW:
        return
    ints = _extract_int_list(value.elts)
    result[key] = (existing + ints) if ints is not None else _SHADOW
