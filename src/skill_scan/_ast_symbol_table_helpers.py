"""Private assignment-tracking helpers used by the symbol table builder.

Extracted from _ast_symbol_table.py. These functions walk statement bodies
and collect string assignments (Name targets, tuple/list unpacking,
augmented assignment, walrus operator) into a mutable table.
"""

from __future__ import annotations

import ast

from skill_scan._ast_helpers import _resolve_int_expr, try_resolve_string
from skill_scan._ast_symbol_table import _Ref


def _walk_body(body: list[ast.stmt], table: dict[str, str | _Ref]) -> None:
    """Walk a statement list, collecting assignments into table."""
    for stmt in body:
        _process_stmt(stmt, table)


def _process_stmt(stmt: ast.stmt, table: dict[str, str | _Ref]) -> None:
    """Process a single statement for assignment tracking."""
    if isinstance(stmt, ast.Assign):
        _handle_assign(stmt, table)
    elif isinstance(stmt, ast.AugAssign):
        _handle_aug_assign(stmt, table)
    else:
        _recurse_control_flow(stmt, table)
    _collect_walrus(stmt, table)


def _recurse_control_flow(stmt: ast.stmt, table: dict[str, str | _Ref]) -> None:
    """Recurse into control flow bodies (if/for/while/with/try)."""
    if isinstance(stmt, ast.If):
        _walk_body(stmt.body, table)
        _walk_body(stmt.orelse, table)
    elif isinstance(stmt, ast.For | ast.While):
        _walk_body(stmt.body, table)
        _walk_body(stmt.orelse, table)
    elif isinstance(stmt, ast.With):
        _walk_body(stmt.body, table)
    elif isinstance(stmt, ast.Try):
        _walk_body(stmt.body, table)
        for handler in stmt.handlers:
            _walk_body(handler.body, table)
        _walk_body(stmt.orelse, table)
        _walk_body(stmt.finalbody, table)


def _collect_walrus(stmt: ast.stmt, table: dict[str, str | _Ref]) -> None:
    """Collect walrus operator (:=) assignments, skipping nested scope bodies."""

    class _WalrusVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            return

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
            if isinstance(node.target, ast.Name):
                resolved = try_resolve_string(node.value)
                if resolved is not None:
                    table[node.target.id] = resolved
            self.generic_visit(node)

    _WalrusVisitor().visit(stmt)


def _handle_assign(stmt: ast.Assign, table: dict[str, str | _Ref]) -> None:
    """Handle ast.Assign: simple Name target or tuple/list unpacking."""
    if len(stmt.targets) != 1:
        return
    target = stmt.targets[0]

    if isinstance(target, ast.Tuple | ast.List):
        _handle_unpack(target, stmt.value, table)
        return

    if isinstance(target, ast.Subscript):
        _handle_subscript_assign(target, stmt.value, table)
        return

    if isinstance(target, ast.Name):
        # Check if RHS is a dict literal -- track composite keys
        if isinstance(stmt.value, ast.Dict):
            _handle_dict_literal(target.id, stmt.value, table)
        _track_name_assign(target.id, stmt.value, table)
        return


def _handle_unpack(
    target: ast.Tuple | ast.List,
    value: ast.expr,
    table: dict[str, str | _Ref],
) -> None:
    """Handle tuple/list unpacking: a, b = 'ev', 'al'."""
    if not isinstance(value, ast.Tuple | ast.List):
        return
    if len(target.elts) != len(value.elts):
        return
    for tgt, val in zip(target.elts, value.elts, strict=False):
        if isinstance(tgt, ast.Name):
            resolved = try_resolve_string(val)
            if resolved is not None:
                table[tgt.id] = resolved


def _track_name_assign(var_name: str, value_node: ast.expr, table: dict[str, str | _Ref]) -> None:
    """Track a simple Name = <expr> assignment."""
    resolved = try_resolve_string(value_node)
    if resolved is not None:
        table[var_name] = resolved
        return
    mult = _resolve_binop_mult(value_node)
    if mult is not None:
        table[var_name] = mult
        return
    if isinstance(value_node, ast.Name):
        table[var_name] = _Ref(value_node.id)


def _resolve_binop_mult(node: ast.expr) -> str | None:
    """Resolve string * positive-int (or int * string) to repeated string.

    Only resolves when the integer operand is >= 1. Returns None for
    zero, negative, float, or non-constant operands.
    """
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Mult):
        return None

    # Try str * int first, then int * str
    str_val = try_resolve_string(node.left)
    int_val = _resolve_int_expr(node.right) if str_val is not None else None
    if str_val is None or int_val is None:
        str_val = try_resolve_string(node.right)
        int_val = _resolve_int_expr(node.left) if str_val is not None else None
    if str_val is None or int_val is None:
        return None
    if int_val < 1:
        return None
    return str_val * int_val


def _handle_subscript_assign(
    target: ast.Subscript,
    value_node: ast.expr,
    table: dict[str, str | _Ref],
) -> None:
    """Handle subscript assignment: d['key'] = 'value' -> composite key 'varname[key]'."""
    if not isinstance(target.value, ast.Name):
        return
    if not isinstance(target.slice, ast.Constant) or not isinstance(target.slice.value, str):
        return
    resolved = try_resolve_string(value_node)
    if resolved is None:
        return
    base = target.value.id
    key = target.slice.value
    table[f"{base}[{key}]"] = resolved


def _handle_dict_literal(
    var_name: str,
    dict_node: ast.Dict,
    table: dict[str, str | _Ref],
) -> None:
    """Handle dict literal: parts = {'a': 'ex', 'b': 'ec'} -> composite keys."""
    for k, v in zip(dict_node.keys, dict_node.values, strict=False):
        if k is None:
            continue  # **kwargs unpacking
        if not isinstance(k, ast.Constant) or not isinstance(k.value, str):
            continue
        resolved = try_resolve_string(v)
        if resolved is not None:
            table[f"{var_name}[{k.value}]"] = resolved


def _handle_aug_assign(stmt: ast.AugAssign, table: dict[str, str | _Ref]) -> None:
    """Handle ast.AugAssign: augmented string assignment when x is already tracked."""
    if not isinstance(stmt.op, ast.Add):
        return
    if not isinstance(stmt.target, ast.Name):
        return
    var_name = stmt.target.id
    existing = table.get(var_name)
    if not isinstance(existing, str):
        return
    rhs = try_resolve_string(stmt.value)
    if rhs is not None:
        table[var_name] = existing + rhs
