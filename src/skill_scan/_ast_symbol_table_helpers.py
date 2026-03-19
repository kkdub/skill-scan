"""Private assignment-tracking helpers used by the symbol table builder.

Extracted from _ast_symbol_table.py. These functions walk statement bodies
and collect string assignments (Name targets, tuple/list unpacking,
augmented assignment, walrus operator, replace chains) into a mutable table.
"""

from __future__ import annotations

import ast

from skill_scan._ast_helpers import _resolve_int_expr, try_resolve_string
from skill_scan._ast_symbol_table import _Ref
from skill_scan._ast_symbol_table_dict_helpers import (
    _handle_dict_literal,
    _handle_dict_pop,
    _handle_string_list_literal,
    _resolve_replace_chain_simple,
)


def _walk_body(body: list[ast.stmt], table: dict[str, str | _Ref]) -> None:
    """Walk a statement list, dispatching each to ``_process_stmt``."""
    for stmt in body:
        _process_stmt(stmt, table)


def _process_stmt(stmt: ast.stmt, table: dict[str, str | _Ref]) -> None:
    """Process one statement: dispatch by type, then collect walrus exprs."""
    if isinstance(stmt, ast.Assign):
        if not _handle_dict_pop(stmt, table):
            _handle_assign(stmt, table)
    elif isinstance(stmt, ast.AugAssign):
        _handle_aug_assign(stmt, table)
    else:
        _recurse_control_flow(stmt, table)
    _collect_walrus(stmt, table)


def _recurse_control_flow(stmt: ast.stmt, table: dict[str, str | _Ref]) -> None:
    """Recurse into control flow bodies (if/for/while/with/try/except)."""
    match stmt:
        case ast.If() | ast.For() | ast.While() | ast.AsyncFor():
            _walk_body(stmt.body, table)
            _walk_body(stmt.orelse, table)
        case ast.With() | ast.AsyncWith():
            _walk_body(stmt.body, table)
        case ast.Try():
            _walk_body(stmt.body, table)
            for handler in stmt.handlers:
                _walk_body(handler.body, table)
            _walk_body(stmt.orelse, table)
            _walk_body(stmt.finalbody, table)


def _collect_walrus(stmt: ast.stmt, table: dict[str, str | _Ref]) -> None:
    """Collect walrus (:=) assignments, skipping nested scopes (func/class/lambda)."""

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
    """Handle ``ast.Assign`` nodes by iterating ALL targets.

    Supports Name targets (simple assignment), Tuple/List targets (unpacking),
    and Subscript targets (``d['key'] = val``). For Name targets, also checks
    whether the RHS is a dict literal or a string list/tuple literal.
    """
    for target in stmt.targets:
        if isinstance(target, ast.Tuple | ast.List):
            _handle_unpack(target, stmt.value, table)
            continue

        if isinstance(target, ast.Subscript):
            _handle_subscript_assign(target, stmt.value, table)
            continue

        if isinstance(target, ast.Name):
            # Check if RHS is a dict literal -- track composite keys
            if isinstance(stmt.value, ast.Dict):
                _handle_dict_literal(target.id, stmt.value, table)
            # Check if RHS is a list/tuple of all string constants
            if isinstance(stmt.value, ast.List | ast.Tuple):
                _handle_string_list_literal(target.id, stmt.value, table)
            _track_name_assign(target.id, stmt.value, table)
            continue


def _handle_unpack(target: ast.Tuple | ast.List, value: ast.expr, table: dict[str, str | _Ref]) -> None:
    """Handle tuple/list unpacking like ``a, b = 'ev', 'al'``.

    Both sides must have matching element counts; Name targets get resolved.
    """
    if not isinstance(value, ast.Tuple | ast.List):
        return
    if len(target.elts) != len(value.elts):
        return
    for tgt, val in zip(target.elts, value.elts, strict=False):
        if isinstance(tgt, ast.Name):
            resolved = try_resolve_string(val)
            if resolved is not None:
                table[tgt.id] = resolved


def _resolve_operand(node: ast.expr, table: dict[str, str | _Ref]) -> str | None:
    """Resolve a BinOp operand: string constant or table-tracked Name."""
    s = try_resolve_string(node)
    if s is not None:
        return s
    if isinstance(node, ast.Name):
        v = table.get(node.id)
        return v if isinstance(v, str) else None
    return None


def _track_name_assign(var_name: str, value_node: ast.expr, table: dict[str, str | _Ref]) -> None:
    """Track a simple ``Name = <expr>`` assignment into the symbol table.

    Tries resolution in order: string literal, string multiplication,
    string concatenation (BinOp Add), ``.replace()`` chain, and finally
    a ``_Ref`` for Name-to-Name aliasing when nothing else resolves.
    """
    resolved = try_resolve_string(value_node)
    if resolved is not None:
        table[var_name] = resolved
        return
    mult = _resolve_binop_mult(value_node)
    if mult is not None:
        table[var_name] = mult
        return
    if isinstance(value_node, ast.BinOp) and isinstance(value_node.op, ast.Add):
        left = _resolve_operand(value_node.left, table)
        right = _resolve_operand(value_node.right, table)
        if left is not None and right is not None:
            table[var_name] = left + right
            return
    repl = _resolve_replace_chain_simple(value_node, table)
    if repl is not None:
        table[var_name] = repl
        return
    if isinstance(value_node, ast.Name):
        table[var_name] = _Ref(value_node.id)


_MAX_REPEAT = 1000  # cap repetition to prevent DoS via huge strings


def _resolve_binop_mult(node: ast.expr) -> str | None:
    """Resolve ``string * int`` to a repeated string.

    Only resolves when the integer is in ``[1, _MAX_REPEAT]`` to prevent
    denial-of-service via huge string allocation.
    """
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Mult):
        return None
    pair = _extract_str_int_pair(node)
    if pair is None:
        return None
    str_val, int_val = pair
    return str_val * int_val if 1 <= int_val <= _MAX_REPEAT else None


def _extract_str_int_pair(node: ast.BinOp) -> tuple[str, int] | None:
    """Extract ``(string, int)`` from either operand order of a BinOp.

    Handles both ``'x' * 3`` and ``3 * 'x'`` orderings.
    """
    str_val = try_resolve_string(node.left)
    if str_val is not None:
        int_val = _resolve_int_expr(node.right)
        if int_val is not None:
            return str_val, int_val
    str_val = try_resolve_string(node.right)
    if str_val is not None:
        int_val = _resolve_int_expr(node.left)
        if int_val is not None:
            return str_val, int_val
    return None


def _handle_subscript_assign(
    target: ast.Subscript, value_node: ast.expr, table: dict[str, str | _Ref]
) -> None:
    """Handle subscript assignment ``d['key'] = 'val'``.

    Stores the value under a composite key ``'varname[key]'`` in the table.
    Only handles string or non-negative integer slice keys.
    """
    if not isinstance(target.value, ast.Name):
        return
    if not isinstance(target.slice, ast.Constant):
        return
    slice_val = target.slice.value
    if isinstance(slice_val, str):
        key = slice_val
    elif isinstance(slice_val, int) and slice_val >= 0:
        key = str(slice_val)
    else:
        return
    resolved = try_resolve_string(value_node)
    if resolved is None:
        return
    base = target.value.id
    table[f"{base}[{key}]"] = resolved


def _collect_scope_declarations(body: list[ast.stmt]) -> tuple[set[str], set[str]]:
    """Collect ``global`` and ``nonlocal`` declarations from a statement body.

    Recurses into control-flow constructs (if/for/while/with/try) to find
    declarations nested inside branches. Returns two sets: global names
    and nonlocal names.
    """
    global_names: set[str] = set()
    nonlocal_names: set[str] = set()

    def _recurse(stmts: list[ast.stmt]) -> None:
        g, n = _collect_scope_declarations(stmts)
        global_names.update(g)
        nonlocal_names.update(n)

    for stmt in body:
        match stmt:
            case ast.Global():
                global_names.update(stmt.names)
            case ast.Nonlocal():
                nonlocal_names.update(stmt.names)
            case ast.If() | ast.For() | ast.While() | ast.AsyncFor():
                _recurse(stmt.body)
                _recurse(stmt.orelse)
            case ast.With() | ast.AsyncWith():
                _recurse(stmt.body)
            case ast.Try():
                _recurse(stmt.body)
                for handler in stmt.handlers:
                    _recurse(handler.body)
                _recurse(stmt.orelse)
                _recurse(stmt.finalbody)
    return global_names, nonlocal_names


def _handle_aug_assign(stmt: ast.AugAssign, table: dict[str, str | _Ref]) -> None:
    """Handle ``ast.AugAssign`` for augmented string concatenation.

    Only processes ``+=`` on Name targets where the variable is already
    tracked as a string in the table. Concatenates the resolved RHS
    string onto the existing value.
    """
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


def _handle_self_attr_assign(
    body: list[ast.stmt], result: dict[str, str], self_name: str, class_name: str
) -> None:
    """Walk a method body for ``self.attr = 'string'`` (deferred import)."""
    from skill_scan._ast_symbol_table_class_helpers import _walk_self_attrs

    _walk_self_attrs(body, result, self_name, class_name)
