"""AST symbol table builder -- variable assignment tracking with scope.

Builds a symbol table from Python source AST by tracking simple string
assignments at module-level and function-level scopes. Resolves variable
indirection chains (y = x where x is tracked) bounded by MAX_RESOLVE_DEPTH.

Used by the split detector to reconstruct payloads assembled via variables.
"""

from __future__ import annotations

import ast

from skill_scan._ast_helpers import try_resolve_string

MAX_RESOLVE_DEPTH = 50


class _Ref:
    """Sentinel for an unresolved variable reference."""

    __slots__ = ("target",)

    def __init__(self, target: str) -> None:
        self.target = target

    def __repr__(self) -> str:
        return f"_Ref({self.target!r})"


def build_symbol_table(tree: ast.Module) -> dict[str, str]:
    """Build a symbol table mapping variable names to resolved string values.

    Walks module-level statements and function bodies separately.
    Function-local assignments are scoped -- they can read from module scope
    but do not write back to it. Returns a flat dict merging all scopes
    (function-scoped names are prefixed with ``funcname.varname``).

    Only tracks assignments where the RHS resolves to a string constant
    or a chain of variable references ending in a string constant.
    Non-string assignments (int, list, etc.) are silently skipped.
    """
    module_scope = _collect_assignments(tree.body)
    _resolve_indirections(module_scope)

    # After _resolve_indirections, all remaining values are str (Refs removed)
    result: dict[str, str] = {k: v for k, v in module_scope.items() if isinstance(v, str)}

    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            func_scope = _collect_assignments(node.body)
            _resolve_indirections(func_scope, parent_scope=module_scope)
            for var_name, value in func_scope.items():
                if isinstance(value, str):
                    result[f"{node.name}.{var_name}"] = value

    return result


def _collect_assignments(
    body: list[ast.stmt],
) -> dict[str, str | _Ref]:
    """Extract assignments from a body, recursing into control flow blocks."""
    table: dict[str, str | _Ref] = {}
    _walk_body(body, table)
    return table


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

    if not isinstance(target, ast.Name):
        return
    _track_name_assign(target.id, stmt.value, table)


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
    if isinstance(value_node, ast.Name):
        table[var_name] = _Ref(value_node.id)


def _handle_aug_assign(stmt: ast.AugAssign, table: dict[str, str | _Ref]) -> None:
    """Handle ast.AugAssign: x += 'suffix' when x is already a tracked string."""
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


def _resolve_indirections(
    scope: dict[str, str | _Ref],
    parent_scope: dict[str, str | _Ref] | None = None,
) -> None:
    """Resolve _Ref entries in-place by following variable chains.

    Chains are bounded by MAX_RESOLVE_DEPTH. Circular references
    result in the variable being removed from the scope (no entry).
    """
    to_remove: list[str] = []

    for var_name in list(scope):
        entry = scope[var_name]
        if not isinstance(entry, _Ref):
            continue

        resolved = _follow_chain(var_name, scope, parent_scope)
        if resolved is not None:
            scope[var_name] = resolved
        else:
            to_remove.append(var_name)

    for var_name in to_remove:
        del scope[var_name]


def _follow_chain(
    start: str,
    scope: dict[str, str | _Ref],
    parent_scope: dict[str, str | _Ref] | None,
) -> str | None:
    """Follow a chain of _Ref entries to find a terminal string value.

    Returns None if the chain is circular or exceeds MAX_RESOLVE_DEPTH.
    """
    visited: set[str] = {start}
    current_ref = scope[start]

    for _ in range(MAX_RESOLVE_DEPTH):
        if not isinstance(current_ref, _Ref):
            return current_ref  # Found a resolved string

        target_name = current_ref.target

        if target_name in visited:
            return None  # Circular reference

        visited.add(target_name)

        # Look up target in current scope first, then parent
        if target_name in scope:
            current_ref = scope[target_name]
        elif parent_scope is not None and target_name in parent_scope:
            current_ref = parent_scope[target_name]
        else:
            return None  # Reference to unknown variable

    return None  # Exceeded MAX_RESOLVE_DEPTH
