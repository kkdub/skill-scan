"""Int-list tracking helpers for the pre-pass collector.

Handles assignment, AugAssign (+=), and .extend() mutations on tracked
int-list variables. Imported by ``_ast_split_comprehension``.

Shadow marker: ``_SHADOW`` is a module-level sentinel list used to mark
variables that were assigned a non-int-list value.  We compare by identity
(``existing is _SHADOW``) so that a legitimate empty int list (``codes = []``)
is not confused with a shadowed variable.
"""

from __future__ import annotations

import ast

_SHADOW: list[int] = []
"""Identity sentinel -- never mutate.  Used as shadow marker in int-list table."""

_MAX_INT_LIST_SIZE = 10000
"""Cap combined int-list size to prevent allocation spikes on untrusted input."""

_Decls = tuple[set[str], set[str]] | None
"""Type alias for optional (global_names, nonlocal_names) tuple."""


def _resolve_scope_key(
    name: str,
    scope: str,
    declarations: _Decls = None,
    enclosing_scope: str = "",
) -> str:
    """Resolve the storage key for *name* respecting global/nonlocal declarations.

    * ``global name`` -> bare *name* (module-level key, empty scope).
    * ``nonlocal name`` -> ``enclosing_scope.name`` (or bare if no enclosing).
    * Otherwise -> ``scope.name`` (current scope, existing behaviour).
    """
    if declarations:
        if name in declarations[0]:  # global
            return name
        if name in declarations[1]:  # nonlocal
            return f"{enclosing_scope}.{name}" if enclosing_scope else name
    return f"{scope}.{name}" if scope else name


def _extract_int_list(elts: list[ast.expr]) -> list[int] | None:
    """Extract a list of int constants, or None if any element is non-int."""
    values: list[int] = []
    for elt in elts:
        if not isinstance(elt, ast.Constant) or not isinstance(elt.value, int):
            return None
        values.append(elt.value)
    return values


def _handle_int_list_stmt(
    stmt: ast.stmt,
    scope: str,
    result: dict[str, list[int]],
    declarations: _Decls = None,
    enclosing_scope: str = "",
) -> None:
    """Dispatch a single statement for int-list tracking."""
    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
        _handle_assign(stmt, scope, result, declarations, enclosing_scope)
    elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.op, ast.Add):
        if isinstance(stmt.target, ast.Name):
            _extend_tracked(stmt.target.id, stmt.value, scope, result, declarations, enclosing_scope)
    elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        _handle_extend_call(stmt.value, scope, result, declarations, enclosing_scope)


def _handle_assign(
    stmt: ast.Assign,
    scope: str,
    result: dict[str, list[int]],
    declarations: _Decls = None,
    enclosing_scope: str = "",
) -> None:
    """Track Name = <expr> assignments for int-list pre-pass."""
    tgt = stmt.targets[0]
    if not isinstance(tgt, ast.Name):
        return
    key = _resolve_scope_key(tgt.id, scope, declarations, enclosing_scope)
    if isinstance(stmt.value, ast.List | ast.Tuple):
        ints = _extract_int_list(stmt.value.elts)
        result[key] = ints if ints is not None else _SHADOW
    elif isinstance(stmt.value, ast.BinOp) and isinstance(stmt.value.op, ast.Add):
        result[key] = _resolve_binop_concat(stmt.value, scope, result, declarations, enclosing_scope)
    else:
        result[key] = _SHADOW


def _resolve_binop_concat(
    node: ast.BinOp,
    scope: str,
    result: dict[str, list[int]],
    declarations: _Decls = None,
    enclosing_scope: str = "",
) -> list[int]:
    """Resolve Name + Name where both operands are tracked int-lists."""
    if not (isinstance(node.left, ast.Name) and isinstance(node.right, ast.Name)):
        return _SHADOW
    left_key = _resolve_scope_key(node.left.id, scope, declarations, enclosing_scope)
    right_key = _resolve_scope_key(node.right.id, scope, declarations, enclosing_scope)
    left = result.get(left_key)
    right = result.get(right_key)
    if left is None or left is _SHADOW or right is None or right is _SHADOW:
        return _SHADOW
    if len(left) + len(right) > _MAX_INT_LIST_SIZE:
        return _SHADOW
    return left + right


def _handle_extend_call(
    call: ast.Call,
    scope: str,
    result: dict[str, list[int]],
    declarations: _Decls = None,
    enclosing_scope: str = "",
) -> None:
    """Handle codes.extend([...]) calls on tracked variables."""
    if not (isinstance(call.func, ast.Attribute) and call.func.attr == "extend"):
        return
    if not (isinstance(call.func.value, ast.Name) and len(call.args) == 1 and not call.keywords):
        return
    _extend_tracked(call.func.value.id, call.args[0], scope, result, declarations, enclosing_scope)


def _extend_tracked(
    name: str,
    value: ast.expr,
    scope: str,
    result: dict[str, list[int]],
    declarations: _Decls = None,
    enclosing_scope: str = "",
) -> None:
    """Extend a tracked int-list via += or .extend(); ignore unknown variables."""
    key = _resolve_scope_key(name, scope, declarations, enclosing_scope)
    if key not in result:
        return
    existing = result[key]
    if isinstance(value, ast.Name):
        _extend_with_tracked_var(key, value.id, scope, existing, result, declarations, enclosing_scope)
        return
    if not isinstance(value, ast.List | ast.Tuple):
        result[key] = _SHADOW
        return
    if existing is _SHADOW:
        return
    ints = _extract_int_list(value.elts)
    if ints is None or len(existing) + len(ints) > _MAX_INT_LIST_SIZE:
        result[key] = _SHADOW
    else:
        result[key] = existing + ints


def _extend_with_tracked_var(
    target_key: str,
    var_name: str,
    scope: str,
    existing: list[int],
    result: dict[str, list[int]],
    declarations: _Decls = None,
    enclosing_scope: str = "",
) -> None:
    """Extend target with a tracked variable's int-list, or shadow if unresolvable."""
    var_key = _resolve_scope_key(var_name, scope, declarations, enclosing_scope)
    src = result.get(var_key)
    if src is None or src is _SHADOW:
        result[target_key] = _SHADOW
        return
    if existing is _SHADOW:
        return
    if len(existing) + len(src) > _MAX_INT_LIST_SIZE:
        result[target_key] = _SHADOW
        return
    result[target_key] = existing + src


def _values_agree(vals: list[list[int]]) -> bool:
    """Check whether all values agree (identity for _SHADOW, equality otherwise)."""
    first = vals[0]
    for v in vals[1:]:
        if first is _SHADOW:
            if v is not _SHADOW:
                return False
        elif v is _SHADOW or v != first:
            return False
    return True


def _merge_branches(
    branches: list[dict[str, list[int]]],
    result: dict[str, list[int]],
) -> None:
    """Merge N branch results conservatively into *result*.

    Keys with identical values across all branches that contain them are
    kept.  Keys with differing values are replaced with ``_SHADOW``.
    Keys present in only some branches are kept (security-conservative).
    """
    all_keys: set[str] = set()
    for br in branches:
        all_keys.update(br)
    for key in all_keys:
        vals = [br[key] for br in branches if key in br]
        result[key] = vals[0] if _values_agree(vals) else _SHADOW


def _is_exhaustive_match(node: ast.Match) -> bool:
    """Return True if the match has a wildcard case (MatchAs with name=None)."""
    if not node.cases:
        return False
    last_pat = node.cases[-1].pattern
    return isinstance(last_pat, ast.MatchAs) and last_pat.name is None


def _walk_fn_body(
    body: list[ast.stmt],
    scope: str,
    result: dict[str, list[int]],
    decls: _Decls = None,
    enclosing: str = "",
) -> None:
    """Recursively walk a body for int-list tracking, threading declarations.

    If and Match nodes use snapshot-walk-merge so that mutually exclusive
    branches do not contaminate each other.  For/While/Try/With are still
    walked sequentially.
    """
    from skill_scan._ast_symbol_table_returns import _sub_bodies

    for stmt in body:
        _handle_int_list_stmt(stmt, scope, result, decls, enclosing)
        if isinstance(stmt, ast.If):
            snap = result.copy()
            _walk_fn_body(stmt.body, scope, result, decls, enclosing)
            after_if = result.copy()
            result.clear()
            result.update(snap)
            _walk_fn_body(stmt.orelse, scope, result, decls, enclosing)
            after_else = result.copy()
            result.clear()
            result.update(snap)
            _merge_branches([after_if, after_else], result)
        elif isinstance(stmt, ast.Match):
            snap = result.copy()
            branch_results: list[dict[str, list[int]]] = []
            for case in stmt.cases:
                result.clear()
                result.update(snap)
                _walk_fn_body(case.body, scope, result, decls, enclosing)
                branch_results.append(result.copy())
            if not _is_exhaustive_match(stmt):
                branch_results.append(snap)
            result.clear()
            result.update(snap)
            _merge_branches(branch_results, result)
        else:
            for child_body in _sub_bodies(stmt):
                _walk_fn_body(child_body, scope, result, decls, enclosing)


def _collect_fn_body(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    scope: str,
    enclosing: str,
    result: dict[str, list[int]],
) -> None:
    """Collect int-lists from a function body, recursing into nested functions.

    Handles ``global`` and ``nonlocal`` declarations so that mutations inside
    the function update the correct scope key (module-level for ``global``,
    enclosing function for ``nonlocal``).
    """
    from skill_scan._ast_symbol_table_assignments import _collect_scope_declarations

    decls = _collect_scope_declarations(fn.body)
    # Walk the function body with scope declarations active.
    _walk_fn_body(fn.body, scope, result, decls, enclosing)
    # Determine child_enc per nested function: pass through to enclosing
    # when the parent doesn't locally own any of the child's nonlocal names.
    # A name is "owned" if scope.name exists in result (was assigned here);
    # names routed via global/nonlocal or not touched at all are transparent.
    for stmt in fn.body:
        if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
            child_nl = _collect_scope_declarations(stmt.body)[1]
            if child_nl:
                owns_any = any(_resolve_scope_key(n, scope) in result for n in child_nl)
                child_enc = scope if owns_any else enclosing
            else:
                child_enc = scope
            _collect_fn_body(stmt, f"{scope}.{stmt.name}", child_enc, result)
