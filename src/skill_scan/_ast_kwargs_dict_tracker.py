"""Dict-collection pre-pass for kwargs unpacking detection.

Extracted from _ast_kwargs_detector.py to keep files under the 300-line limit.
Tracks dict variable assignments, subscript mutations, union operators (| and |=),
and .update() calls across all scopes.
"""

from __future__ import annotations

import ast

_UNRESOLVABLE = object()  # sentinel for _eval_constant_expr failure


def _collect_dict_assigns(tree: ast.Module) -> dict[str, dict[str, object]]:
    """Pre-pass: collect dict variable assignments from all scopes.

    Tracks raw constant values (preserving native Python types).
    """
    result: dict[str, dict[str, object]] = {}
    _collect_from_body(tree.body, "", result)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            _collect_from_body(node.body, node.name, result)
        elif isinstance(node, ast.ClassDef):
            for stmt in node.body:
                if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
                    _collect_from_body(stmt.body, node.name, result)
    return result


def _build_string_table(body: list[ast.stmt]) -> dict[str, str]:
    """Build a local table of Name -> string for simple assignments.

    Tracks ``name = 'literal'`` and ``name = 'a' + 'b'`` patterns.
    """
    table: dict[str, str] = {}
    for stmt in body:
        if not (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1):
            continue
        target = stmt.targets[0]
        if not isinstance(target, ast.Name):
            continue
        if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
            table[target.id] = stmt.value.value
        elif isinstance(stmt.value, ast.BinOp) and isinstance(stmt.value.op, ast.Add):
            resolved = _resolve_string_concat(stmt.value)
            if resolved is not None:
                table[target.id] = resolved
    return table


def _collect_from_body(
    body: list[ast.stmt],
    scope: str,
    result: dict[str, dict[str, object]],
) -> None:
    """Collect dict assignments from a body, keyed with *scope* prefix."""
    string_table = _build_string_table(body)
    for stmt in body:
        if isinstance(stmt, ast.AugAssign) and isinstance(stmt.op, ast.BitOr):
            _track_aug_union(stmt, result, scope)
        elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            _track_assign(stmt.targets[0], stmt.value, result, scope, string_table=string_table)
        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            _handle_update_call(stmt.value, result, scope)


def _track_assign(
    target: ast.expr,
    value: ast.expr,
    result: dict[str, dict[str, object]],
    scope: str,
    *,
    string_table: dict[str, str] | None = None,
) -> None:
    """Dispatch a single-target Assign to the appropriate tracker."""
    if isinstance(target, ast.Name) and isinstance(value, ast.BinOp) and isinstance(value.op, ast.BitOr):
        _track_union(target, value, result, scope)
    elif isinstance(target, ast.Name) and isinstance(value, ast.Dict):
        extracted = _extract_dict_literal(value, string_table=string_table)
        if extracted is not None:
            key = f"{scope}.{target.id}" if scope else target.id
            result[key] = extracted
    elif isinstance(target, ast.Subscript):
        _track_subscript_assign(target, value, result, scope)


def _track_subscript_assign(
    target: ast.Subscript,
    value: ast.expr,
    result: dict[str, dict[str, object]],
    scope: str = "",
) -> None:
    """Track ``opts['shell'] = True`` -- subscript assignment to tracked dict."""
    if not isinstance(target.value, ast.Name):
        return
    if not (isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str)):
        return
    resolved = _eval_constant_expr(value)
    if resolved is _UNRESOLVABLE:
        return
    var_name = f"{scope}.{target.value.id}" if scope else target.value.id
    result.setdefault(var_name, {})[target.slice.value] = resolved


def _resolve_dict_operand(
    node: ast.expr,
    result: dict[str, dict[str, object]],
    scope: str,
) -> dict[str, object] | None:
    """Resolve one operand of a dict union to a concrete dict, or ``None``.

    Recurses into ``ast.BinOp(BitOr)`` for chained unions (``a | b | c``).
    """
    if isinstance(node, ast.Dict):
        return _extract_dict_literal(node)
    if isinstance(node, ast.Name):
        key = f"{scope}.{node.id}" if scope else node.id
        hit = result.get(key)
        if hit is not None or not scope:
            return hit
        return result.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _resolve_dict_operand(node.left, result, scope)
        if left is None:
            return None
        right = _resolve_dict_operand(node.right, result, scope)
        return {**left, **right} if right is not None else None
    return None


def _track_union(
    target: ast.Name,
    binop: ast.BinOp,
    result: dict[str, dict[str, object]],
    scope: str,
) -> None:
    """Track ``x = a | b`` where both operands are resolvable dicts."""
    left = _resolve_dict_operand(binop.left, result, scope)
    right = _resolve_dict_operand(binop.right, result, scope)
    if left is not None and right is not None:
        key = f"{scope}.{target.id}" if scope else target.id
        result[key] = {**left, **right}


def _track_aug_union(
    stmt: ast.AugAssign,
    result: dict[str, dict[str, object]],
    scope: str,
) -> None:
    """Track ``x |= rhs`` -- merge into existing tracked dict or drop."""
    if not isinstance(stmt.target, ast.Name):
        return
    key = f"{scope}.{stmt.target.id}" if scope else stmt.target.id
    existing = result.get(key)
    if existing is None:
        return
    rhs = _resolve_dict_operand(stmt.value, result, scope)
    if rhs is not None:
        result[key] = {**existing, **rhs}
    else:
        del result[key]


def _handle_update_call(
    call: ast.Call,
    result: dict[str, dict[str, object]],
    scope: str,
) -> None:
    """Track ``opts.update({'shell': True})`` -- merge dict arg into tracked dict.

    Handles positional dict literal args and tracked variable args.
    Silently skips keyword-only args and non-resolvable arguments.
    """
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "update":
        return
    if not isinstance(call.func.value, ast.Name):
        return
    # Only handle single positional dict arg (no keyword-only update calls)
    if len(call.args) != 1 or call.keywords:
        return
    arg = call.args[0]
    var_name = f"{scope}.{call.func.value.id}" if scope else call.func.value.id
    update_dict = _resolve_dict_operand(arg, result, scope)
    if update_dict is None:
        return
    existing = result.get(var_name)
    if existing is not None:
        result[var_name] = {**existing, **update_dict}
    else:
        result[var_name] = dict(update_dict)


def _eval_constant_expr(node: ast.expr) -> object:
    """Resolve ast.Constant or UnaryOp(USub|UAdd, Constant) to a value.

    Returns ``_UNRESOLVABLE`` sentinel when the node cannot be evaluated.
    """
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.operand, ast.Constant):
        val = node.operand.value
        if isinstance(node.op, ast.USub) and isinstance(val, int | float | complex):
            return -val
        if isinstance(node.op, ast.UAdd) and isinstance(val, int | float | complex):
            return +val
    return _UNRESOLVABLE


def _resolve_string_concat(node: ast.expr) -> str | None:
    """Resolve BinOp(Add) of string Constants recursively.

    Returns the concatenated string, or ``None`` if any operand is not
    a string constant.  Handles chains like ``'a' + 'b' + 'c'``.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _resolve_string_concat(node.left)
        if left is None:
            return None
        right = _resolve_string_concat(node.right)
        if right is None:
            return None
        return left + right
    return None


def _resolve_dict_key(
    key_node: ast.expr,
    string_table: dict[str, str] | None = None,
) -> str | None:
    """Resolve a dict key node to a string, or ``None``.

    Handles ast.Constant(str), BinOp(Add) of string constants, and
    ast.Name referencing a variable in the local *string_table*.
    """
    if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
        return key_node.value
    if isinstance(key_node, ast.BinOp) and isinstance(key_node.op, ast.Add):
        return _resolve_string_concat(key_node)
    if isinstance(key_node, ast.Name) and string_table is not None:
        return string_table.get(key_node.id)
    return None


def _extract_dict_literal(
    node: ast.Dict,
    string_table: dict[str, str] | None = None,
) -> dict[str, object] | None:
    """Extract constant key-value pairs from an inline ast.Dict.

    Returns ``None`` if any ``**spread`` is present (avoids false positives).
    Values are stored as raw Python constants (preserving native types).
    Resolves BinOp(Add) string keys and Name keys via *string_table*.
    """
    if any(k is None for k in node.keys):
        return None
    result: dict[str, object] = {}
    for key_node, value_node in zip(node.keys, node.values, strict=False):
        if key_node is None:
            continue  # pragma: no cover -- guarded by spread check above
        key_str = _resolve_dict_key(key_node, string_table)
        if key_str is not None:
            val = _eval_constant_expr(value_node)
            if val is not _UNRESOLVABLE:
                result[key_str] = val
    return result
