"""Kwargs unpacking detector -- detect dangerous keyword arguments via ** unpacking.

Detects subprocess.run(**opts) where opts contains shell=True (or any truthy value).
Table-driven via _DANGEROUS_KWARGS.  Scope-aware via _build_scope_map.
"""

from __future__ import annotations

import ast

from skill_scan._ast_detectors import _make_finding
from skill_scan._ast_helpers import get_call_name
from skill_scan._ast_split_detector import _build_scope_map
from skill_scan.models import Finding, Severity

_UNRESOLVABLE = object()  # sentinel for _eval_constant_expr failure

# Dangerous kwargs table: prefix -> (key, value, rule_id, severity, desc_prefix).
_DangerousEntry = tuple[str, object, str, Severity, str]
_DANGEROUS_KWARGS: dict[str, list[_DangerousEntry]] = {
    "subprocess.": [
        ("shell", True, "EXEC-002", Severity.CRITICAL, "subprocess with shell=True via **kwargs unpacking"),
    ],
}


def detect_kwargs_unpacking(
    tree: ast.Module,
    file_path: str,
    alias_map: dict[str, str],
    symbol_table: dict[str, str],
    *,
    _nodes: list[ast.AST] | None = None,
) -> list[Finding]:
    """Detect dangerous keyword arguments passed via ``**`` unpacking.

    Scope-aware: resolves function-local dicts before module-level ones.
    Accepts ``_nodes`` to reuse a pre-built ``ast.walk()`` list.
    """
    dict_assigns = _collect_dict_assigns(tree)
    scope_map = _build_scope_map(tree)
    findings: list[Finding] = []
    for node in _nodes if _nodes is not None else ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = get_call_name(node, alias_map)
        entries = _match_prefix(call_name)
        if entries is None:
            continue
        scope = scope_map.get(id(node), "")
        _check_call_kwargs(node, call_name, entries, symbol_table, dict_assigns, file_path, findings, scope)
    return findings


def _match_prefix(call_name: str) -> list[_DangerousEntry] | None:
    """Return matching dangerous-kwargs entries for *call_name*, or ``None``."""
    if not call_name:
        return None
    return next((e for p, e in _DANGEROUS_KWARGS.items() if call_name.startswith(p)), None)


def _check_call_kwargs(
    node: ast.Call,
    call_name: str,
    entries: list[_DangerousEntry],
    symbol_table: dict[str, str],
    dict_assigns: dict[str, dict[str, object]],
    file_path: str,
    findings: list[Finding],
    scope: str = "",
) -> None:
    """Check a single Call node's ** kwargs against dangerous entries."""
    for kw in node.keywords:
        if kw.arg is not None:
            continue
        resolved = _resolve_kwargs_dict(kw.value, symbol_table, dict_assigns, scope)
        if resolved is None:
            continue
        for key, value, rule_id, severity, desc_prefix in entries:
            if _kwarg_matches(resolved, key, value):
                findings.append(
                    _make_finding(
                        rule_id=rule_id,
                        severity=severity,
                        file=file_path,
                        line=node.lineno,
                        matched_text=f"{call_name}(**{{{key!r}: {value!r}}})",
                        description=f"{desc_prefix} detected via AST",
                    )
                )


def _resolve_kwargs_dict(
    node: ast.expr,
    symbol_table: dict[str, str],
    dict_assigns: dict[str, dict[str, object]],
    scope: str = "",
) -> dict[str, object] | None:
    """Resolve ``**expr`` to a dict of key-value pairs, or ``None``.

    Tries scoped lookups first, then module-level.
    """
    if isinstance(node, ast.Dict):
        return _extract_dict_literal(node)
    if isinstance(node, ast.Name):
        if scope:
            scoped = f"{scope}.{node.id}"
            st_result = _lookup_symbol_table_dict(scoped, symbol_table)
            if st_result:
                return st_result
            da_result = dict_assigns.get(scoped)
            if da_result:
                return da_result
        st_result = _lookup_symbol_table_dict(node.id, symbol_table)
        if st_result:
            return st_result
        return dict_assigns.get(node.id)
    return None


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


def _collect_from_body(body: list[ast.stmt], scope: str, result: dict[str, dict[str, object]]) -> None:
    """Collect dict assignments from a body, keyed with *scope* prefix."""
    for stmt in body:
        if isinstance(stmt, ast.AugAssign) and isinstance(stmt.op, ast.BitOr):
            _track_aug_union(stmt, result, scope)
        elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            _track_assign(stmt.targets[0], stmt.value, result, scope)


def _track_assign(
    target: ast.expr,
    value: ast.expr,
    result: dict[str, dict[str, object]],
    scope: str,
) -> None:
    """Dispatch a single-target Assign to the appropriate tracker."""
    if isinstance(target, ast.Name) and isinstance(value, ast.BinOp) and isinstance(value.op, ast.BitOr):
        _track_union(target, value, result, scope)
    elif isinstance(target, ast.Name) and isinstance(value, ast.Dict):
        extracted = _extract_dict_literal(value)
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


def _track_aug_union(stmt: ast.AugAssign, result: dict[str, dict[str, object]], scope: str) -> None:
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


def _eval_constant_expr(node: ast.expr) -> object:
    """Resolve ast.Constant or UnaryOp(USub|UAdd, Constant) to a value.

    Returns ``_UNRESOLVABLE`` sentinel when the node cannot be evaluated.
    """
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.operand, ast.Constant):
        val = node.operand.value
        if isinstance(node.op, ast.USub) and isinstance(val, int | float):
            return -val
        if isinstance(node.op, ast.UAdd) and isinstance(val, int | float):
            return +val
    return _UNRESOLVABLE


def _extract_dict_literal(node: ast.Dict) -> dict[str, object] | None:
    """Extract constant key-value pairs from an inline ast.Dict.

    Returns ``None`` if any ``**spread`` is present (avoids false positives).
    Values are stored as raw Python constants (preserving native types).
    """
    if any(k is None for k in node.keys):
        return None
    result: dict[str, object] = {}
    for key_node, value_node in zip(node.keys, node.values, strict=False):
        if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
            val = _eval_constant_expr(value_node)
            if val is not _UNRESOLVABLE:
                result[key_node.value] = val
    return result


def _lookup_symbol_table_dict(var_name: str, symbol_table: dict[str, str]) -> dict[str, object]:
    """Reconstruct a dict from ``'varname[key]'`` composite keys in symbol table."""
    prefix = f"{var_name}["
    result: dict[str, object] = {}
    for st_key, st_value in symbol_table.items():
        if st_key.startswith(prefix) and st_key.endswith("]"):
            inner_key = st_key[len(prefix) : -1]
            result[inner_key] = st_value
    return result


def _kwarg_matches(
    resolved: dict[str, object],
    key: str,
    value: object,
) -> bool:
    """Check whether *resolved* contains a matching (key, value) pair.

    Bool table entries use truthiness; non-bool entries use str() equality.
    """
    if key not in resolved:
        return False
    resolved_val = resolved[key]
    if isinstance(value, bool):
        return bool(resolved_val) == value
    return str(resolved_val) == str(value)
