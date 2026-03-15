"""Kwargs unpacking detector -- detect dangerous keyword arguments via ** unpacking.

Detects patterns like subprocess.run(**opts) where opts contains shell=True,
or subprocess.run(**{'shell': True}). Table-driven: new dangerous combinations
are config-only additions to _DANGEROUS_KWARGS.

Scope-aware: uses _build_scope_map to resolve function-local dicts before
falling back to module-level assignments, matching the pattern established
by detect_split_evasion.

Pure functions: no I/O, no logging, no side effects.
"""

from __future__ import annotations

import ast

from skill_scan._ast_detectors import _make_finding
from skill_scan._ast_helpers import get_call_name
from skill_scan._ast_split_detector import _build_scope_map
from skill_scan.models import Finding, Severity

# ---------------------------------------------------------------------------
# Dangerous kwargs table
# ---------------------------------------------------------------------------
# Maps function-name prefix to a list of (kwarg_key, kwarg_value, rule_id,
# severity, description_prefix) tuples.  The call name (resolved via
# get_call_name + alias_map) is checked with startswith() against each prefix.
#
# To add a new dangerous combo, append an entry -- no code changes needed.
# ---------------------------------------------------------------------------

_DangerousEntry = tuple[str, object, str, Severity, str]

_DANGEROUS_KWARGS: dict[str, list[_DangerousEntry]] = {
    "subprocess.": [
        (
            "shell",
            True,
            "EXEC-002",
            Severity.CRITICAL,
            "subprocess with shell=True via **kwargs unpacking",
        ),
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
    """Detect dangerous keyword arguments passed via ** unpacking.

    Walks all ast.Call nodes in *tree*.  For each call whose resolved name
    matches a prefix in ``_DANGEROUS_KWARGS``, inspects ``node.keywords``
    for ``**expr`` entries and checks resolved dicts against the table.

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
    """Return matching table entries for *call_name*, or None."""
    if not call_name:
        return None
    for prefix, entries in _DANGEROUS_KWARGS.items():
        if call_name.startswith(prefix):
            return entries
    return None


def _check_call_kwargs(
    node: ast.Call,
    call_name: str,
    entries: list[_DangerousEntry],
    symbol_table: dict[str, str],
    dict_assigns: dict[str, dict[str, str]],
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
    dict_assigns: dict[str, dict[str, str]],
    scope: str = "",
) -> dict[str, str] | None:
    """Resolve a ** unpacking argument to a dict of string key-value pairs.

    Tries function-scoped lookups first (via *scope* prefix), then falls
    back to module-level.  Returns ``None`` when the expression cannot be
    resolved.
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


def _collect_dict_assigns(tree: ast.Module) -> dict[str, dict[str, str]]:
    """Pre-pass: collect dict variable assignments from all scopes.

    Unlike the symbol table, this tracks ALL constant values (including
    booleans and integers), converting them to strings for uniform comparison.
    Scoped entries are keyed as ``'funcname.varname'``.
    """
    result: dict[str, dict[str, str]] = {}
    _collect_from_body(tree.body, "", result)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            _collect_from_body(node.body, node.name, result)
        elif isinstance(node, ast.ClassDef):
            for stmt in node.body:
                if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
                    _collect_from_body(stmt.body, node.name, result)
    return result


def _collect_from_body(body: list[ast.stmt], scope: str, result: dict[str, dict[str, str]]) -> None:
    """Collect dict assignments from a body, keyed with *scope* prefix."""
    for stmt in body:
        if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1:
            continue
        target = stmt.targets[0]
        if isinstance(target, ast.Name) and isinstance(stmt.value, ast.Dict):
            extracted = _extract_dict_literal(stmt.value)
            if extracted:
                key = f"{scope}.{target.id}" if scope else target.id
                result[key] = extracted
        elif isinstance(target, ast.Subscript):
            _track_subscript_assign(target, stmt.value, result, scope)


def _track_subscript_assign(
    target: ast.Subscript,
    value: ast.expr,
    result: dict[str, dict[str, str]],
    scope: str = "",
) -> None:
    """Track a subscript assignment like opts['shell'] = True."""
    if not isinstance(target.value, ast.Name):
        return
    if not isinstance(target.slice, ast.Constant):
        return
    if not isinstance(target.slice.value, str):
        return
    if not isinstance(value, ast.Constant):
        return
    var_name = f"{scope}.{target.value.id}" if scope else target.value.id
    if var_name not in result:
        result[var_name] = {}
    result[var_name][target.slice.value] = str(value.value)


def _extract_dict_literal(node: ast.Dict) -> dict[str, str] | None:
    """Extract constant key-value pairs from an inline ast.Dict.

    Returns ``None`` if any ``**spread`` element is present, since spread
    ordering can override extracted keys and produce false positives.
    """
    if any(k is None for k in node.keys):
        return None
    result: dict[str, str] = {}
    for key_node, value_node in zip(node.keys, node.values, strict=False):
        if (
            isinstance(key_node, ast.Constant)
            and isinstance(key_node.value, str)
            and isinstance(value_node, ast.Constant)
        ):
            result[key_node.value] = str(value_node.value)
    return result


def _lookup_symbol_table_dict(var_name: str, symbol_table: dict[str, str]) -> dict[str, str]:
    """Reconstruct a dict from symbol table composite keys.

    The symbol table stores dict entries as ``'varname[key]'`` composite keys.
    This function enumerates all matching entries and reconstructs the dict.
    """
    prefix = f"{var_name}["
    result: dict[str, str] = {}
    for st_key, st_value in symbol_table.items():
        if st_key.startswith(prefix) and st_key.endswith("]"):
            inner_key = st_key[len(prefix) : -1]
            result[inner_key] = st_value
    return result


def _kwarg_matches(
    resolved: dict[str, str],
    key: str,
    value: object,
) -> bool:
    """Check whether *resolved* contains a matching (key, value) pair.

    The symbol table stores all values as strings, so boolean ``True`` is
    compared against the string ``'True'``.
    """
    if key not in resolved:
        return False
    return str(resolved[key]) == str(value)
