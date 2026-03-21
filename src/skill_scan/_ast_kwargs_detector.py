"""Kwargs unpacking detector -- detect dangerous keyword arguments via ** unpacking.

Detects subprocess.run(**opts) where opts contains shell=True (or any truthy value).
Table-driven via _DANGEROUS_KWARGS.  Scope-aware via _build_scope_map.

Dict-collection helpers live in ``_ast_kwargs_dict_tracker`` and are re-exported
here for backward compatibility.
"""

from __future__ import annotations

import ast

from skill_scan._ast_detectors import _make_finding
from skill_scan._ast_imports import get_call_name
from skill_scan._ast_kwargs_dict_tracker import (
    _UNRESOLVABLE,
    _collect_dict_assigns,
    _collect_from_body,
    _eval_constant_expr,
    _extract_dict_literal,
    _resolve_dict_operand,
    _track_assign,
    _track_aug_union,
    _track_subscript_assign,
    _track_union,
)
from skill_scan._ast_split_detector import _build_scope_map
from skill_scan.models import Finding, Severity

# Re-export extracted symbols for backward compatibility with existing tests.
__all__ = [
    "_UNRESOLVABLE",
    "_collect_dict_assigns",
    "_collect_from_body",
    "_eval_constant_expr",
    "_extract_dict_literal",
    "_resolve_dict_operand",
    "_track_assign",
    "_track_aug_union",
    "_track_subscript_assign",
    "_track_union",
]

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
    scope_map = _build_scope_map(tree, method_scope=True)
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
