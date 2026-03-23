"""Tree-level dynamic exec detector -- symbol table + taint sink.

Detects getattr() calls where the second argument is a variable that
resolves to a dangerous name (HIGH) or cannot be resolved but targets
a sensitive module (MEDIUM taint sink).

Node-level _detect_dynamic_access already handles constant second args
(e.g. getattr(os, 'system')). This detector covers variable second args.
"""

from __future__ import annotations

import ast

from skill_scan._ast_detectors import (
    _DANGEROUS_NAMES,
    _SENSITIVE_MODULES,
    _make_finding,
)
from skill_scan._ast_imports import get_call_name
from skill_scan._ast_split_detector import _build_scope_map
from skill_scan._ast_split_format import _scoped_lookup
from skill_scan.models import Finding, Severity


def _resolve_first_arg(node: ast.Call, alias_map: dict[str, str]) -> str | None:
    """Resolve the first argument of a Call to a module name via alias_map."""
    if not node.args:
        return None
    arg = node.args[0]
    if isinstance(arg, ast.Name):
        return alias_map.get(arg.id, arg.id)
    if isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name):
        return alias_map.get(arg.value.id, arg.value.id)
    return None


def _check_resolved_name(
    node: ast.Call,
    second_arg: ast.Name,
    resolved: str,
    file_path: str,
) -> Finding | None:
    """Emit EXEC-006 HIGH when symbol-table resolution reaches a dangerous name."""
    if resolved not in _DANGEROUS_NAMES:
        return None
    return _make_finding(
        rule_id="EXEC-006",
        severity=Severity.HIGH,
        file=file_path,
        line=node.lineno,
        matched_text=f"getattr(..., {second_arg.id}='{resolved}')",
        description=(
            f"Dynamic indirection -- getattr resolves variable"
            f" '{second_arg.id}' to '{resolved}' via symbol table"
        ),
    )


def _check_taint_sink(
    node: ast.Call,
    second_arg: ast.Name,
    alias_map: dict[str, str],
    file_path: str,
) -> Finding | None:
    """Emit EXEC-006 MEDIUM when an unresolvable variable targets a sensitive module."""
    module_name = _resolve_first_arg(node, alias_map)
    if module_name not in _SENSITIVE_MODULES:
        return None
    return _make_finding(
        rule_id="EXEC-006",
        severity=Severity.MEDIUM,
        file=file_path,
        line=node.lineno,
        matched_text=f"getattr({module_name}, {second_arg.id})",
        description=(
            f"Dynamic indirection -- getattr on sensitive module"
            f" '{module_name}' with unresolvable variable '{second_arg.id}'"
        ),
    )


def detect_dynamic_exec(
    tree: ast.Module,
    file_path: str,
    alias_map: dict[str, str],
    symbol_table: dict[str, str],
    *,
    _nodes: list[ast.AST] | None = None,
) -> list[Finding]:
    """Detect getattr() with variable second arg resolving to dangerous names.

    Two detection modes:
    1. Symbol-table resolution: 2nd arg is a Name that resolves to a
       dangerous name -> EXEC-006 HIGH.
    2. Taint sink: 1st arg is a sensitive module, 2nd arg is a Name
       that cannot be resolved -> EXEC-006 MEDIUM.
    """
    scope_map = _build_scope_map(tree)
    nodes = _nodes if _nodes is not None else list(ast.walk(tree))
    findings: list[Finding] = []

    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        if get_call_name(node, alias_map) != "getattr" or len(node.args) < 2:
            continue
        second_arg = node.args[1]
        if not isinstance(second_arg, ast.Name):
            continue

        scope = scope_map.get(id(node), "")
        resolved = _scoped_lookup(second_arg.id, symbol_table, scope)

        if resolved is not None:
            finding = _check_resolved_name(node, second_arg, resolved, file_path)
        else:
            finding = _check_taint_sink(node, second_arg, alias_map, file_path)

        if finding is not None:
            findings.append(finding)

    return findings
