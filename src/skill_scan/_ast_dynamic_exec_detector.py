"""Tree-level dynamic exec detector -- symbol table + taint sink + ref_table.

Detects unsafe patterns at multiple depths of indirection:

Depth-1 (EXEC-006):
    ``getattr(os, variable)`` where variable resolves to a dangerous name
    via symbol table -> HIGH; unresolvable variable on sensitive module -> MEDIUM.

Depth-2 (EXEC-002):
    ``m = __import__('os'); m.system('cmd')`` -- attribute access on tracked
    module ref emits EXEC-002 CRITICAL.  Tracks ``f = m.system`` as func_ref
    in ref_table.

Depth-3 (EXEC-002):
    ``e = getattr(tracked_mod, 'eval'); e('code')`` -- getattr on a tracked
    ref stores func_ref; bare call on func_ref emits EXEC-002 CRITICAL.
    Depth-3 helpers live in ``_ast_dynamic_exec_depth3``.

Node-level ``_detect_dynamic_access`` already handles constant second args
(e.g. ``getattr(os, 'system')``).  This detector covers variable second args
and ref_table-based detection.
"""

from __future__ import annotations

import ast

from skill_scan._ast_detectors import (
    _DANGEROUS_NAMES,
    _SENSITIVE_MODULES,
    _make_finding,
)
from skill_scan._ast_dynamic_exec_depth3 import (
    _check_bare_func_call,
    _is_dangerous_ref_attr,
    _ref_lookup,
    _track_getattr_ref,
)
from skill_scan._ast_imports import get_call_name
from skill_scan._ast_ref_tracker import RefEntry
from skill_scan._ast_split_detector import _build_scope_map
from skill_scan._ast_split_format import _scoped_lookup
from skill_scan.models import Finding, Severity

# ---------------------------------------------------------------------------
# Depth-1: symbol-table resolution and taint-sink detection (EXEC-006)
# ---------------------------------------------------------------------------


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


def _check_getattr_call(
    node: ast.Call,
    alias_map: dict[str, str],
    symbol_table: dict[str, str],
    scope: str,
    file_path: str,
) -> Finding | None:
    """Check getattr() with variable 2nd arg -> EXEC-006 HIGH or MEDIUM."""
    if get_call_name(node, alias_map) != "getattr" or len(node.args) < 2:
        return None
    second_arg = node.args[1]
    if not isinstance(second_arg, ast.Name):
        return None
    resolved = _scoped_lookup(second_arg.id, symbol_table, scope)
    if resolved is not None:
        return _check_resolved_name(node, second_arg, resolved, file_path)
    return _check_taint_sink(node, second_arg, alias_map, file_path)


# ---------------------------------------------------------------------------
# Depth-2: attribute access on tracked module refs (EXEC-002)
# ---------------------------------------------------------------------------


def _check_ref_attr_call(
    node: ast.Call,
    ref_entry: RefEntry,
    attr: str,
    file_path: str,
) -> Finding | None:
    """Emit EXEC-002 CRITICAL for Call on dangerous attr of a tracked module ref."""
    if ref_entry.kind != "module":
        return None
    if not _is_dangerous_ref_attr(ref_entry.resolved, attr):
        return None
    qualified = f"{ref_entry.resolved}.{attr}"
    return _make_finding(
        rule_id="EXEC-002",
        severity=Severity.CRITICAL,
        file=file_path,
        line=node.lineno,
        matched_text=qualified,
        description=f"Dynamic code execution -- {qualified} via tracked ref",
    )


def _track_func_ref(
    node: ast.Assign,
    ref_table: dict[str, RefEntry],
    scope_map: dict[int, str],
) -> None:
    """Track ``f = m.attr`` where m is a tracked module -> store func_ref."""
    if len(node.targets) != 1:
        return
    target = node.targets[0]
    if not isinstance(target, ast.Name):
        return
    val = node.value
    if not isinstance(val, ast.Attribute) or not isinstance(val.value, ast.Name):
        return
    scope = scope_map.get(id(node), "")
    entry = _ref_lookup(val.value.id, ref_table, scope)
    if entry is None or entry.kind != "module":
        return
    key = f"{scope}.{target.id}" if scope else target.id
    ref_table[key] = RefEntry(kind="func_ref", resolved=f"{entry.resolved}.{val.attr}")


def _check_ref_call(
    node: ast.Call,
    ref_table: dict[str, RefEntry],
    scope_map: dict[int, str],
    file_path: str,
) -> Finding | None:
    """Check Call(func=Attribute(value=Name)) against ref_table -> EXEC-002."""
    func = node.func
    if not isinstance(func, ast.Attribute) or not isinstance(func.value, ast.Name):
        return None
    scope = scope_map.get(id(node), "")
    entry = _ref_lookup(func.value.id, ref_table, scope)
    if entry is None:
        return None
    return _check_ref_attr_call(node, entry, func.attr, file_path)


# ---------------------------------------------------------------------------
# Main detector loop
# ---------------------------------------------------------------------------


def _process_assign(
    node: ast.Assign,
    ref_table: dict[str, RefEntry],
    scope_map: dict[int, str],
    alias_map: dict[str, str],
    file_path: str,
    findings: list[Finding],
) -> None:
    """Handle Assign nodes: track func_ref from m.attr and getattr(ref, 'attr')."""
    _track_func_ref(node, ref_table, scope_map)
    finding = _track_getattr_ref(node, ref_table, scope_map, alias_map, file_path)
    if finding is not None:
        findings.append(finding)


def _process_call(
    node: ast.Call,
    ref_table: dict[str, RefEntry],
    scope_map: dict[int, str],
    file_path: str,
    findings: list[Finding],
) -> None:
    """Handle Call nodes: check ref_table attr access and bare func call."""
    finding = _check_ref_call(node, ref_table, scope_map, file_path)
    if finding is not None:
        findings.append(finding)
    finding = _check_bare_func_call(node, ref_table, scope_map, file_path)
    if finding is not None:
        findings.append(finding)


def detect_dynamic_exec(
    tree: ast.Module,
    file_path: str,
    alias_map: dict[str, str],
    symbol_table: dict[str, str],
    *,
    _nodes: list[ast.AST] | None = None,
    ref_table: dict[str, RefEntry] | None = None,
) -> list[Finding]:
    """Detect dynamic exec via symbol-table, taint-sink, and ref_table paths.

    Note: when *ref_table* is provided, this function **mutates it in-place**
    by adding ``func_ref`` entries discovered during the walk (via
    ``_track_func_ref`` and ``_track_getattr_ref``).  Callers that need an
    unmodified copy should pass ``dict(ref_table)`` instead.
    """
    scope_map = _build_scope_map(tree)
    nodes = _nodes if _nodes is not None else list(ast.walk(tree))
    findings: list[Finding] = []

    for node in nodes:
        # Assign nodes: track func_ref from m.attr and getattr(ref, 'attr') patterns.
        if ref_table is not None and isinstance(node, ast.Assign):
            _process_assign(node, ref_table, scope_map, alias_map, file_path, findings)
            continue
        if not isinstance(node, ast.Call):
            continue
        # Call nodes: check ref_table, bare func call, and getattr symbol resolution.
        if ref_table is not None:
            _process_call(node, ref_table, scope_map, file_path, findings)
        scope = scope_map.get(id(node), "")
        finding = _check_getattr_call(node, alias_map, symbol_table, scope, file_path)
        if finding is not None:
            findings.append(finding)

    return findings
