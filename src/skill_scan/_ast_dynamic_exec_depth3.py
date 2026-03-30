"""Depth-3 dynamic exec detection helpers -- getattr-on-ref and bare call resolution.

Extracted from ``_ast_dynamic_exec_detector.py`` to keep file complexity under
thresholds. These helpers implement two detection paths:

PATH 1 -- getattr on tracked module ref:
    ``e = getattr(tracked_mod, 'eval')`` stores a func_ref in ref_table.
    If the attr is dangerous (eval, exec, system, popen, etc.), also emits
    EXEC-002 CRITICAL immediately.

PATH 2 -- bare call on tracked func_ref:
    ``e('code')`` where ``e`` resolves in ref_table as a func_ref whose
    resolved name is dangerous emits EXEC-002 CRITICAL.

Both paths are called from the main ``detect_dynamic_exec`` walk loop via
``_process_assign`` and ``_process_call``.
"""

from __future__ import annotations

import ast

from skill_scan._ast_detectors import (
    _DANGEROUS_NAMES,
    _INLINE_CHAIN_ATTRS as _EXEC_ATTR_NAMES,
    _UNSAFE_EXEC_CALLS,
    _make_finding,
)
from skill_scan._ast_exfil_detector import _SUBPROCESS_CALLS
from skill_scan._ast_imports import get_call_name
from skill_scan._ast_ref_tracker import RefEntry
from skill_scan.models import Finding, Severity

_DANGEROUS_QUALIFIED: frozenset[str] = _UNSAFE_EXEC_CALLS | _SUBPROCESS_CALLS


def _ref_lookup(
    name: str,
    ref_table: dict[str, RefEntry],
    scope: str,
) -> RefEntry | None:
    """Scope-aware lookup in ref_table (mirrors _scoped_lookup for RefEntry)."""
    if scope:
        scoped = ref_table.get(f"{scope}.{name}")
        if scoped is not None:
            return scoped
    return ref_table.get(name)


def _is_dangerous_ref_attr(module: str, attr: str) -> bool:
    """Check if module.attr is a dangerous execution target."""
    if attr in _EXEC_ATTR_NAMES:
        return True
    return f"{module}.{attr}" in _DANGEROUS_QUALIFIED


def _getattr_call_parts(val: ast.expr, alias_map: dict[str, str]) -> tuple[ast.Name, str] | None:
    """Extract (first_arg_name, attr_str) from a ``getattr(name, 'str')`` Call.

    Returns None when the expression is not a getattr() call with a Name
    first arg and a constant string second arg.
    """
    if not isinstance(val, ast.Call):
        return None
    if get_call_name(val, alias_map) != "getattr" or len(val.args) < 2:
        return None
    first_arg = val.args[0]
    second_arg = val.args[1]
    if not isinstance(first_arg, ast.Name):
        return None
    if not isinstance(second_arg, ast.Constant) or not isinstance(second_arg.value, str):
        return None
    return first_arg, second_arg.value


def _extract_getattr_on_ref(
    node: ast.Assign,
    ref_table: dict[str, RefEntry],
    scope_map: dict[int, str],
    alias_map: dict[str, str],
) -> tuple[str, str, RefEntry] | None:
    """Extract (target_name, attr, module_entry) from ``x = getattr(ref, 'a')``.

    Validates that the Assign has a single Name target, the RHS is a getattr()
    call with a first arg that resolves to a tracked module in ref_table, and
    the second arg is a constant string.

    Returns None when any of these conditions are not met.
    """
    if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
        return None
    parts = _getattr_call_parts(node.value, alias_map)
    if parts is None:
        return None
    first_arg, attr = parts
    scope = scope_map.get(id(node), "")
    entry = _ref_lookup(first_arg.id, ref_table, scope)
    if entry is None or entry.kind != "module":
        return None
    return node.targets[0].id, attr, entry


def _track_getattr_ref(
    node: ast.Assign,
    ref_table: dict[str, RefEntry],
    scope_map: dict[int, str],
    alias_map: dict[str, str],
    file_path: str,
) -> Finding | None:
    """Track ``e = getattr(mod, 'attr')`` where mod is in ref_table.

    Always stores the func_ref in ref_table (dangerous or safe).
    Emits EXEC-002 CRITICAL when the resolved attribute is dangerous.
    Returns None otherwise.
    """
    extracted = _extract_getattr_on_ref(node, ref_table, scope_map, alias_map)
    if extracted is None:
        return None
    target_name, attr, entry = extracted
    qualified = f"{entry.resolved}.{attr}"
    scope = scope_map.get(id(node), "")
    key = f"{scope}.{target_name}" if scope else target_name
    ref_table[key] = RefEntry(kind="func_ref", resolved=qualified)
    if not _is_dangerous_ref_attr(entry.resolved, attr):
        return None
    return _make_finding(
        rule_id="EXEC-002",
        severity=Severity.CRITICAL,
        file=file_path,
        line=node.lineno,
        matched_text=qualified,
        description=f"Dynamic code execution -- {qualified} via getattr on tracked ref",
    )


def _is_dangerous_resolved(resolved: str) -> bool:
    """Check whether a fully-resolved func_ref name is dangerous.

    Splits on '.' to separate module from attr, then checks _is_dangerous_ref_attr.
    Falls back to _DANGEROUS_NAMES for unqualified names.
    """
    parts = resolved.rsplit(".", 1)
    if len(parts) == 2:
        return _is_dangerous_ref_attr(parts[0], parts[1])
    return resolved in _DANGEROUS_NAMES


def _check_bare_func_call(
    node: ast.Call,
    ref_table: dict[str, RefEntry],
    scope_map: dict[int, str],
    file_path: str,
) -> Finding | None:
    """Check ``Call(func=Name)`` against ref_table func_ref entries.

    If the Name resolves in ref_table as a func_ref whose resolved name
    is dangerous, emits EXEC-002 CRITICAL.
    """
    func = node.func
    if not isinstance(func, ast.Name):
        return None
    scope = scope_map.get(id(node), "")
    entry = _ref_lookup(func.id, ref_table, scope)
    if entry is None or entry.kind != "func_ref":
        return None
    if not _is_dangerous_resolved(entry.resolved):
        return None
    return _make_finding(
        rule_id="EXEC-002",
        severity=Severity.CRITICAL,
        file=file_path,
        line=node.lineno,
        matched_text=entry.resolved,
        description=f"Dynamic code execution -- {entry.resolved} via tracked func ref",
    )
