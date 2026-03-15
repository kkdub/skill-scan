"""AST split detector -- detect dangerous names assembled from split variables.
Uses a registry of (predicate, resolver) pairs to dispatch node types.
Dynamic dispatch via introspection subscripts is handled separately.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Callable

from skill_scan._ast_detectors import _DANGEROUS_NAMES, _make_finding
from skill_scan._ast_split_helpers import _scoped_lookup
from skill_scan._ast_split_resolve import (
    _resolve_replace_chain,
    resolve_binop_chain,
    resolve_call,
    resolve_fstring,
    resolve_percent_format,
)
from skill_scan.decoder import decode_payload, extract_encoded_strings
from skill_scan.models import Finding, Severity

# EXEC-006 names (dynamic import/indirection) vs EXEC-002 (code execution)
_DYNAMIC_IMPORT_NAMES = frozenset({"__import__", "getattr"})
_EXEC_NAMES = _DANGEROUS_NAMES - _DYNAMIC_IMPORT_NAMES
_NAME_RULE: dict[str, tuple[str, Severity, str]] = {
    **{n: ("EXEC-002", Severity.CRITICAL, "String splitting evasion") for n in _EXEC_NAMES},
    **{n: ("EXEC-006", Severity.HIGH, "Dynamic import evasion") for n in _DYNAMIC_IMPORT_NAMES},
}
_INTROSPECTION_FUNCS = frozenset({"vars", "globals", "locals"})  # dynamic dispatch detection
# -- Resolver registry: (predicate, resolver) pairs for _try_resolve_split --
_Predicate = Callable[[ast.AST], bool]
_Resolver = Callable[..., str | None]
_is_binop_add: _Predicate = lambda n: isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add)  # noqa: E731
_is_binop_mod: _Predicate = lambda n: isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod)  # noqa: E731
_is_fstr: _Predicate = lambda n: isinstance(n, ast.JoinedStr)  # noqa: E731
_is_call: _Predicate = lambda n: isinstance(n, ast.Call)  # noqa: E731


def _is_replace(n: ast.AST) -> bool:
    """Check if node is a .replace() method call."""
    func = getattr(n, "func", None)
    return _is_call(n) and isinstance(func, ast.Attribute) and func.attr == "replace"


_RESOLVERS: tuple[tuple[_Predicate, _Resolver], ...] = (
    (_is_binop_add, resolve_binop_chain),
    (_is_binop_mod, resolve_percent_format),
    (_is_fstr, resolve_fstring),
    (_is_replace, _resolve_replace_chain),
    (_is_call, resolve_call),
)


def detect_split_evasion(
    tree: ast.Module,
    file_path: str,
    alias_map: dict[str, str],
    symbol_table: dict[str, str],
    *,
    _nodes: list[ast.AST] | None = None,
) -> list[Finding]:
    """Detect dangerous names assembled from split variables."""
    findings: list[Finding] = []
    scope_map = _build_scope_map(tree)
    for node in _nodes if _nodes is not None else ast.walk(tree):
        scope = scope_map.get(id(node), "")
        # Dynamic dispatch via introspection subscripts
        dd = _check_dynamic_dispatch(node, symbol_table, scope, file_path)
        if dd is not None:
            findings.append(dd)
            continue
        resolved = _try_resolve_split(node, symbol_table, scope, alias_map)
        if resolved is None:
            continue
        finding = _check_dangerous(resolved, file_path, node)
        if finding is not None:
            findings.append(finding)
    return findings


def _build_scope_map(tree: ast.Module) -> dict[int, str]:
    """Map node id -> scope name (function or class name for methods)."""
    result: dict[int, str] = {}
    pairs: list[tuple[ast.AST, str]] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            pairs.append((node, node.name))
        elif isinstance(node, ast.ClassDef):
            for stmt in node.body:
                if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
                    pairs.append((stmt, node.name))
    for root, scope_name in pairs:
        for child in ast.walk(root):
            result[id(child)] = scope_name
    return result


def _check_dynamic_dispatch(
    node: ast.AST,
    symbol_table: dict[str, str],
    scope: str,
    file_path: str,
) -> Finding | None:
    """Detect dynamic dispatch via introspection subscript chains."""
    if not isinstance(node, ast.Subscript):
        return None
    key = _extract_subscript_key(node.slice, symbol_table, scope)
    if key is None:
        return None
    value = node.value
    is_two_level = isinstance(value, ast.Subscript) and _is_introspection_base(value.value)
    if not is_two_level and not _is_introspection_base(value):
        return None
    entry = _NAME_RULE.get(key)
    if entry is None:
        return None
    rule_id, severity, desc_prefix = entry
    label = "chained subscript" if is_two_level else "introspection subscript"
    return _make_finding(
        rule_id=rule_id,
        severity=severity,
        file=file_path,
        line=getattr(node, "lineno", None),
        matched_text=f"split evasion: dynamic dispatch via {label} to '{key}'",
        description=f"{desc_prefix} -- {label} resolves to '{key}'",
    )


def _is_introspection_base(node: ast.AST) -> bool:
    """Check if node is globals(), locals(), vars(...), or obj.__dict__."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return node.func.id in _INTROSPECTION_FUNCS
    return isinstance(node, ast.Attribute) and node.attr == "__dict__"


def _extract_subscript_key(slice_node: ast.AST, symbol_table: dict[str, str], scope: str) -> str | None:
    """Extract subscript key as a string (constant or tracked variable)."""
    if isinstance(slice_node, ast.Constant) and isinstance(slice_node.value, str):
        return slice_node.value
    if isinstance(slice_node, ast.Name):
        return _scoped_lookup(slice_node.id, symbol_table, scope)
    return None


def _try_resolve_split(
    node: ast.AST,
    symbol_table: dict[str, str],
    scope: str,
    alias_map: dict[str, str] | None = None,
) -> str | None:
    """Try to resolve a node to a string via the _RESOLVERS registry."""
    for pred, resolver in _RESOLVERS:
        if pred(node):
            result = resolver(node, symbol_table, scope, alias_map=alias_map)
            if result is not None:
                return result
    return None


def _check_dangerous(resolved: str, file_path: str, node: ast.AST) -> Finding | None:
    """Return a Finding for a dangerous assembled name, or None if safe."""
    entry = _NAME_RULE.get(resolved)
    if entry is not None:
        rule_id, severity, desc_prefix = entry
        return _make_finding(
            rule_id=rule_id,
            severity=severity,
            file=file_path,
            line=getattr(node, "lineno", None),
            matched_text=f"split variable evasion building '{resolved}'",
            description=f"{desc_prefix} -- variables reassembled to build '{resolved}' via AST",
        )
    # Bridge to decoder for base64/hex/url encoded payloads
    for payload in extract_encoded_strings(resolved):
        decoded = decode_payload(payload)
        if decoded is None:
            continue
        for name in _DANGEROUS_NAMES:
            if re.search(rf"\b{re.escape(name)}\b", decoded):
                return _make_finding(
                    rule_id="EXEC-002",
                    severity=Severity.CRITICAL,
                    file=file_path,
                    line=getattr(node, "lineno", None),
                    matched_text=f"split encoded evasion: decoded '{name}'",
                    description=f"Encoded payload decoded to dangerous name '{name}' via AST",
                )
    return None
