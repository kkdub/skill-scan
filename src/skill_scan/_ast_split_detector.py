"""AST split detector -- detect dangerous names assembled from split variables."""

from __future__ import annotations

import ast
import re

from skill_scan._ast_detectors import _DANGEROUS_NAMES, _make_finding
from skill_scan._ast_split_helpers import (
    _resolve_format_call,
    _resolve_generator_join,
    _resolve_join_elements,
    _resolve_map_join,
    _resolve_percent_format,
)
from skill_scan._ast_split_resolve import resolve_binop_chain, resolve_fstring
from skill_scan.decoder import decode_payload, extract_encoded_strings
from skill_scan.models import Finding, Severity

# Subset of _DANGEROUS_NAMES that map to EXEC-006 (dynamic import/indirection)
_DYNAMIC_IMPORT_NAMES = frozenset({"__import__", "getattr"})

# Remaining dangerous names map to EXEC-002 (code execution)
_EXEC_NAMES = _DANGEROUS_NAMES - _DYNAMIC_IMPORT_NAMES

# Maps each dangerous name -> (rule_id, severity, description prefix)
_NAME_RULE: dict[str, tuple[str, Severity, str]] = {
    **{n: ("EXEC-002", Severity.CRITICAL, "String splitting evasion") for n in _EXEC_NAMES},
    **{n: ("EXEC-006", Severity.HIGH, "Dynamic import evasion") for n in _DYNAMIC_IMPORT_NAMES},
}


def detect_split_evasion(
    tree: ast.Module,
    file_path: str,
    alias_map: dict[str, str],
    symbol_table: dict[str, str],
    *,
    _nodes: list[ast.AST] | None = None,
) -> list[Finding]:
    """Detect dangerous names assembled from split variables via concatenation, f-strings, or join."""
    findings: list[Finding] = []
    scope_map = _build_scope_map(tree)
    for node in _nodes if _nodes is not None else ast.walk(tree):
        scope = scope_map.get(id(node), "")
        resolved = _try_resolve_split(node, symbol_table, scope, alias_map)
        if resolved is None:
            continue
        finding = _check_dangerous(resolved, file_path, node)
        if finding is not None:
            findings.append(finding)
    return findings


def _build_scope_map(tree: ast.Module) -> dict[int, str]:
    """Map node id -> scope name (function name or class name for methods)."""
    result: dict[int, str] = {}
    # Collect (subtree_root, scope_name) pairs for functions and class methods
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


def _try_resolve_split(
    node: ast.AST,
    symbol_table: dict[str, str],
    scope: str,
    alias_map: dict[str, str] | None = None,
) -> str | None:
    """Try to resolve a node to a string via BinOp(Add/Mod), f-string, join, or format."""
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add):
            return resolve_binop_chain(node, symbol_table, scope)
        if isinstance(node.op, ast.Mod):
            return _resolve_percent_format(node, symbol_table, scope)
    if isinstance(node, ast.JoinedStr):
        return resolve_fstring(node, symbol_table, scope)
    if isinstance(node, ast.Call):
        am = alias_map or {}
        return _resolve_join_call(node, symbol_table, scope, am) or _resolve_format_call(
            node, symbol_table, scope
        )
    return None


def _resolve_join_call(
    node: ast.Call,
    symbol_table: dict[str, str],
    scope: str,
    alias_map: dict[str, str] | None = None,
) -> str | None:
    """Resolve ''.join(...) with list/tuple, generator, or map(chr/str) arguments."""
    if not _is_str_join_call(node):
        return None
    if not isinstance(node.func, ast.Attribute) or not isinstance(node.func.value, ast.Constant):
        return None  # defensive: _is_str_join_call guarantees this
    sep = str(node.func.value.value)
    arg = node.args[0]
    if isinstance(arg, ast.List | ast.Tuple):
        return _resolve_join_elements(arg.elts, sep, symbol_table, scope)
    if isinstance(arg, ast.GeneratorExp):
        return _resolve_generator_join(arg, sep, symbol_table, scope)
    if isinstance(arg, ast.Call):
        return _resolve_map_join(arg, sep, alias_map or {})
    return None


def _is_str_join_call(node: ast.Call) -> bool:
    """Check if node is a '<str>'.join(<one_arg>) call."""
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str)
        and len(node.args) == 1
    )


def _check_dangerous(resolved: str, file_path: str, node: ast.AST) -> Finding | None:
    """Return a Finding for a dangerous assembled name, or None if safe."""
    entry = _NAME_RULE.get(resolved)
    if entry is None:
        return _check_encoded(resolved, file_path, node)
    rule_id, severity, desc_prefix = entry
    return _make_finding(
        rule_id=rule_id,
        severity=severity,
        file=file_path,
        line=getattr(node, "lineno", None),
        matched_text=f"split variable evasion building '{resolved}'",
        description=f"{desc_prefix} -- variables reassembled to build '{resolved}' via AST",
    )


def _check_encoded(resolved: str, file_path: str, node: ast.AST) -> Finding | None:
    """Bridge to decoder module for base64/hex/url encoded dangerous payloads."""
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
