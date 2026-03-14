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
    _scoped_lookup,
)
from skill_scan._ast_split_resolve import (
    resolve_binop_chain,
    resolve_bytes_constructor,
    resolve_call_return,
    resolve_fstring,
)
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


_INTROSPECTION_FUNCS = frozenset({"vars", "globals", "locals"})


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
        # Check for dynamic dispatch via introspection subscripts
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


def _check_dynamic_dispatch(
    node: ast.AST,
    symbol_table: dict[str, str],
    scope: str,
    file_path: str,
) -> Finding | None:
    """Detect dynamic dispatch via introspection subscript chains.

    Patterns: globals()['eval'], vars(obj)['eval'], obj.__dict__['eval'],
    and two-level: globals()['__builtins__']['eval'].
    """
    if not isinstance(node, ast.Subscript):
        return None
    key = _extract_subscript_key(node.slice, symbol_table, scope)
    if key is None:
        return None
    value = node.value
    # Two-level chaining: outer[key1][key2] where outer is introspection
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
    """Check if node is an introspection expression: globals(), locals(), vars(...), obj.__dict__."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return node.func.id in _INTROSPECTION_FUNCS
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        return True
    return False


def _extract_subscript_key(slice_node: ast.AST, symbol_table: dict[str, str], scope: str) -> str | None:
    """Extract the subscript key as a string (constant or tracked variable)."""
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
        result = _resolve_join_call(node, symbol_table, scope, am) or _resolve_format_call(
            node, symbol_table, scope
        )
        if result is not None:
            return result
        # Bytes-constructor patterns: bytearray(b'...').decode(), str(b'...',enc), codecs.decode(b'...',enc)
        bytes_result = resolve_bytes_constructor(node, am)
        if bytes_result is not None:
            return bytes_result
        # Fallback: standalone call returning a dangerous name
        return resolve_call_return(node, symbol_table, scope)
    return None


def _resolve_join_call(
    node: ast.Call,
    symbol_table: dict[str, str],
    scope: str,
    alias_map: dict[str, str] | None = None,
) -> str | None:
    """Resolve ''.join(...) with list/tuple, generator, reversed, or map(chr/str) arguments."""
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
        am = alias_map or {}
        rev = _resolve_reversed_join(arg, sep, symbol_table, scope)
        if rev is not None:
            return rev
        return _resolve_map_join(arg, sep, am)
    return None


def _resolve_reversed_join(
    call: ast.Call,
    sep: str,
    symbol_table: dict[str, str],
    scope: str,
) -> str | None:
    """Resolve reversed() inside join: ``''.join(reversed('lave'))`` -> 'eval'.

    Gates to reversed() on:
    - string literal arguments (reversed the characters)
    - List/Tuple of tracked elements (reverse then join)
    - tracked variable names resolving to strings
    """
    if not (isinstance(call.func, ast.Name) and call.func.id == "reversed"):
        return None
    if len(call.args) != 1 or call.keywords:
        return None
    chars = _resolve_reversed_inner(call.args[0], sep, symbol_table, scope)
    if chars is None:
        return None
    return sep.join(reversed(chars))


def _resolve_reversed_inner(
    inner: ast.expr, sep: str, symbol_table: dict[str, str], scope: str
) -> list[str] | None:
    """Resolve the inner argument of reversed() to a list of characters/parts."""
    # reversed('string_literal')
    if isinstance(inner, ast.Constant) and isinstance(inner.value, str):
        return list(inner.value)
    # reversed(['a', 'b', 'c']) or reversed(('a', 'b', 'c'))
    if isinstance(inner, ast.List | ast.Tuple):
        result = _resolve_join_elements(inner.elts, sep, symbol_table, scope)
        if result is None:
            return None
        return result.split(sep) if sep else list(result)
    # reversed(tracked_variable) where variable is a string
    if isinstance(inner, ast.Name):
        val = _scoped_lookup(inner.id, symbol_table, scope)
        if val is not None:
            return list(val)
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
