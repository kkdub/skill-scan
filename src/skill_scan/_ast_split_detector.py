"""AST split detector -- detect dangerous names assembled from split variables."""

from __future__ import annotations

import ast

from skill_scan._ast_detectors import _DANGEROUS_NAMES, _make_finding
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
) -> list[Finding]:
    """Detect dangerous names assembled from split variables via concatenation, f-strings, or join."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        resolved = _try_resolve_split(node, symbol_table)
        if resolved is None:
            continue
        finding = _check_dangerous(resolved, file_path, node)
        if finding is not None:
            findings.append(finding)
    return findings


def _try_resolve_split(
    node: ast.AST,
    symbol_table: dict[str, str],
) -> str | None:
    """Try to resolve a node to a string using the symbol table.

    Handles BinOp(Add) chains, f-strings, and join calls.
    Returns None if any fragment is unresolvable.
    """
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _resolve_binop_chain(node, symbol_table)
    if isinstance(node, ast.JoinedStr):
        return _resolve_fstring(node, symbol_table)
    if isinstance(node, ast.Call):
        return _resolve_join_call(node, symbol_table)
    return None


def _resolve_binop_chain(
    node: ast.BinOp,
    symbol_table: dict[str, str],
) -> str | None:
    """Recursively resolve BinOp(Add) chains: a + b + c -> BinOp(BinOp(a, +, b), +, c)."""
    left = _resolve_operand(node.left, symbol_table)
    if left is None:
        return None
    right = _resolve_operand(node.right, symbol_table)
    if right is None:
        return None
    return left + right


def _resolve_operand(
    node: ast.expr,
    symbol_table: dict[str, str],
) -> str | None:
    """Resolve a single BinOp operand: nested BinOp, Name lookup, or Constant."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _resolve_binop_chain(node, symbol_table)
    if isinstance(node, ast.Name):
        return symbol_table.get(node.id)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _resolve_fstring(
    node: ast.JoinedStr,
    symbol_table: dict[str, str],
) -> str | None:
    """Resolve an f-string where all interpolated values are tracked variables.

    F-string values are either ast.Constant (static text) or
    ast.FormattedValue (interpolated expressions). Only simple Name
    references in FormattedValue are resolved.
    """
    parts: list[str] = []
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            parts.append(value.value)
        elif isinstance(value, ast.FormattedValue):
            resolved = _resolve_formatted_value(value, symbol_table)
            if resolved is None:
                return None
            parts.append(resolved)
        else:
            return None
    return "".join(parts)


def _resolve_formatted_value(
    node: ast.FormattedValue,
    symbol_table: dict[str, str],
) -> str | None:
    """Resolve a FormattedValue: simple Name without format spec or conversion."""
    if node.conversion != -1 or node.format_spec is not None:
        return None
    if isinstance(node.value, ast.Name):
        return symbol_table.get(node.value.id)
    return None


def _resolve_join_call(
    node: ast.Call,
    symbol_table: dict[str, str],
) -> str | None:
    """Resolve ''.join([a, b, ...]) where elements are tracked variables.

    The receiver must be a string constant (the separator).
    The argument must be a list/tuple literal with Name or Constant elements.
    """
    if not _is_str_join_call(node):
        return None

    if not isinstance(node.func, ast.Attribute) or not isinstance(node.func.value, ast.Constant):
        return None  # defensive: _is_str_join_call guarantees this branch is unreachable
    sep = str(node.func.value.value)
    arg = node.args[0]

    if not isinstance(arg, ast.List | ast.Tuple):
        return None

    return _resolve_join_elements(arg.elts, sep, symbol_table)


def _is_str_join_call(node: ast.Call) -> bool:
    """Check if node is a '<str>'.join(<one_arg>) call."""
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str)
        and len(node.args) == 1
    )


def _resolve_join_elements(
    elts: list[ast.expr],
    sep: str,
    symbol_table: dict[str, str],
) -> str | None:
    """Resolve list/tuple elements to a joined string using the symbol table."""
    parts: list[str] = []
    for elt in elts:
        if isinstance(elt, ast.Name):
            val = symbol_table.get(elt.id)
            if val is None:
                return None
            parts.append(val)
        elif isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            parts.append(elt.value)
        else:
            return None
    return sep.join(parts)


def _check_dangerous(
    resolved: str,
    file_path: str,
    node: ast.AST,
) -> Finding | None:
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
    """Check if resolved string contains an encoded dangerous payload."""
    for payload in extract_encoded_strings(resolved):
        decoded = decode_payload(payload)
        if decoded is None:
            continue
        for name in _DANGEROUS_NAMES:
            if name in decoded:
                return _make_finding(
                    rule_id="EXEC-002",
                    severity=Severity.CRITICAL,
                    file=file_path,
                    line=getattr(node, "lineno", None),
                    matched_text=f"split encoded evasion: decoded '{name}'",
                    description=f"Encoded payload decoded to dangerous name '{name}' via AST",
                )
    return None
