"""AST split detector -- registry-based dispatch for dangerous-name reconstruction.

Walks AST nodes to find string-assembly patterns building dangerous names.
Uses predicate/resolver pairs: binop-add, %-format, f-string, .replace(), call.
"""

from __future__ import annotations

import ast
from collections.abc import Callable

from skill_scan._ast_detectors import _make_finding
from skill_scan._ast_split_bytes import _build_bytes_table, resolve_fromhex_concat
from skill_scan._ast_split_format import _scoped_lookup
from skill_scan._ast_split_match import _NAME_RULE, _check_dangerous
from skill_scan._ast_split_resolve import (
    _is_case_method,
    _resolve_case_method_chain,
    _resolve_replace_chain,
    resolve_binop_chain,
    resolve_call,
    resolve_call_return,
    resolve_fstring,
    resolve_percent_format,
    resolve_subscript,
)
from skill_scan.models import Finding

_INTROSPECTION_FUNCS = frozenset({"vars", "globals", "locals"})  # dynamic dispatch detection
_Predicate = Callable[[ast.AST], bool]
_Resolver = Callable[..., str | None]


def _is_binop_add(n: ast.AST) -> bool:
    return isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add)


def _is_binop_mod(n: ast.AST) -> bool:
    return isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod)


def _is_fstr(n: ast.AST) -> bool:
    return isinstance(n, ast.JoinedStr)


def _is_call(n: ast.AST) -> bool:
    return isinstance(n, ast.Call)


def _is_replace(n: ast.AST) -> bool:
    func = getattr(n, "func", None)
    return _is_call(n) and isinstance(func, ast.Attribute) and func.attr == "replace"


def _is_case(n: ast.AST) -> bool:
    return isinstance(n, ast.Call) and _is_case_method(n)


def _is_subscript(n: ast.AST) -> bool:
    return isinstance(n, ast.Subscript)


_RESOLVERS: tuple[tuple[_Predicate, _Resolver], ...] = (
    (_is_binop_add, resolve_binop_chain),
    (_is_binop_mod, resolve_percent_format),
    (_is_fstr, resolve_fstring),
    (_is_replace, _resolve_replace_chain),
    (_is_case, _resolve_case_method_chain),
    (_is_subscript, resolve_subscript),
    (_is_call, resolve_call),
)


def detect_split_evasion(
    tree: ast.Module,
    file_path: str,
    alias_map: dict[str, str],
    symbol_table: dict[str, str],
    *,
    _nodes: list[ast.AST] | None = None,
    int_list_table: dict[str, list[int]] | None = None,
) -> list[Finding]:
    """Detect dangerous names assembled from split variables."""
    findings: list[Finding] = []
    scope_map = _build_scope_map(tree)
    il_scope_map = _build_scope_map(tree, method_scope=True) if int_list_table else scope_map
    bytes_table = _build_bytes_table(tree)
    for node in _nodes if _nodes is not None else ast.walk(tree):
        scope = scope_map.get(id(node), "")
        # Dynamic dispatch via introspection subscripts
        dd = _check_dynamic_dispatch(node, symbol_table, scope, file_path)
        if dd is not None:
            findings.append(dd)
            continue
        # bytes.fromhex() concat: (bytes.fromhex('XX') + ...).decode()
        if isinstance(node, ast.Call):
            fh = resolve_fromhex_concat(node, bytes_table, symbol_table)
            if fh is not None:
                finding = _check_dangerous(fh, file_path, node, label="split variable")
                if finding is not None:
                    findings.append(finding)
                    continue
        il_scope = il_scope_map.get(id(node), "")
        pair = _try_resolve_split(
            node,
            symbol_table,
            scope,
            alias_map,
            int_list_table=int_list_table,
            int_list_scope=il_scope,
        )
        if pair is None:
            continue
        resolved, label = pair
        finding = _check_dangerous(resolved, file_path, node, label=label)
        if finding is not None:
            findings.append(finding)
    return findings


def _build_scope_map(tree: ast.Module, *, method_scope: bool = False) -> dict[int, str]:
    """Map node id -> scope name.

    When *method_scope* is True, class methods get ``ClassName.method``
    instead of just ``ClassName``, giving per-method granularity.
    """
    result: dict[int, str] = {}
    pairs: list[tuple[ast.AST, str]] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            pairs.append((node, node.name))
        elif isinstance(node, ast.ClassDef):
            # Map class body statements (non-method) to class scope
            for stmt in node.body:
                if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
                    scope = f"{node.name}.{stmt.name}" if method_scope else node.name
                    pairs.append((stmt, scope))
                else:
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
    *,
    int_list_table: dict[str, list[int]] | None = None,
    int_list_scope: str = "",
) -> tuple[str, str] | None:
    """Try each resolver; returns (resolved, label) or None.

    Label is 'call-return' when resolution came from call-return tracking,
    'split variable' otherwise.
    """
    for pred, resolver in _RESOLVERS:
        if not pred(node):
            continue
        kw: dict[str, object] = {"alias_map": alias_map}
        if resolver is resolve_call:
            kw["int_list_table"] = int_list_table
            kw["int_list_scope"] = int_list_scope
        result = resolver(node, symbol_table, scope, **kw)
        if result is not None:
            label = "split variable"
            if isinstance(node, ast.Call):
                cr = resolve_call_return(node, symbol_table, scope)
                if cr == result:
                    label = "call-return"
            return result, label
    return None
