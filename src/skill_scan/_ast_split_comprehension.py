"""AST split join helpers -- join resolution for the split detector.

Resolves ``''.join(...)`` patterns (list/generator/map/reversed) and tracked
int-list variables used as comprehension iterables via ``_collect_int_list_assigns``.

Public surface
--------------
``_collect_int_list_assigns(tree)``
    Pre-pass that collects all ``Name = [int, ...]`` assignments and mutations
    (``+=``, ``.extend()``) from all scopes.  Returns ``dict[str, list[int]]``
    keyed by ``scope.name`` (module-level uses empty-string prefix).

``_resolve_join_call(node, symbol_table, scope, ...)``
    Top-level resolver: returns the decoded string for ``'sep'.join(arg)`` or
    None if the argument cannot be statically resolved.
"""

from __future__ import annotations

import ast

from skill_scan._ast_split_format import _resolve_expr_list, _resolve_join_elements, _scoped_lookup
from skill_scan._ast_split_int_list_tracker import _SHADOW, _handle_int_list_stmt
from skill_scan._ast_split_map_resolver import _resolve_call_fn_name, _resolve_map_chr, _resolve_map_join
from skill_scan._ast_split_star_unpack import _maybe_flatten_starred
from skill_scan._ast_symbol_table_returns import _sub_bodies


def _collect_int_list_assigns(tree: ast.Module) -> dict[str, list[int]]:
    """Pre-pass: collect and track int-list assignments and mutations (+=, .extend()) from all scopes."""
    result: dict[str, list[int]] = {}
    _collect_int_lists_from_body(tree.body, "", result)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            _collect_int_lists_from_body(node.body, node.name, result)
        elif isinstance(node, ast.ClassDef):
            _collect_int_lists_from_body(node.body, node.name, result)
            for stmt in node.body:
                if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
                    _collect_int_lists_from_body(stmt.body, f"{node.name}.{stmt.name}", result)
    return result


def _collect_int_lists_from_body(body: list[ast.stmt], scope: str, result: dict[str, list[int]]) -> None:
    """Collect assignments; int-lists get values, others get _SHADOW sentinel."""
    for stmt in body:
        _handle_int_list_stmt(stmt, scope, result)
        for child_body in _sub_bodies(stmt):
            _collect_int_lists_from_body(child_body, scope, result)


def _resolve_comprehension_join(
    node: ast.GeneratorExp | ast.ListComp,
    sep: str,
    symbol_table: dict[str, str],
    scope: str,
    *,
    alias_map: dict[str, str] | None = None,
    int_list_table: dict[str, list[int]] | None = None,
    int_list_scope: str = "",
) -> str | None:
    """Resolve generator or list comprehension inside join to a string."""
    if len(node.generators) == 2:
        return _resolve_nested_comprehension_join(node, sep, alias_map=alias_map)
    if len(node.generators) != 1:
        return None
    comp = node.generators[0]
    if comp.ifs or not isinstance(comp.target, ast.Name):
        return None
    am = alias_map or {}
    if isinstance(comp.iter, ast.List | ast.Tuple):
        return _resolve_direct_iter(
            node.elt, comp.target.id, comp.iter.elts, sep, symbol_table, scope, alias_map=am
        )
    if isinstance(comp.iter, ast.Name) and int_list_table:
        return _resolve_tracked_iter(
            node.elt,
            comp.target.id,
            comp.iter.id,
            sep,
            int_list_table,
            scope,
            alias_map=am,
            int_list_scope=int_list_scope,
        )
    return None


def _flatten_list_of_lists(outer_iter: ast.expr) -> list[ast.expr] | None:
    """Flatten a ``[[int, ...], [int, ...]]`` literal to a 1D element list, or None."""
    if not isinstance(outer_iter, ast.List | ast.Tuple):
        return None
    flat: list[ast.expr] = []
    for elt in outer_iter.elts:
        if not isinstance(elt, ast.List):
            return None
        flat.extend(elt.elts)
    return flat


def _resolve_nested_comprehension_join(
    node: ast.GeneratorExp | ast.ListComp,
    sep: str,
    *,
    alias_map: dict[str, str] | None = None,
) -> str | None:
    """Resolve nested comprehension: ``chr(c) for row in [[ints], ...] for c in row``.

    Handles exactly 2 generators where the outer iterates a List/Tuple of Lists
    (2D int array), the inner target iterates the outer variable, and the element
    is chr(inner_target).
    """
    outer, inner = node.generators[0], node.generators[1]
    if outer.ifs or inner.ifs:
        return None
    if not isinstance(outer.target, ast.Name) or not isinstance(inner.target, ast.Name):
        return None
    if not isinstance(inner.iter, ast.Name) or inner.iter.id != outer.target.id:
        return None
    flat = _flatten_list_of_lists(outer.iter)
    if flat is None:
        return None
    return _resolve_comprehension_chr(node.elt, inner.target.id, flat, sep, alias_map=alias_map)


def _resolve_direct_iter(
    elt: ast.expr,
    target_id: str,
    iter_elts: list[ast.expr],
    sep: str,
    symbol_table: dict[str, str],
    scope: str,
    *,
    alias_map: dict[str, str] | None = None,
) -> str | None:
    """Resolve comprehension with direct List/Tuple iteration source."""
    # Try chr(x) pattern first: chr(c) for c in [101, 118, ...]
    chr_result = _resolve_comprehension_chr(elt, target_id, iter_elts, sep, alias_map=alias_map)
    if chr_result is not None:
        return chr_result
    # Identity pattern: x for x in ['ev', 'al']
    if isinstance(elt, ast.Name) and elt.id == target_id:
        parts = _resolve_expr_list(iter_elts, symbol_table, scope)
        if parts is not None:
            return sep.join(parts)
    return None


def _resolve_tracked_iter(
    elt: ast.expr,
    target_id: str,
    iter_name: str,
    sep: str,
    int_list_table: dict[str, list[int]],
    scope: str,
    *,
    alias_map: dict[str, str] | None = None,
    int_list_scope: str = "",
) -> str | None:
    """Resolve comprehension with tracked int-list variable as iteration source."""
    ls = int_list_scope or scope
    int_list = int_list_table.get(f"{ls}.{iter_name}") if ls else None
    if int_list is _SHADOW:
        return None  # Shadow marker: locally bound but not an int list
    if int_list is None:
        int_list = int_list_table.get(iter_name)
    if int_list is _SHADOW or not int_list:
        return None
    synthetic: list[ast.expr] = [ast.Constant(value=v) for v in int_list]
    return _resolve_comprehension_chr(elt, target_id, synthetic, sep, alias_map=alias_map)


def _resolve_comprehension_chr(
    elt: ast.expr,
    target_id: str,
    iter_elts: list[ast.expr],
    sep: str,
    *,
    alias_map: dict[str, str] | None = None,
) -> str | None:
    """Resolve ``chr(x) for x in [int, ...]`` comprehension pattern."""
    # Verify the element is a chr() call with the loop variable as argument
    if not (isinstance(elt, ast.Call) and len(elt.args) == 1 and not elt.keywords):
        return None
    fn_name = _resolve_call_fn_name(elt.func, alias_map or {})
    if fn_name not in ("chr", "builtins.chr"):
        return None
    arg = elt.args[0]
    if not (isinstance(arg, ast.Name) and arg.id == target_id):
        return None
    return _resolve_map_chr(iter_elts, sep)


def _is_str_join_call(node: ast.Call) -> bool:
    """Check if node is a '<str>'.join(<one_arg>) call."""
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str)
        and len(node.args) == 1
    )


def _resolve_reversed_inner(
    inner: ast.expr, sep: str, symbol_table: dict[str, str], scope: str
) -> list[str] | None:
    """Resolve the inner argument of reversed() to a list of characters/parts."""
    # reversed('string_literal')
    if isinstance(inner, ast.Constant) and isinstance(inner.value, str):
        return list(inner.value)
    # reversed(['a', 'b', 'c']) or reversed(('a', 'b', 'c'))
    if isinstance(inner, ast.List | ast.Tuple):
        return _resolve_expr_list(inner.elts, symbol_table, scope)
    # reversed(tracked_variable) where variable is a string
    if isinstance(inner, ast.Name):
        val = _scoped_lookup(inner.id, symbol_table, scope)
        if val is not None:
            return list(val)
    return None


def _resolve_reversed_join(
    call: ast.Call,
    sep: str,
    symbol_table: dict[str, str],
    scope: str,
) -> str | None:
    """Resolve reversed() inside join: ``''.join(reversed('lave'))`` -> 'eval'."""
    # Gate: must be a direct reversed() call with exactly one positional arg
    if not (isinstance(call.func, ast.Name) and call.func.id == "reversed"):
        return None
    if len(call.args) != 1 or call.keywords:
        return None
    chars = _resolve_reversed_inner(call.args[0], sep, symbol_table, scope)
    if chars is None:
        return None
    return sep.join(reversed(chars))


def _resolve_join_call(
    node: ast.Call,
    symbol_table: dict[str, str],
    scope: str,
    alias_map: dict[str, str] | None = None,
    *,
    int_list_table: dict[str, list[int]] | None = None,
    int_list_scope: str = "",
) -> str | None:
    """Resolve ''.join(...) with list/tuple, generator, reversed, or map(chr/str) arguments."""
    if not _is_str_join_call(node):
        return None
    if not (isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Constant)):
        return None  # pragma: no cover — _is_str_join_call guarantees this
    sep = str(node.func.value.value)
    arg = node.args[0]
    if isinstance(arg, ast.List | ast.Tuple):
        elts = _maybe_flatten_starred(arg.elts, symbol_table, scope)
        return _resolve_join_elements(elts, sep, symbol_table, scope)
    if isinstance(arg, ast.GeneratorExp | ast.ListComp):
        return _resolve_comprehension_join(
            arg,
            sep,
            symbol_table,
            scope,
            alias_map=alias_map,
            int_list_table=int_list_table,
            int_list_scope=int_list_scope,
        )
    if isinstance(arg, ast.Call):
        rev = _resolve_reversed_join(arg, sep, symbol_table, scope)
        if rev is not None:
            return rev
        return _resolve_map_join(
            arg,
            sep,
            alias_map or {},
            int_list_table=int_list_table,
            int_list_scope=int_list_scope,
        )
    return None
