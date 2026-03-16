"""AST split join helpers -- join resolution for the split detector.

Resolves ``''.join(...)`` patterns (list/generator/map/reversed) and tracked
int-list variables used as comprehension iterables via ``_collect_int_list_assigns``.
"""

from __future__ import annotations

import ast

from skill_scan._ast_split_helpers import (
    _resolve_expr_list,
    _resolve_join_elements,
    _scoped_lookup,
)


def _collect_int_list_assigns(tree: ast.Module) -> dict[str, list[int]]:
    """Pre-pass: collect Name = [int, ...] assignments from all scopes."""
    result: dict[str, list[int]] = {}
    # Module-level assignments (no scope prefix)
    _collect_int_lists_from_body(tree.body, "", result)
    for node in tree.body:
        # Function-level assignments (scoped by function name)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            _collect_int_lists_from_body(node.body, node.name, result)
        # Class method assignments (scoped by class name)
        elif isinstance(node, ast.ClassDef):
            for stmt in node.body:
                if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
                    _collect_int_lists_from_body(stmt.body, node.name, result)
    return result


def _collect_int_lists_from_body(body: list[ast.stmt], scope: str, result: dict[str, list[int]]) -> None:
    """Collect integer-list assignments, recursing into control-flow blocks."""
    for stmt in body:
        # Track single-target assignments of all-int lists/tuples
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target = stmt.targets[0]
            if isinstance(target, ast.Name) and isinstance(stmt.value, ast.List | ast.Tuple):
                ints = _extract_int_list(stmt.value.elts)
                if ints is not None:
                    result[f"{scope}.{target.id}" if scope else target.id] = ints
        # Recurse into control-flow sub-bodies (if/for/while/with/try)
        for child_body in _sub_bodies(stmt):
            _collect_int_lists_from_body(child_body, scope, result)


def _sub_bodies(stmt: ast.stmt) -> list[list[ast.stmt]]:
    """Yield child body lists from control-flow nodes."""
    # Only recurse into known control-flow nodes, not function/class defs
    if not isinstance(stmt, ast.If | ast.For | ast.While | ast.AsyncFor | ast.With | ast.AsyncWith | ast.Try):
        return []
    # Collect body, orelse, finalbody attributes (varies by node type)
    bodies = [getattr(stmt, a) for a in ("body", "orelse", "finalbody") if hasattr(stmt, a)]
    # Try handlers have their own body lists
    for handler in getattr(stmt, "handlers", ()):
        bodies.append(handler.body)
    return bodies


def _extract_int_list(elts: list[ast.expr]) -> list[int] | None:
    """Extract a list of int constants, or None if any element is non-int."""
    # Strict all-or-nothing: one non-int element rejects the whole list
    values: list[int] = []
    for elt in elts:
        if not isinstance(elt, ast.Constant) or not isinstance(elt.value, int):
            return None
        values.append(elt.value)
    return values


def _resolve_generator_join(
    gen: ast.GeneratorExp,
    sep: str,
    symbol_table: dict[str, str],
    scope: str,
    *,
    int_list_table: dict[str, list[int]] | None = None,
) -> str | None:
    """Resolve ``p for p in ['ev', 'al']`` or ``chr(c) for c in [ints]`` inside join."""
    return _resolve_comprehension_join(gen, sep, symbol_table, scope, int_list_table=int_list_table)


def _resolve_comprehension_join(
    node: ast.GeneratorExp | ast.ListComp,
    sep: str,
    symbol_table: dict[str, str],
    scope: str,
    *,
    int_list_table: dict[str, list[int]] | None = None,
) -> str | None:
    """Resolve generator or list comprehension inside join to a string."""
    # Only handle simple single-generator comprehensions without filters
    if len(node.generators) != 1:
        return None
    comp = node.generators[0]
    if comp.ifs or not isinstance(comp.target, ast.Name):
        return None
    # Direct list/tuple iteration source
    if isinstance(comp.iter, ast.List | ast.Tuple):
        return _resolve_direct_iter(node.elt, comp.target.id, comp.iter.elts, sep, symbol_table, scope)
    # Tracked int-list variable as iteration source
    if isinstance(comp.iter, ast.Name) and int_list_table:
        return _resolve_tracked_iter(node.elt, comp.target.id, comp.iter.id, sep, int_list_table, scope)
    return None


def _resolve_direct_iter(
    elt: ast.expr,
    target_id: str,
    iter_elts: list[ast.expr],
    sep: str,
    symbol_table: dict[str, str],
    scope: str,
) -> str | None:
    """Resolve comprehension with direct List/Tuple iteration source."""
    # Try chr(x) pattern first: chr(c) for c in [101, 118, ...]
    chr_result = _resolve_comprehension_chr(elt, target_id, iter_elts, sep)
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
) -> str | None:
    """Resolve comprehension with tracked int-list variable as iteration source."""
    # Scoped lookup: try function.varname first, then fall back to global
    int_list = int_list_table.get(f"{scope}.{iter_name}") if scope else None
    if int_list is None:
        int_list = int_list_table.get(iter_name)
    if int_list is None:
        return None
    # Synthesize AST Constant nodes from the tracked int values
    synthetic: list[ast.expr] = [ast.Constant(value=v) for v in int_list]
    return _resolve_comprehension_chr(elt, target_id, synthetic, sep)


def _resolve_comprehension_chr(
    elt: ast.expr, target_id: str, iter_elts: list[ast.expr], sep: str
) -> str | None:
    """Resolve ``chr(x) for x in [int, ...]`` comprehension pattern."""
    # Verify the element is a chr() call with the loop variable as argument
    if not (
        isinstance(elt, ast.Call)
        and isinstance(elt.func, ast.Name)
        and elt.func.id == "chr"
        and len(elt.args) == 1
        and not elt.keywords
    ):
        return None
    arg = elt.args[0]
    if not (isinstance(arg, ast.Name) and arg.id == target_id):
        return None
    return _resolve_map_chr(iter_elts, sep)


def _resolve_map_join(
    call: ast.Call,
    sep: str,
    alias_map: dict[str, str],
) -> str | None:
    """Resolve ``map(chr, [ints])`` or ``map(str, [strs])`` inside join."""
    from skill_scan._ast_helpers import get_call_name

    if get_call_name(call, alias_map) != "map" or len(call.args) != 2:
        return None
    func_arg = call.args[0]
    if not isinstance(func_arg, ast.Name):
        return None
    # Resolve aliased function names (e.g., c = chr; map(c, ...))
    fn_name = alias_map.get(func_arg.id, func_arg.id)
    iter_arg = call.args[1]
    if not isinstance(iter_arg, ast.List | ast.Tuple):
        return None
    # Dispatch to chr or str resolver based on mapped function name
    if fn_name == "chr":
        return _resolve_map_chr(iter_arg.elts, sep)
    if fn_name == "str":
        return _resolve_map_str(iter_arg.elts, sep)
    return None


def _resolve_map_chr(elts: list[ast.expr], sep: str) -> str | None:
    """Convert list of int literals to characters, joined by sep."""
    # Each int must be a valid Unicode codepoint
    parts: list[str] = []
    for elt in elts:
        if not isinstance(elt, ast.Constant) or not isinstance(elt.value, int):
            return None
        if not (0 <= elt.value <= 0x10FFFF):
            return None
        parts.append(chr(elt.value))
    return sep.join(parts)


def _resolve_map_str(elts: list[ast.expr], sep: str) -> str | None:
    """Pass through list of string literals, joined by sep."""
    # Parallel to _resolve_map_chr but for str identity mapping
    parts: list[str] = []
    for elt in elts:
        if not isinstance(elt, ast.Constant) or not isinstance(elt.value, str):
            return None
        parts.append(elt.value)
    return sep.join(parts)


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
) -> str | None:
    """Resolve ''.join(...) with list/tuple, generator, reversed, or map(chr/str) arguments."""
    if not _is_str_join_call(node):
        return None
    # Type narrowing: _is_str_join_call guarantees Attribute with Constant value
    assert isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Constant)
    sep = str(node.func.value.value)
    arg = node.args[0]
    # Direct list/tuple: ''.join(['e', 'v', 'a', 'l'])
    if isinstance(arg, ast.List | ast.Tuple):
        return _resolve_join_elements(arg.elts, sep, symbol_table, scope)
    # Generator/listcomp: ''.join(chr(c) for c in [ints])
    if isinstance(arg, ast.GeneratorExp | ast.ListComp):
        return _resolve_comprehension_join(arg, sep, symbol_table, scope, int_list_table=int_list_table)
    # Call: reversed() or map(chr/str, [...])
    if isinstance(arg, ast.Call):
        rev = _resolve_reversed_join(arg, sep, symbol_table, scope)
        if rev is not None:
            return rev
        return _resolve_map_join(arg, sep, alias_map or {})
    return None
