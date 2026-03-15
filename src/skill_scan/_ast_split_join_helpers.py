"""AST split join helpers -- join resolution for the split detector.

Resolves ``''.join(x for x in [...])`` , ``''.join(map(chr/str, [...]))``,
``''.join(reversed(...))``, and general ``'sep'.join([...])`` patterns.
Used by _ast_split_detector to detect dangerous names assembled via
join-based evasion.
"""

from __future__ import annotations

import ast

from skill_scan._ast_split_helpers import (
    _resolve_expr_list,
    _resolve_join_elements,
    _scoped_lookup,
)


def _resolve_generator_join(
    gen: ast.GeneratorExp, sep: str, symbol_table: dict[str, str], scope: str
) -> str | None:
    """Resolve ``p for p in ['ev', 'al']`` or ``chr(c) for c in [ints]`` inside join."""
    return _resolve_comprehension_join(gen, sep, symbol_table, scope)


def _resolve_comprehension_join(
    node: ast.GeneratorExp | ast.ListComp, sep: str, symbol_table: dict[str, str], scope: str
) -> str | None:
    """Resolve generator or list comprehension inside join to a string.

    Handles both ``x for x in [...]`` identity patterns and
    ``chr(c) for c in [ints]`` chr-mapping patterns.
    """
    if len(node.generators) != 1:
        return None
    comp = node.generators[0]
    if comp.ifs or not isinstance(comp.target, ast.Name):
        return None
    if not isinstance(comp.iter, ast.List | ast.Tuple):
        return None
    # chr(x) comprehension: ``chr(c) for c in [101, 118, ...]``
    chr_result = _resolve_comprehension_chr(node.elt, comp.target.id, comp.iter.elts, sep)
    if chr_result is not None:
        return chr_result
    # Identity comprehension: ``x for x in [...]`` where elt == target
    if not (isinstance(node.elt, ast.Name) and node.elt.id == comp.target.id):
        return None
    parts = _resolve_expr_list(comp.iter.elts, symbol_table, scope)
    if parts is None:
        return None
    return sep.join(parts)


def _resolve_comprehension_chr(
    elt: ast.expr, target_id: str, iter_elts: list[ast.expr], sep: str
) -> str | None:
    """Resolve ``chr(x) for x in [int, ...]`` comprehension pattern."""
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
    fn_name = alias_map.get(func_arg.id, func_arg.id)
    iter_arg = call.args[1]
    if not isinstance(iter_arg, ast.List | ast.Tuple):
        return None
    if fn_name == "chr":
        return _resolve_map_chr(iter_arg.elts, sep)
    if fn_name == "str":
        return _resolve_map_str(iter_arg.elts, sep)
    return None


def _resolve_map_chr(elts: list[ast.expr], sep: str) -> str | None:
    """Convert list of int literals to characters, joined by sep."""
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
    if isinstance(arg, ast.GeneratorExp | ast.ListComp):
        return _resolve_comprehension_join(arg, sep, symbol_table, scope)
    if isinstance(arg, ast.Call):
        am = alias_map or {}
        rev = _resolve_reversed_join(arg, sep, symbol_table, scope)
        if rev is not None:
            return rev
        return _resolve_map_join(arg, sep, am)
    return None
