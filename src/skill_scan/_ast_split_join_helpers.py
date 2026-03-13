"""AST split join helpers -- generator expression and map() resolution for join.

Resolves ``''.join(x for x in [...])`` and ``''.join(map(chr/str, [...]))``
patterns. Used by _ast_split_detector to detect dangerous names assembled
via join-based evasion.
"""

from __future__ import annotations

import ast

from skill_scan._ast_split_helpers import _resolve_expr_list


def _resolve_generator_join(
    gen: ast.GeneratorExp, sep: str, symbol_table: dict[str, str], scope: str
) -> str | None:
    """Resolve ``p for p in ['ev', 'al']`` inside join -- single-variable identity generators."""
    if len(gen.generators) != 1:
        return None
    comp = gen.generators[0]
    if comp.ifs or not isinstance(comp.target, ast.Name):
        return None
    if not isinstance(comp.iter, ast.List | ast.Tuple):
        return None
    # Only identity generators: ``x for x in [...]`` where elt == target
    if not (isinstance(gen.elt, ast.Name) and gen.elt.id == comp.target.id):
        return None
    parts = _resolve_expr_list(comp.iter.elts, symbol_table, scope)
    if parts is None:
        return None
    return sep.join(parts)


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
