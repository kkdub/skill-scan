"""AST join-resolution helpers — extracted from _ast_helpers.py.

Pure functions for resolving join/listcomp/map(chr, ...) patterns
in AST nodes. Used by _ast_helpers._resolve_join_call().
"""

from __future__ import annotations

import ast
from collections.abc import Sequence


def _resolve_int_list_to_chars(elts: Sequence[ast.expr], sep: str) -> str | None:
    """Resolve a list of int expressions to chr() characters, joined by sep."""
    from skill_scan._ast_helpers import _resolve_int_expr

    parts: list[str] = []
    for item in elts:
        val = _resolve_int_expr(item)
        if val is None or not (0 <= val <= 0x10FFFF):
            return None
        parts.append(chr(val))
    return sep.join(parts)


def _is_chr_of_target(elt: ast.expr, target_name: str) -> bool:
    """Check if node is chr(target_name) -- a chr() call on the loop variable."""
    from skill_scan._ast_helpers import _get_call_name_from_any

    if not isinstance(elt, ast.Call) or _get_call_name_from_any(elt) != "chr":
        return False
    return len(elt.args) == 1 and isinstance(elt.args[0], ast.Name) and elt.args[0].id == target_name


def _resolve_join_listcomp(comp: ast.ListComp, sep: str) -> str | None:
    """Resolve [chr(c) for c in [101, 118, ...]] inside join."""
    if len(comp.generators) != 1:
        return None
    gen = comp.generators[0]
    if gen.ifs or not isinstance(gen.iter, ast.List | ast.Tuple):
        return None
    if not isinstance(gen.target, ast.Name):
        return None
    if not _is_chr_of_target(comp.elt, gen.target.id):
        return None
    return _resolve_int_list_to_chars(gen.iter.elts, sep)


def _resolve_join_map_chr(call: ast.Call, sep: str) -> str | None:
    """Resolve map(chr, [101, 118, ...]) inside join."""
    from skill_scan._ast_helpers import _get_call_name_from_any

    if _get_call_name_from_any(call) != "map" or len(call.args) != 2:
        return None
    func_arg = call.args[0]
    if not isinstance(func_arg, ast.Name) or func_arg.id != "chr":
        return None
    iter_arg = call.args[1]
    if not isinstance(iter_arg, ast.List | ast.Tuple):
        return None
    return _resolve_int_list_to_chars(iter_arg.elts, sep)
