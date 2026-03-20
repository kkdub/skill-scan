"""AST split map helpers -- map(chr/str, [...]) resolution for join patterns.

Resolves ``map(chr, [ints])``, ``map(lambda c: chr(c), [ints])``,
``map(str, [strs])``, and tracked int-list variables inside map() calls
that appear as join arguments in the split-evasion detector.
"""

from __future__ import annotations

import ast


def _resolve_call_fn_name(func: ast.expr, alias_map: dict[str, str]) -> str | None:
    """Resolve a call's function name via alias map (Name or Attribute)."""
    if isinstance(func, ast.Name):
        return alias_map.get(func.id, func.id)
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        base = alias_map.get(func.value.id, func.value.id)
        return f"{base}.{func.attr}"
    return None


def _is_lambda_chr(node: ast.Lambda) -> bool:
    """Check if lambda is ``lambda <x>: chr(<x>)`` -- single arg, body is chr(arg).

    Validates the lambda has exactly one positional parameter (no vararg,
    no keyword-only args), and the body is a ``chr()`` call whose sole
    argument is the lambda's parameter name.
    """
    args = node.args
    if len(args.args) != 1 or args.vararg or args.kwonlyargs:
        return False
    param_name = args.args[0].arg
    body = node.body
    if not isinstance(body, ast.Call) or len(body.args) != 1 or body.keywords:
        return False
    fn = body.func
    if not (isinstance(fn, ast.Name) and fn.id == "chr"):
        return False
    arg = body.args[0]
    return isinstance(arg, ast.Name) and arg.id == param_name


def _resolve_map_join(
    call: ast.Call,
    sep: str,
    alias_map: dict[str, str],
    *,
    int_list_table: dict[str, list[int]] | None = None,
    int_list_scope: str = "",
) -> str | None:
    """Resolve map(chr/str/lambda, iterable) inside join to a string.

    Handles three map function patterns:
    - ``map(chr, [101, 118, ...])`` -- Name reference to chr/str
    - ``map(lambda c: chr(c), [101, ...])`` -- lambda wrapping chr
    - ``map(str, ['ev', 'al'])`` -- Name reference to str

    The iterable can be a literal list/tuple or a tracked int-list variable
    name resolved via ``int_list_table``.
    """
    from skill_scan._ast_imports import get_call_name

    if get_call_name(call, alias_map) != "map" or len(call.args) != 2:
        return None
    fn_name = _effective_map_fn(call.args[0], alias_map)
    if fn_name is None:
        return None

    # Resolve iteration source: literal list/tuple or tracked int-list variable
    iter_arg = call.args[1]
    elts: list[ast.expr] | None = None
    if isinstance(iter_arg, ast.List | ast.Tuple):
        elts = iter_arg.elts
    elif isinstance(iter_arg, ast.Name) and fn_name in ("chr", "builtins.chr"):
        elts = _resolve_tracked_elts(iter_arg.id, int_list_table, int_list_scope)
    if elts is None:
        return None

    if fn_name in ("chr", "builtins.chr"):
        return _resolve_map_chr(elts, sep)
    if fn_name == "str":
        return _resolve_map_str(elts, sep)
    return None


def _effective_map_fn(func_arg: ast.expr, alias_map: dict[str, str]) -> str | None:
    """Determine effective function name from map's first argument.

    Returns the canonical name for ast.Name references (resolved through
    alias_map), or ``'chr'`` for ``lambda c: chr(c)`` patterns.
    """
    if isinstance(func_arg, ast.Name):
        return alias_map.get(func_arg.id, func_arg.id)
    if isinstance(func_arg, ast.Lambda) and _is_lambda_chr(func_arg):
        return "chr"
    return None


def _resolve_tracked_elts(
    name: str,
    int_list_table: dict[str, list[int]] | None,
    scope: str,
) -> list[ast.expr] | None:
    """Look up a tracked int-list variable and synthesize AST constants."""
    if not int_list_table:
        return None
    from skill_scan._ast_split_int_list_tracker import _SHADOW

    key = f"{scope}.{name}" if scope else None
    int_list = int_list_table.get(key) if key else None
    if int_list is _SHADOW:
        return None
    if int_list is None:
        int_list = int_list_table.get(name)
    if int_list is _SHADOW or not int_list:
        return None
    return [ast.Constant(value=v) for v in int_list]


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
