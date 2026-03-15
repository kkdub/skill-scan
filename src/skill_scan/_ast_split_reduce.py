"""AST split reduce -- functools.reduce() and operator.add/concat detection.

Resolves functools.reduce(lambda a,b: a+b, [...]) and
functools.reduce(operator.add, [...]) / functools.reduce(operator.concat, [...])
patterns to concatenated strings.
"""

from __future__ import annotations

import ast

from skill_scan._ast_helpers import get_call_name


def _resolve_reduce_concat(
    node: ast.Call,
    symbol_table: dict[str, str],
    scope: str,
    *,
    alias_map: dict[str, str] | None = None,
) -> str | None:
    """Resolve functools.reduce() with string-concatenation combiner to a string.

    Detects two patterns:
    1. functools.reduce(lambda a, b: a + b, ['ev', 'al']) -> 'eval'
    2. functools.reduce(operator.add, ['ev', 'al']) -> 'eval'
       functools.reduce(operator.concat, ['ev', 'al']) -> 'eval'

    Uses alias_map to resolve functools/operator aliases (R-IMP008).
    """
    am = alias_map or {}
    call_name = get_call_name(node, am)
    if call_name not in ("functools.reduce", "reduce"):
        return None
    if len(node.args) < 2:
        return None
    combiner = node.args[0]
    iterable = node.args[1]
    if not _is_string_concat_combiner(combiner, am):
        return None
    result = _resolve_string_list(iterable)
    if result is None:
        return None
    # Account for optional initializer (3rd argument)
    if len(node.args) >= 3:
        init = node.args[2]
        if not (isinstance(init, ast.Constant) and isinstance(init.value, str)):
            return None
        result = init.value + result
    return result


def _is_string_concat_combiner(node: ast.expr, alias_map: dict[str, str]) -> bool:
    """Check if the combiner argument is a string-concatenation function.

    Accepts:
    - lambda a, b: a + b  (two-arg lambda with BinOp(Add) body)
    - operator.add / operator.concat (resolved via alias_map)
    """
    if isinstance(node, ast.Lambda):
        return _is_add_lambda(node)
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        canonical = alias_map.get(node.value.id, node.value.id)
        return canonical == "operator" and node.attr in ("add", "concat")
    # from operator import add as plus; reduce(plus, [...])
    if isinstance(node, ast.Name):
        canonical = alias_map.get(node.id, node.id)
        return canonical in ("operator.add", "operator.concat")
    return False


def _is_add_lambda(node: ast.Lambda) -> bool:
    """Check if a lambda is ``lambda a, b: a + b``."""
    args = node.args
    if len(args.args) != 2 or args.vararg or args.kwarg or args.defaults:
        return False
    body = node.body
    if not (isinstance(body, ast.BinOp) and isinstance(body.op, ast.Add)):
        return False
    left_name = args.args[0].arg
    right_name = args.args[1].arg
    return (
        isinstance(body.left, ast.Name)
        and body.left.id == left_name
        and isinstance(body.right, ast.Name)
        and body.right.id == right_name
    )


def _resolve_string_list(node: ast.expr) -> str | None:
    """Resolve a list/tuple of string constants to their concatenation."""
    if not isinstance(node, ast.List | ast.Tuple):
        return None
    parts: list[str] = []
    for elt in node.elts:
        if not (isinstance(elt, ast.Constant) and isinstance(elt.value, str)):
            return None
        parts.append(elt.value)
    if not parts:
        return None
    return "".join(parts)
