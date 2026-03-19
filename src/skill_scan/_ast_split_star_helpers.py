"""AST split star helpers -- flatten starred elements in join arguments.

Resolves ``''.join([*parts1, *parts2])`` by expanding starred names into
their tracked string-list elements from the symbol table.

Public surface
--------------
``_flatten_starred_list(elts, symbol_table, scope)``
    Replace ``ast.Starred`` elements with synthetic ``ast.Constant`` nodes
    for tracked string-list variables. Non-starred elements pass through.
    Returns None if any starred variable cannot be resolved.
"""

from __future__ import annotations

import ast

from skill_scan._ast_split_helpers import _scoped_lookup


def _flatten_starred_list(
    elts: list[ast.expr],
    symbol_table: dict[str, str],
    scope: str,
) -> list[ast.expr] | None:
    """Flatten starred elements in a list/tuple by expanding tracked string-lists.

    For each element:
    - Non-Starred: pass through unchanged.
    - Starred(Name): look up 'name.__len__' and 'name[0]', 'name[1]', ...
      in symbol_table. Replace with synthetic ast.Constant nodes.
      Returns None if the starred variable is not tracked.
    """
    result: list[ast.expr] = []
    for elt in elts:
        if not isinstance(elt, ast.Starred):
            result.append(elt)
            continue
        expanded = _expand_starred(elt, symbol_table, scope)
        if expanded is None:
            return None
        result.extend(expanded)
    return result


def _expand_starred(
    node: ast.Starred,
    symbol_table: dict[str, str],
    scope: str,
) -> list[ast.expr] | None:
    """Expand a single Starred node into its tracked string-list elements.

    Returns None if the starred value is not a Name or is not tracked.
    """
    if not isinstance(node.value, ast.Name):
        return None
    name = node.value.id
    len_str = _scoped_lookup(f"{name}.__len__", symbol_table, scope)
    if len_str is None:
        return None
    try:
        length = int(len_str)
    except ValueError:
        return None
    expanded: list[ast.expr] = []
    for i in range(length):
        val = _scoped_lookup(f"{name}[{i}]", symbol_table, scope)
        if val is None:
            return None
        expanded.append(ast.Constant(value=val))
    return expanded


def _maybe_flatten_starred(elts: list[ast.expr], symbol_table: dict[str, str], scope: str) -> list[ast.expr]:
    """Flatten starred elements if any, otherwise return original list."""
    if not any(isinstance(e, ast.Starred) for e in elts):
        return elts
    flat = _flatten_starred_list(elts, symbol_table, scope)
    return flat if flat is not None else elts
