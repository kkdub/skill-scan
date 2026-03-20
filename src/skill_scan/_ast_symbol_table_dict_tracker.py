"""Dict/list/replace-chain tracking helpers for the symbol table builder.

Extracted from _ast_symbol_table_helpers.py for SIZE-001 compliance.
Handles dict literal composite keys, list/tuple element tracking,
dict.pop() resolution, and .replace() chain resolution.
"""

from __future__ import annotations

import ast

from skill_scan._ast_imports import try_resolve_string
from skill_scan._ast_symbol_table import _Ref


def _handle_dict_literal(
    var_name: str,
    dict_node: ast.Dict,
    table: dict[str, str | _Ref],
) -> None:
    """Handle dict literal: parts = {'a': 'ex', 'b': 'ec'} -> composite keys."""
    for k, v in zip(dict_node.keys, dict_node.values, strict=False):
        if k is None:
            continue  # **kwargs unpacking
        if not isinstance(k, ast.Constant) or not isinstance(k.value, str):
            continue
        resolved = try_resolve_string(v)
        if resolved is not None:
            table[f"{var_name}[{k.value}]"] = resolved


def _handle_string_list_literal(
    var_name: str,
    node: ast.List | ast.Tuple,
    table: dict[str, str | _Ref],
) -> None:
    """Handle list/tuple of all string constants: track name[i] and name.__len__."""
    elts = node.elts
    if not all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in elts):
        if len(elts) == 0:
            table[f"{var_name}.__len__"] = "0"
        return
    for i, e in enumerate(elts):
        assert isinstance(e, ast.Constant)  # guaranteed by all() check above
        table[f"{var_name}[{i}]"] = str(e.value)
    table[f"{var_name}.__len__"] = str(len(elts))


def _extract_dict_pop_parts(stmt: ast.Assign) -> tuple[str, str, str] | None:
    """Extract (target_name, dict_name, key) from name = d.pop('key'), or None."""
    if len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
        return None
    call = stmt.value
    if not isinstance(call, ast.Call):
        return None
    func = call.func
    if not isinstance(func, ast.Attribute) or func.attr != "pop":
        return None
    if not isinstance(func.value, ast.Name):
        return None
    if len(call.args) not in (1, 2) or not isinstance(call.args[0], ast.Constant):
        return None
    if not isinstance(call.args[0].value, str):
        return None
    return stmt.targets[0].id, func.value.id, call.args[0].value


def _handle_dict_pop(
    stmt: ast.Assign,
    table: dict[str, str | _Ref],
) -> bool:
    """Handle name = d.pop('key') by resolving via composite key lookup.

    Returns True if the pattern was matched (regardless of whether
    a value was resolved), False if the statement doesn't match.
    """
    parts = _extract_dict_pop_parts(stmt)
    if parts is None:
        return False
    target_name, dict_name, key = parts
    composite_key = f"{dict_name}[{key}]"
    val = table.get(composite_key)
    if isinstance(val, str):
        table[target_name] = val
    else:
        # Store as _Ref so _resolve_indirections can resolve from parent scope
        table[target_name] = _Ref(composite_key)
    return True


# -- .replace() chain resolution -------------------------------------------


def _is_replace_node(node: ast.expr) -> bool:
    """Check if node is a .replace(old, new) call with two string args."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "replace"
        and len(node.args) == 2
        and not node.keywords
    )


def _str_pair(call: ast.Call) -> tuple[str, str] | None:
    """Extract (old, new) string pair from .replace() args, or None."""
    a, b = call.args
    if (
        isinstance(a, ast.Constant)
        and isinstance(a.value, str)
        and isinstance(b, ast.Constant)
        and isinstance(b.value, str)
    ):
        return (a.value, b.value)
    return None


def _resolve_replace_base(node: ast.expr, table: dict[str, str | _Ref]) -> str | None:
    """Resolve the base of a .replace() chain to a string constant or tracked var."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        v = table.get(node.id)
        return v if isinstance(v, str) else None
    return None


def _resolve_replace_chain_simple(node: ast.expr, table: dict[str, str | _Ref]) -> str | None:
    """Resolve chained .replace(old, new) on a constant or tracked variable."""
    pairs: list[tuple[str, str]] = []
    cur: ast.expr = node
    for _ in range(20):
        if not _is_replace_node(cur):
            break
        assert isinstance(cur, ast.Call)
        pair = _str_pair(cur)
        if pair is None:
            return None
        pairs.append(pair)
        assert isinstance(cur.func, ast.Attribute)
        cur = cur.func.value
    if not pairs:
        return None
    base = _resolve_replace_base(cur, table)
    if base is None:
        return None
    for old_val, new_val in reversed(pairs):
        base = base.replace(old_val, new_val)
    return base
