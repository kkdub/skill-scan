"""Format-map resolver for split-evasion detection.

Extracted from _ast_split_resolve.py (PLAN-033 Part A).
Resolves ``'template'.format_map(dict_expr)`` via inline dict literals or
tracked dict variables (composite ``var[key]`` entries in the symbol table).
"""

from __future__ import annotations

import ast

from skill_scan._ast_split_format import _scoped_lookup, _substitute_format


def _resolve_format_map_call(
    node: ast.Call,
    symbol_table: dict[str, str],
    scope: str,
) -> str | None:
    """Resolve ``'t'.format_map(d)`` or ``var.format_map(d)`` to a string.

    Handles inline dict literals and tracked dict variables (via symbol table
    composite keys ``var[key]``). Receiver can be a string constant or a
    tracked variable.
    """
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "format_map":
        return None
    if len(node.args) != 1 or node.keywords:
        return None
    # Resolve template (string constant or tracked variable)
    recv = node.func.value
    template: str | None = None
    if isinstance(recv, ast.Constant) and isinstance(recv.value, str):
        template = recv.value
    elif isinstance(recv, ast.Name):
        template = _scoped_lookup(recv.id, symbol_table, scope)
    if template is None:
        return None
    # Resolve the dict arg
    mapping = _resolve_dict_arg(node.args[0], symbol_table, scope)
    if mapping is None:
        return None
    # Substitute {name} placeholders
    return _substitute_format(template, [], kwargs=mapping)


def _resolve_dict_arg(node: ast.expr, symbol_table: dict[str, str], scope: str) -> dict[str, str] | None:
    """Resolve a dict expression to a {str: str} mapping.

    Handles inline ast.Dict with string keys/values and tracked dict variables
    (Name lookup via symbol table composite keys ``var[key]``).
    """
    if isinstance(node, ast.Dict):
        result: dict[str, str] = {}
        for k, v in zip(node.keys, node.values, strict=False):
            if k is None:
                return None  # **spread -- bail
            if not isinstance(k, ast.Constant) or not isinstance(k.value, str):
                return None
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                result[k.value] = v.value
            else:
                return None
        return result
    if isinstance(node, ast.Name):
        return _lookup_str_dict(node.id, symbol_table, scope)
    return None


def _lookup_str_dict(var_name: str, symbol_table: dict[str, str], scope: str) -> dict[str, str] | None:
    """Reconstruct a {str: str} dict from composite keys in symbol table.

    Mirrors ``_scoped_lookup`` semantics: if any scoped entries exist, build
    the mapping exclusively from those; otherwise fall back to unscoped keys.
    This prevents module-level dict entries from leaking into function-scope
    lookups when both exist.
    """
    prefix = f"{var_name}["
    scoped_prefix = f"{scope}.{var_name}[" if scope else None
    scoped_result: dict[str, str] = {}
    unscoped_result: dict[str, str] = {}
    for key, val in symbol_table.items():
        if scoped_prefix and key.startswith(scoped_prefix) and key.endswith("]"):
            dict_key = key[len(scoped_prefix) : -1]
            scoped_result[dict_key] = val
        elif key.startswith(prefix) and key.endswith("]"):
            dict_key = key[len(prefix) : -1]
            unscoped_result[dict_key] = val
    result = scoped_result if scoped_result else unscoped_result
    return result if result else None
