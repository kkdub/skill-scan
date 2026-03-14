"""AST split helpers -- str.format() and %-format resolution.

Resolves ``'template'.format(a, b)`` and ``'%s%s' % (a, b)`` patterns.
Gates on string-constant receivers/LHS to avoid false positives.
"""

from __future__ import annotations

import ast
import re


def _scoped_lookup(name: str, symbol_table: dict[str, str], scope: str) -> str | None:
    """Look up name in symbol table, trying function scope first."""
    if scope:
        val = symbol_table.get(f"{scope}.{name}")
        if val is not None:
            return val
    return symbol_table.get(name)


# Matches {} or {0}, {1}, etc. (simple positional placeholders only)
_FORMAT_PLACEHOLDER_RE = re.compile(r"\{(\d*)\}")

# Matches standard %-specifiers (negative lookbehind excludes escaped %% sequences)
_PERCENT_SPEC_RE = re.compile(r"(?<!%)%[sdfrxoegcai]")


def _resolve_format_call(
    node: ast.Call,
    symbol_table: dict[str, str],
    scope: str,
) -> str | None:
    """Resolve ``'template'.format(a, b)`` to a string.

    Gates on:
    - func is an Attribute with attr == 'format'
    - receiver (func.value) is a string Constant
    - all positional args resolve via symbol table

    Returns the formatted string, or None if unresolvable.
    """
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "format":
        return None
    if not isinstance(node.func.value, ast.Constant):
        return None
    if not isinstance(node.func.value.value, str):
        return None
    if node.keywords:
        return None  # keyword args not supported

    template = node.func.value.value
    resolved_args = _resolve_expr_list(node.args, symbol_table, scope)
    if resolved_args is None:
        return None

    return _substitute_format(template, resolved_args)


def _resolve_expr_list(
    exprs: list[ast.expr],
    symbol_table: dict[str, str],
    scope: str,
) -> list[str] | None:
    """Resolve a list of AST expressions to strings via symbol table or constants."""
    result: list[str] = []
    for expr in exprs:
        val = _resolve_single_expr(expr, symbol_table, scope)
        if val is None:
            return None
        result.append(val)
    return result


def _resolve_single_expr(expr: ast.expr, symbol_table: dict[str, str], scope: str) -> str | None:
    """Resolve one expression node to a string value.

    Handles ast.Constant(str) directly; delegates Name, Attribute,
    Subscript, and Call to resolve_expr() (deferred import to avoid
    circular dependency since _ast_split_resolve imports from us).
    """
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return expr.value
    # resolve_expr handles Name, Attribute, Subscript, and Call
    from skill_scan._ast_split_resolve import resolve_expr

    return resolve_expr(expr, symbol_table, scope)


def _resolve_subscript_key(slice_val: object) -> str | None:
    """Convert subscript slice (str key or non-negative int) to composite key suffix."""
    if isinstance(slice_val, str):
        return slice_val
    if isinstance(slice_val, int) and slice_val >= 0:
        return str(slice_val)
    return None


def _resolve_subscript_expr(
    node: ast.Subscript,
    symbol_table: dict[str, str],
    scope: str,
) -> str | None:
    """Resolve ast.Subscript to string via composite key lookup."""
    if not isinstance(node.value, ast.Name):
        return None
    if not isinstance(node.slice, ast.Constant):
        return None
    key = _resolve_subscript_key(node.slice.value)
    if key is None:
        return None
    return _scoped_lookup(f"{node.value.id}[{key}]", symbol_table, scope)


def _substitute_format(template: str, args: list[str]) -> str | None:
    """Substitute {} and {N} placeholders with resolved args.

    Auto-numbering ({} {} {}) uses sequential indices.
    Explicit numbering ({0} {1}) uses the specified index.
    Mixed numbering is rejected (returns None).
    """
    placeholders = list(_FORMAT_PLACEHOLDER_RE.finditer(template))
    if not placeholders:
        return None  # no placeholders to substitute

    has_auto = any(m.group(1) == "" for m in placeholders)
    has_explicit = any(m.group(1) != "" for m in placeholders)
    if has_auto and has_explicit:
        return None  # mixed numbering not supported

    parts: list[str] = []
    last_end = 0
    auto_idx = 0

    for match in placeholders:
        parts.append(template[last_end : match.start()])
        if match.group(1) == "":
            idx = auto_idx
            auto_idx += 1
        else:
            idx = int(match.group(1))
        if idx >= len(args):
            return None  # index out of range
        parts.append(args[idx])
        last_end = match.end()

    parts.append(template[last_end:])
    return "".join(parts)


def _resolve_percent_format(
    node: ast.BinOp,
    symbol_table: dict[str, str],
    scope: str,
) -> str | None:
    """Resolve ``'%s%s' % (a, b)`` to a string.

    Gates on:
    - op is Mod
    - LHS (left) is a string Constant (not integer -- avoids ``10 % 3``)
    - RHS (right) is a Tuple with resolvable elements
    - number of %s placeholders matches tuple length

    Returns the formatted string, or None if unresolvable.
    """
    if not isinstance(node.op, ast.Mod):
        return None
    if not isinstance(node.left, ast.Constant):
        return None
    if not isinstance(node.left.value, str):
        return None

    template = node.left.value
    percent_placeholders = _PERCENT_SPEC_RE.findall(template)
    if not percent_placeholders:
        return None

    # RHS must be a tuple for multi-arg %-formatting
    if not isinstance(node.right, ast.Tuple):
        # Single %s with a single Name/Constant RHS
        if len(percent_placeholders) == 1:
            return _resolve_single_percent(template, node.right, symbol_table, scope)
        return None

    elements = _resolve_expr_list(node.right.elts, symbol_table, scope)
    if elements is None:
        return None

    if len(percent_placeholders) != len(elements):
        return None

    return _substitute_percent(template, elements)


def _resolve_single_percent(
    template: str,
    rhs: ast.expr,
    symbol_table: dict[str, str],
    scope: str,
) -> str | None:
    """Resolve single-arg %-format: ``'%s' % varname``."""
    val = _resolve_single_expr(rhs, symbol_table, scope)
    if val is None:
        return None
    return _PERCENT_SPEC_RE.sub(lambda _: val, template, count=1)


def _substitute_percent(template: str, values: list[str]) -> str | None:
    """Substitute %-specifier placeholders with values in order.

    Returns None when len(values) > placeholder count (over-provisioning defense).
    Uses manual match iteration to avoid re.sub backslash interpretation.
    """
    placeholders = list(_PERCENT_SPEC_RE.finditer(template))
    if len(values) > len(placeholders):
        return None  # over-provisioned: more args than placeholders

    parts: list[str] = []
    last_end = 0
    for i, match in enumerate(placeholders):
        parts.append(template[last_end : match.start()])
        parts.append(values[i] if i < len(values) else match.group())
        last_end = match.end()
    parts.append(template[last_end:])
    return "".join(parts)


def _resolve_join_elements(
    elts: list[ast.expr],
    sep: str,
    symbol_table: dict[str, str],
    scope: str,
) -> str | None:
    """Resolve list/tuple elements to a joined string using the symbol table."""
    parts = _resolve_expr_list(elts, symbol_table, scope)
    if parts is None:
        return None
    return sep.join(parts)


# re-exports at BOTTOM -- backward-compat (Facade Re-export Pattern)
from skill_scan._ast_split_join_helpers import (  # noqa: E402
    _resolve_generator_join as _resolve_generator_join,
    _resolve_map_join as _resolve_map_join,
)
