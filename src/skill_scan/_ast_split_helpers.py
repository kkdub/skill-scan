"""AST split helpers -- str.format() / %-format / slice resolution.

Resolves ``'template'.format(a, b)``, ``'{x}'.format(x='val')``, and
``'%s%s' % (a, b)`` patterns. Also resolves slice expressions like
``s[2:6]`` and ``s[::-1]`` (string reversal). Gates on string-constant
receivers and LHS operands to avoid false positives.

AT LINE LIMIT: 297/300
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


# Matches {}, {0}, {1}, {name}, etc. (positional and keyword placeholders)
_FORMAT_PLACEHOLDER_RE = re.compile(r"\{(\w*)\}")

# Matches standard %-specifiers (negative lookbehind excludes escaped %% sequences)
_PERCENT_SPEC_RE = re.compile(r"(?<!%)%[sdfrxoegcai]")


def _resolve_format_keywords(
    keywords: list[ast.keyword], symbol_table: dict[str, str], scope: str
) -> dict[str, str] | None:
    """Resolve keyword args to a string dict. Returns None if any are unresolvable.

    Caller must ensure no **splat keywords are present (kw.arg is not None).
    """
    result: dict[str, str] = {}
    for kw in keywords:
        v = _resolve_single_expr(kw.value, symbol_table, scope)
        if v is None:
            return None
        assert kw.arg is not None  # guaranteed by _has_splat_kwarg pre-check
        result[kw.arg] = v
    return result


def _has_splat_kwarg(keywords: list[ast.keyword]) -> bool:
    """Return True if any keyword is a **kwargs splat (kw.arg is None)."""
    return any(kw.arg is None for kw in keywords)


def _resolve_format_call(
    node: ast.Call,
    symbol_table: dict[str, str],
    scope: str,
) -> str | None:
    """Resolve ``'t'.format(a)`` or ``'{x}'.format(x='v')`` to a string.

    Gates: func.attr=='format', receiver is str Constant, all args resolve,
    **kwargs (kw.arg is None) rejected.
    """
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "format":
        return None
    val = node.func.value
    if not isinstance(val, ast.Constant) or not isinstance(val.value, str):
        return None
    if _has_splat_kwarg(node.keywords):
        return None
    resolved_args = _resolve_expr_list(node.args, symbol_table, scope)
    if resolved_args is None:
        return None
    kwargs = _resolve_format_keywords(node.keywords, symbol_table, scope) if node.keywords else None
    if node.keywords and kwargs is None:
        return None
    return _substitute_format(val.value, resolved_args, kwargs=kwargs)


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
    """Resolve one expression to a string (Constant or via resolve_expr)."""
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return expr.value
    from skill_scan._ast_split_resolve import resolve_expr  # deferred: circular dep

    return resolve_expr(expr, symbol_table, scope)


def _resolve_subscript_expr(
    node: ast.Subscript,
    symbol_table: dict[str, str],
    scope: str,
) -> str | None:
    """Resolve ast.Subscript to string via composite key lookup or slice extraction."""
    if not isinstance(node.value, ast.Name):
        return None
    if isinstance(node.slice, ast.Slice):
        return _resolve_slice_expr(node.value.id, node.slice, symbol_table, scope)
    if not isinstance(node.slice, ast.Constant):
        return None
    sv = node.slice.value
    key = sv if isinstance(sv, str) else (str(sv) if isinstance(sv, int) and sv >= 0 else None)
    if key is None:
        return None
    return _scoped_lookup(f"{node.value.id}[{key}]", symbol_table, scope)


def _extract_slice_int(node: ast.expr | None) -> tuple[bool, int | None]:
    """Extract int from optional slice bound; handles -N via UnaryOp(USub).

    Returns (ok, value); ok=False rejects the slice. None means open-ended.
    """
    if node is None:
        return True, None
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return True, node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        if isinstance(node.operand, ast.Constant) and isinstance(node.operand.value, int):
            return True, -node.operand.value
    return False, None


def _resolve_slice_expr(
    var_name: str,
    slc: ast.Slice,
    symbol_table: dict[str, str],
    scope: str,
) -> str | None:
    """Resolve a string slice (e.g. s[2:6], s[::-1]) to the extracted substring.

    Variable must be tracked; bounds must be int Constants; step=0 rejected.
    """
    ok_step, step = _extract_slice_int(slc.step)
    if not ok_step or (step is not None and step == 0):
        return None
    ok_lo, start = _extract_slice_int(slc.lower)
    if not ok_lo:
        return None
    ok_hi, stop = _extract_slice_int(slc.upper)
    if not ok_hi:
        return None

    full_str = _scoped_lookup(var_name, symbol_table, scope)
    if full_str is None:
        return None
    return full_str[start:stop:step]


def _classify_placeholders(placeholders: list[re.Match[str]]) -> tuple[bool, bool, bool]:
    """Classify placeholder types: (has_auto, has_numeric, has_named)."""
    has_auto = has_numeric = has_named = False
    for m in placeholders:
        field = m.group(1)
        if field == "":
            has_auto = True
        elif field.isdigit():
            has_numeric = True
        else:
            has_named = True
    return has_auto, has_numeric, has_named


def _resolve_field(
    field: str, auto_idx: int, args: list[str], kwargs: dict[str, str] | None
) -> tuple[str | None, int]:
    """Resolve a single placeholder field. Returns (value, new_auto_idx)."""
    if field == "":
        if auto_idx >= len(args):
            return None, auto_idx
        return args[auto_idx], auto_idx + 1
    if field.isdigit():
        idx = int(field)
        return (args[idx] if idx < len(args) else None), auto_idx
    return (kwargs[field] if kwargs and field in kwargs else None), auto_idx


def _substitute_format(template: str, args: list[str], *, kwargs: dict[str, str] | None = None) -> str | None:
    """Substitute {}, {N}, and {name} placeholders with resolved args/kwargs."""
    placeholders = list(_FORMAT_PLACEHOLDER_RE.finditer(template))
    if not placeholders:
        return None
    has_auto, has_numeric, has_named = _classify_placeholders(placeholders)
    if (has_auto or has_numeric) and has_named:
        return None
    if has_auto and has_numeric:
        return None
    parts: list[str] = []
    last_end = 0
    auto_idx = 0
    for match in placeholders:
        parts.append(template[last_end : match.start()])
        val, auto_idx = _resolve_field(match.group(1), auto_idx, args, kwargs)
        if val is None:
            return None
        parts.append(val)
        last_end = match.end()
    parts.append(template[last_end:])
    return "".join(parts)


def _resolve_percent_format(
    node: ast.BinOp,
    symbol_table: dict[str, str],
    scope: str,
) -> str | None:
    """Resolve ``'%s%s' % (a, b)`` to a string.

    Gates: op is Mod, LHS is str Constant (not int), RHS is Tuple,
    placeholder count matches tuple length. Returns None if unresolvable.
    """
    if not isinstance(node.op, ast.Mod):
        return None
    if not isinstance(node.left, ast.Constant) or not isinstance(node.left.value, str):
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
    """Substitute %-specifier placeholders with values in order."""
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
from skill_scan._ast_split_map_helpers import (  # noqa: E402
    _resolve_map_join as _resolve_map_join,
)
