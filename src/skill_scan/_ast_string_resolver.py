"""AST string resolution pipeline -- extracted from _ast_helpers.py.

Absorbs all functions from the former _ast_join_helpers.py.
"""

from __future__ import annotations

import ast
from collections.abc import Sequence

MAX_AST_RESOLVE_DEPTH = 50


def try_resolve_string(node: ast.AST) -> str | None:
    """Try to statically resolve a node to a string value.

    Supports: string constants, BinOp Add on strings, ''.join([...]),
    chr(N), chr(arithmetic), list comprehension [chr(c) for c in [...]],
    map(chr, [...]), and b'literal'.decode(). Returns None for anything
    that cannot be resolved statically (f-strings, variables, etc.).
    """
    return _try_resolve_string(node)


def _try_resolve_string(node: ast.AST, *, _depth: int = 0) -> str | None:
    if _depth > MAX_AST_RESOLVE_DEPTH:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return None  # f-string -- cannot resolve statically
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _resolve_binop_add(node, _depth=_depth)
    if isinstance(node, ast.Call):
        return (
            _resolve_chr_call(node, _depth=_depth)
            or _resolve_join_call(node, _depth=_depth)
            or _resolve_bytes_decode(node)
        )
    return None


def _resolve_binop_add(node: ast.BinOp, *, _depth: int = 0) -> str | None:
    """Resolve string concatenation: left + right."""
    left = _try_resolve_string(node.left, _depth=_depth + 1)
    right = _try_resolve_string(node.right, _depth=_depth + 1)
    if left is not None and right is not None:
        return left + right
    return None


def _resolve_int_expr(node: ast.expr, *, _depth: int = 0) -> int | None:
    """Resolve an integer constant or simple arithmetic (add/sub/mul) on int constants."""
    if _depth > MAX_AST_RESOLVE_DEPTH:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if not isinstance(node, ast.BinOp):
        return None
    left = _resolve_int_expr(node.left, _depth=_depth + 1)
    right = _resolve_int_expr(node.right, _depth=_depth + 1)
    if left is None or right is None:
        return None
    if isinstance(node.op, ast.Add):
        return left + right
    if isinstance(node.op, ast.Sub):
        return left - right
    if isinstance(node.op, ast.Mult):
        return left * right
    return None


def _resolve_chr_call(node: ast.Call, *, _depth: int = 0) -> str | None:
    """Resolve chr(N) or chr(arithmetic) to a single character."""
    if _get_call_name_from_any(node) != "chr":
        return None
    if len(node.args) != 1:
        return None
    val = _resolve_int_expr(node.args[0], _depth=_depth)
    if val is not None and 0 <= val <= 0x10FFFF:
        return chr(val)
    return None


def _resolve_join_call(node: ast.Call, *, _depth: int = 0) -> str | None:
    """Resolve ''.join([...]), ''.join(map(chr, [...])), and list comp variants."""
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "join":
        return None
    if not isinstance(node.func.value, ast.Constant) or not isinstance(node.func.value.value, str):
        return None
    if len(node.args) != 1:
        return None

    sep = node.func.value.value
    arg = node.args[0]

    # Direct list/tuple: ''.join(['a', 'b', 'c'])
    if isinstance(arg, ast.List | ast.Tuple):
        return _resolve_iterable_elements(arg.elts, sep, _depth=_depth)

    # List comprehension: ''.join([chr(c) for c in [101, 118, ...]])
    if isinstance(arg, ast.ListComp):
        return _resolve_join_listcomp(arg, sep)

    # map(chr, [...]): ''.join(map(chr, [101, 118, ...]))
    if isinstance(arg, ast.Call):
        return _resolve_join_map_chr(arg, sep)

    return None


def _resolve_iterable_elements(elts: list[ast.expr], sep: str, *, _depth: int = 0) -> str | None:
    """Resolve a list of AST elements to a joined string."""
    parts: list[str] = []
    for elt in elts:
        resolved = _try_resolve_string(elt, _depth=_depth + 1)
        if resolved is None:
            return None
        parts.append(resolved)
    return sep.join(parts)


def _resolve_bytes_decode(node: ast.Call) -> str | None:
    """Resolve b'literal'.decode() to a string."""
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "decode":
        return None
    obj = node.func.value
    if not isinstance(obj, ast.Constant) or not isinstance(obj.value, bytes):
        return None
    try:
        return obj.value.decode()
    except (UnicodeDecodeError, LookupError):
        return None


def _get_call_name_from_any(node: ast.Call) -> str:
    """Get call name -- works for both Name and Attribute nodes."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


# ---------------------------------------------------------------------------
# Absorbed from _ast_join_helpers.py
# ---------------------------------------------------------------------------


def _resolve_int_list_to_chars(elts: Sequence[ast.expr], sep: str) -> str | None:
    """Resolve a list of int expressions to chr() characters, joined by sep."""
    parts: list[str] = []
    for item in elts:
        val = _resolve_int_expr(item)
        if val is None or not (0 <= val <= 0x10FFFF):
            return None
        parts.append(chr(val))
    return sep.join(parts)


def _is_chr_of_target(elt: ast.expr, target_name: str) -> bool:
    """Check if node is chr(target_name) -- a chr() call on the loop variable."""
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
    if _get_call_name_from_any(call) != "map" or len(call.args) != 2:
        return None
    func_arg = call.args[0]
    if not isinstance(func_arg, ast.Name) or func_arg.id != "chr":
        return None
    iter_arg = call.args[1]
    if not isinstance(iter_arg, ast.List | ast.Tuple):
        return None
    return _resolve_int_list_to_chars(iter_arg.elts, sep)
