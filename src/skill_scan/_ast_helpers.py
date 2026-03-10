"""AST helper utilities — string resolution and node inspection.

Pure functions for extracting call names and resolving string values
from AST nodes. Used by ast_analyzer.py for evasion detection.

Resolution pipeline:
  try_resolve_string  (top-level dispatcher)
    -> _resolve_binop_add  (string concatenation)
    -> _resolve_chr_call   (chr(N) or chr(arithmetic))
    -> _resolve_join_call  (join with list/listcomp/map)
    -> _resolve_bytes_decode  (b'literal'.decode())
"""

from __future__ import annotations

import ast

MAX_AST_RESOLVE_DEPTH = 50


def get_call_name(node: ast.Call) -> str:
    """Extract the dotted name of a call (e.g. 'os.system', 'eval')."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return f"{func.value.id}.{func.attr}"
    return ""


def is_subprocess_shell_true(node: ast.Call, name: str) -> bool:
    """Check if a subprocess call has shell=True."""
    if not name.startswith("subprocess."):
        return False
    for kw in node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


_SAFE_LOADER_NAMES = frozenset({"SafeLoader", "CSafeLoader"})


def has_safe_loader(node: ast.Call) -> bool:
    """Check if yaml.load() uses SafeLoader/CSafeLoader (keyword or 2nd positional arg)."""
    # Check keyword arg: Loader=SafeLoader or Loader=yaml.SafeLoader
    for kw in node.keywords:
        if kw.arg == "Loader" and _is_safe_loader_node(kw.value):
            return True

    # Check 2nd positional arg: yaml.load(data, SafeLoader)
    if len(node.args) >= 2 and _is_safe_loader_node(node.args[1]):
        return True

    return False


def _is_safe_loader_node(node: ast.expr) -> bool:
    """Check if a node refers to SafeLoader or CSafeLoader."""
    if isinstance(node, ast.Name) and node.id in _SAFE_LOADER_NAMES:
        return True
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "yaml"
        and node.attr in _SAFE_LOADER_NAMES
    ):
        return True
    return False


def try_resolve_string(node: ast.AST, *, _depth: int = 0) -> str | None:
    """Try to statically resolve a node to a string value.

    Supports: string constants, BinOp Add on strings, ''.join([...]),
    chr(N), chr(arithmetic), list comprehension [chr(c) for c in [...]],
    map(chr, [...]), and b'literal'.decode(). Returns None for anything
    that cannot be resolved statically (f-strings, variables, etc.).
    """
    if _depth > MAX_AST_RESOLVE_DEPTH:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return None  # f-string — cannot resolve statically
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
    left = try_resolve_string(node.left, _depth=_depth + 1)
    right = try_resolve_string(node.right, _depth=_depth + 1)
    if left is not None and right is not None:
        return left + right
    return None


def _resolve_int_expr(node: ast.expr, *, _depth: int = 0) -> int | None:
    """Resolve an integer constant or simple arithmetic (add/sub/mul) on int constants.

    Recursively evaluates BinOp trees containing only integer constants
    and the operators +, -, *. Returns None for anything else.
    """
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
        resolved = try_resolve_string(elt, _depth=_depth + 1)
        if resolved is None:
            return None
        parts.append(resolved)
    return sep.join(parts)


def _resolve_int_list_to_chars(elts: list[ast.expr], sep: str) -> str | None:
    """Resolve a list of int expressions to chr() characters, joined by sep."""
    parts: list[str] = []
    for item in elts:
        val = _resolve_int_expr(item)
        if val is None or not (0 <= val <= 0x10FFFF):
            return None
        parts.append(chr(val))
    return sep.join(parts)


def _is_chr_of_target(elt: ast.expr, target_name: str) -> bool:
    """Check if node is chr(target_name) — a chr() call on the loop variable."""
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
