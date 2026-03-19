"""AST split bytes -- bytes-constructor resolution helpers.

Resolves bytearray(b'...').decode(), str(b'...', enc),
codecs.decode(b'...', enc), and bytes.fromhex() concatenation
patterns to decoded strings.
"""

from __future__ import annotations

import ast


def resolve_bytes_constructor(
    node: ast.Call,
    alias_map: dict[str, str] | None = None,
) -> str | None:
    """Resolve bytes-constructor patterns (bytearray/str/codecs) to a decoded string."""
    result = _resolve_bytearray_decode(node)
    if result is not None:
        return result
    result = _resolve_str_bytes(node)
    if result is not None:
        return result
    return _resolve_codecs_decode(node, alias_map or {})


def _get_decode_encoding(node: ast.Call) -> str | None:
    """Extract encoding from .decode() args (default utf-8 or literal string arg)."""
    if node.keywords or len(node.args) > 1:
        return None
    if not node.args:
        return "utf-8"
    enc = node.args[0]
    if isinstance(enc, ast.Constant) and isinstance(enc.value, str):
        return enc.value
    return None


def _extract_bytearray_bytes(node: ast.expr) -> bytes | None:
    """Extract bytes literal from a bytearray(b'...') call, or None."""
    if not isinstance(node, ast.Call):
        return None
    if not (isinstance(node.func, ast.Name) and node.func.id == "bytearray"):
        return None
    if len(node.args) != 1 or node.keywords:
        return None
    arg = node.args[0]
    if isinstance(arg, ast.Constant) and isinstance(arg.value, bytes):
        return arg.value
    return None


def _resolve_bytearray_decode(node: ast.Call) -> str | None:
    """Resolve bytearray(b'...').decode([encoding]) to a string."""
    func = node.func
    if not (isinstance(func, ast.Attribute) and func.attr == "decode"):
        return None
    encoding = _get_decode_encoding(node)
    if encoding is None:
        return None
    raw = _extract_bytearray_bytes(func.value)
    if raw is None:
        return None
    try:
        return raw.decode(encoding, errors="replace")
    except (LookupError, ValueError):
        return None


def _decode_bytes_encoding_args(node: ast.Call) -> str | None:
    """Extract and decode (bytes_literal, encoding_str) from a two-arg Call."""
    if len(node.args) != 2 or node.keywords:
        return None
    bytes_arg, enc_arg = node.args
    if not (isinstance(bytes_arg, ast.Constant) and isinstance(bytes_arg.value, bytes)):
        return None
    if not (isinstance(enc_arg, ast.Constant) and isinstance(enc_arg.value, str)):
        return None
    try:
        return bytes_arg.value.decode(enc_arg.value, errors="replace")
    except (LookupError, ValueError):
        return None


def _resolve_str_bytes(node: ast.Call) -> str | None:
    """Resolve str(b'...', 'utf-8') to a string."""
    if not (isinstance(node.func, ast.Name) and node.func.id == "str"):
        return None
    return _decode_bytes_encoding_args(node)


def _resolve_codecs_decode(node: ast.Call, alias_map: dict[str, str]) -> str | None:
    """Resolve codecs.decode(b'...', 'utf-8') with alias support."""
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr != "decode":
        return None
    if not isinstance(func.value, ast.Name):
        return None
    canonical = alias_map.get(func.value.id, func.value.id)
    if canonical != "codecs":
        return None
    return _decode_bytes_encoding_args(node)


# -- bytes.fromhex() resolution -----------------------------------------------


def _resolve_fromhex(node: ast.Call) -> bytes | None:
    """Resolve ``bytes.fromhex('hex_str')`` to bytes, or None."""
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr != "fromhex":
        return None
    if not isinstance(func.value, ast.Name) or func.value.id != "bytes":
        return None
    if len(node.args) != 1 or node.keywords:
        return None
    arg = node.args[0]
    if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
        return None
    try:
        return bytes.fromhex(arg.value)
    except ValueError:
        return None


def _resolve_fromhex_operand(
    node: ast.expr,
    bytes_table: dict[str, bytes] | None,
) -> bytes | None:
    """Resolve a single operand of a fromhex BinOp to bytes.

    Handles: direct ``bytes.fromhex()`` Call, Name lookup in *bytes_table*.
    Does NOT handle nested BinOp (caller recurses for left side only).
    """
    if isinstance(node, ast.Call):
        return _resolve_fromhex(node)
    if isinstance(node, ast.Name) and bytes_table:
        return bytes_table.get(node.id)
    return None


def _resolve_fromhex_binop(
    node: ast.expr,
    bytes_table: dict[str, bytes] | None = None,
) -> bytes | None:
    """Resolve ``bytes.fromhex('XX') + bytes.fromhex('YY')`` to concatenated bytes.

    When *bytes_table* is provided, ``ast.Name`` nodes are resolved via it,
    enabling detection of patterns like ``part1 + part2`` where both were
    assigned from ``bytes.fromhex()`` calls.
    """
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Add):
        return None
    left = (
        _resolve_fromhex_binop(node.left, bytes_table)
        if isinstance(node.left, ast.BinOp)
        else _resolve_fromhex_operand(node.left, bytes_table)
    )
    if left is None:
        return None
    right = _resolve_fromhex_operand(node.right, bytes_table)
    if right is None:
        return None
    return left + right


def _build_bytes_table(tree: ast.Module) -> dict[str, bytes]:
    """Pre-pass: collect ``name = bytes.fromhex('hex')`` module-level assignments."""
    result: dict[str, bytes] = {}
    for stmt in tree.body:
        if not isinstance(stmt, ast.Assign):
            continue
        raw = _resolve_fromhex(stmt.value) if isinstance(stmt.value, ast.Call) else None
        if raw is None:
            continue
        for target in stmt.targets:
            if isinstance(target, ast.Name):
                result[target.id] = raw
    return result


def _resolve_raw_bytes(
    inner: ast.expr,
    bytes_table: dict[str, bytes] | None,
) -> bytes | None:
    """Resolve inner expression of ``.decode()`` to bytes."""
    if isinstance(inner, ast.BinOp):
        return _resolve_fromhex_binop(inner, bytes_table)
    if isinstance(inner, ast.Call):
        return _resolve_fromhex(inner)
    if isinstance(inner, ast.Name) and bytes_table:
        return bytes_table.get(inner.id)
    return None


def resolve_fromhex_concat(
    node: ast.expr,
    bytes_table: dict[str, bytes] | None = None,
) -> str | None:
    """Resolve ``(bytes.fromhex('XX') + bytes.fromhex('YY')).decode()`` to a string.

    Also handles single ``bytes.fromhex('XX').decode()`` without concatenation.
    When *bytes_table* is provided, named variables that were assigned from
    ``bytes.fromhex()`` calls are resolved too.
    """
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    if not (isinstance(func, ast.Attribute) and func.attr == "decode"):
        return None
    encoding = _get_decode_encoding(node)
    if encoding is None:
        return None
    raw = _resolve_raw_bytes(func.value, bytes_table)
    if raw is None:
        return None
    try:
        return raw.decode(encoding, errors="replace")
    except (LookupError, ValueError):
        return None
