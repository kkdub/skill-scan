"""AST split bytes -- bytes-constructor resolution helpers.

Resolves bytearray(b'...').decode(), str(b'...', enc), and
codecs.decode(b'...', enc) patterns to decoded strings.
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
