"""AST helper utilities -- import analysis and node inspection.

String resolution re-exported from _ast_string_resolver.py for backward compat.
"""

from __future__ import annotations

import ast


def build_alias_map(tree: ast.Module) -> dict[str, str]:
    """Build alias -> canonical module name mapping from Import/ImportFrom nodes.

    Walks module-level statements and recurses into ast.Try blocks for:
      - ``import codecs as c``  -> {'c': 'codecs'}
      - ``import os``           -> {'os': 'os'}
      - ``from os import path`` -> {'path': 'os.path'}
      - ``from os import path as p`` -> {'p': 'os.path'}
    """
    alias_map: dict[str, str] = {}
    _collect_imports(tree.body, alias_map)
    return alias_map


def _collect_imports(body: list[ast.stmt], alias_map: dict[str, str]) -> None:
    """Collect Import/ImportFrom from a body list, recursing into ast.Try blocks."""
    for node in body:
        if isinstance(node, ast.Import):
            _record_import(node, alias_map)
        elif isinstance(node, ast.ImportFrom) and node.module:
            _record_import_from(node, alias_map)
        elif isinstance(node, ast.Try):
            for sub_body in _try_bodies(node):
                _collect_imports(sub_body, alias_map)


def _record_import(node: ast.Import, alias_map: dict[str, str]) -> None:
    """Record aliases from an ``import`` statement."""
    for alias in node.names:
        alias_map[alias.asname or alias.name] = alias.name


_STAR_IMPORT_EXPANSIONS: dict[str, list[str]] = {
    "os": [
        "system",
        "popen",
        "execl",
        "execle",
        "execlp",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
    ],
    "subprocess": ["run", "call", "check_output", "check_call", "Popen"],
    "shutil": ["rmtree", "move", "copy", "copy2"],
    "socket": ["getaddrinfo", "gethostbyname", "create_connection"],
}


def _record_import_from(node: ast.ImportFrom, alias_map: dict[str, str]) -> None:
    """Record aliases from a ``from ... import`` statement.

    Handles ``from X import *`` for known-dangerous modules by expanding
    to their dangerous exports (e.g. system -> os.system).
    """
    for alias in node.names:
        if alias.name == "*":
            expansions = _STAR_IMPORT_EXPANSIONS.get(node.module or "")
            if expansions:
                for name in expansions:
                    alias_map[name] = f"{node.module}.{name}"
            continue
        alias_map[alias.asname or alias.name] = f"{node.module}.{alias.name}"


def _try_bodies(node: ast.Try) -> list[list[ast.stmt]]:
    """Return all body lists from a Try node (body, handlers, orelse, finalbody)."""
    bodies: list[list[ast.stmt]] = [node.body, node.orelse, node.finalbody]
    for handler in node.handlers:
        bodies.append(handler.body)
    return bodies


def get_call_name(node: ast.Call, alias_map: dict[str, str] | None = None) -> str:
    """Extract the dotted name of a call (e.g. 'os.system', 'eval').

    When alias_map is provided, resolves aliased names:
      - ``c.encode(...)`` with alias_map={'c': 'codecs'} -> 'codecs.encode'
      - ``p.join(...)``   with alias_map={'p': 'os.path'} -> 'os.path.join'
    """
    func = node.func
    if isinstance(func, ast.Name):
        if alias_map and func.id in alias_map:
            return alias_map[func.id]
        return func.id
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        raw = f"{func.value.id}.{func.attr}"
        if alias_map and func.value.id in alias_map:
            return f"{alias_map[func.value.id]}.{func.attr}"
        return raw
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
    for kw in node.keywords:
        if kw.arg == "Loader" and _is_safe_loader_node(kw.value):
            return True
    if len(node.args) >= 2 and _is_safe_loader_node(node.args[1]):
        return True
    return False


def _is_safe_loader_node(node: ast.expr) -> bool:
    """Check if a node refers to SafeLoader or CSafeLoader."""
    if isinstance(node, ast.Name):
        return node.id in _SAFE_LOADER_NAMES
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "yaml"
        and node.attr in _SAFE_LOADER_NAMES
    )


# re-exports at BOTTOM -- backward-compat (Facade Re-export Pattern)
from skill_scan._ast_string_resolver import (  # noqa: E402
    MAX_AST_RESOLVE_DEPTH as MAX_AST_RESOLVE_DEPTH,
    _get_call_name_from_any as _get_call_name_from_any,
    _is_chr_of_target as _is_chr_of_target,
    _resolve_binop_add as _resolve_binop_add,
    _resolve_bytes_decode as _resolve_bytes_decode,
    _resolve_chr_call as _resolve_chr_call,
    _resolve_int_expr as _resolve_int_expr,
    _resolve_int_list_to_chars as _resolve_int_list_to_chars,
    _resolve_iterable_elements as _resolve_iterable_elements,
    _resolve_join_call as _resolve_join_call,
    _resolve_join_listcomp as _resolve_join_listcomp,
    _resolve_join_map_chr as _resolve_join_map_chr,
    _try_resolve_string as _try_resolve_string,
    try_resolve_string as try_resolve_string,
)
