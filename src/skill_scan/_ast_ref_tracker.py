"""Ref-table pre-pass: track dynamic import assignments.

Builds a ``dict[str, RefEntry]`` mapping variable names (scope-aware) to their
resolved module references from ``__import__('mod')`` and
``importlib.import_module('mod')`` call patterns.

Scope keys follow the same convention as ``build_symbol_table``:
- Module-level: bare name (e.g. ``m``)
- Function-scoped: ``funcname.varname`` (e.g. ``foo.m``)
- Class body: ``ClassName.varname``
- Method-scoped: ``ClassName.method.varname`` (e.g. ``MyClass.run.m``)
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Literal

from skill_scan._ast_inline_chain_detector import _IMPORT_CALL_NAMES
from skill_scan._ast_imports import get_call_name
from skill_scan._ast_split_detector import _build_scope_map


@dataclass(slots=True, frozen=True)
class RefEntry:
    """A resolved reference from a dynamic import assignment.

    Attributes:
        kind: The type of reference -- ``'module'`` for module imports,
              ``'func_ref'`` for function references (future use).
        resolved: The resolved module or function name (e.g. ``'os'``,
                  ``'os.system'``).
    """

    kind: Literal["module", "func_ref"]
    resolved: str


def _sub_bodies(node: ast.stmt) -> list[list[ast.stmt]]:
    """Return the sub-bodies of a compound statement for recursive walking."""
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.With | ast.AsyncWith):
        return [node.body]
    if isinstance(node, ast.If | ast.For | ast.While | ast.AsyncFor):
        return [node.body, node.orelse]
    if isinstance(node, ast.Try):
        handler_bodies = [h.body for h in node.handlers]
        return [node.body, *handler_bodies, node.orelse, node.finalbody]
    return []


def _process_assign(
    node: ast.Assign,
    scope_map: dict[int, str],
    alias_map: dict[str, str],
    result: dict[str, RefEntry],
) -> None:
    """Process a single Assign node for ref_table tracking."""
    if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
        return
    if not isinstance(node.value, ast.Call):
        return
    scope = scope_map.get(id(node), "")
    key = f"{scope}.{node.targets[0].id}" if scope else node.targets[0].id
    entry = _try_extract_import(node.value, alias_map)
    if entry is not None:
        result[key] = entry
    elif key in result:
        del result[key]


def _walk_body(
    body: list[ast.stmt],
    scope_map: dict[int, str],
    alias_map: dict[str, str],
    result: dict[str, RefEntry],
) -> None:
    """Walk statement bodies in source order, tracking import assignments.

    Recurses into function/class definitions and compound statements
    (if/for/while/try/with) to visit nested assignments.
    """
    for node in body:
        children = _sub_bodies(node)
        if children:
            for child in children:
                _walk_body(child, scope_map, alias_map, result)
        elif isinstance(node, ast.Assign):
            _process_assign(node, scope_map, alias_map, result)


def build_ref_table(
    tree: ast.Module,
    alias_map: dict[str, str],
) -> dict[str, RefEntry]:
    """Build a ref-table mapping variable names to dynamic import references.

    Walks assignment nodes in the AST looking for patterns like:
    - ``m = __import__('os')``
    - ``mod = importlib.import_module('subprocess')``
    - ``m = builtins.__import__('os')``
    - ``m = __builtins__.__import__('os')``

    Returns a dict with scope-aware keys (e.g. ``'foo.m'`` for function-scoped).
    """
    scope_map = _build_scope_map(tree, method_scope=True)
    result: dict[str, RefEntry] = {}
    _walk_body(tree.body, scope_map, alias_map, result)
    return result


def _try_extract_import(
    call: ast.Call,
    alias_map: dict[str, str],
) -> RefEntry | None:
    """Try to extract a RefEntry from a Call node if it's a recognized import.

    Returns None if the call is not a recognized import pattern or if the
    first argument is not a string constant.
    """
    call_name = get_call_name(call, alias_map)
    if call_name not in _IMPORT_CALL_NAMES:
        return None

    if not call.args:
        return None
    first_arg = call.args[0]
    if not isinstance(first_arg, ast.Constant) or not isinstance(first_arg.value, str):
        return None

    return RefEntry(kind="module", resolved=first_arg.value)
