"""Ref-table pre-pass: track dynamic import assignments.

Builds a ``dict[str, RefEntry]`` mapping variable names (scope-aware) to their
resolved module references from ``__import__('mod')`` and
``importlib.import_module('mod')`` call patterns.

Scope keys follow the same convention as ``build_symbol_table``:
- Module-level: bare name (e.g. ``m``)
- Function-scoped: ``funcname.varname`` (e.g. ``foo.m``)
- Class body: ``ClassName.varname``
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Literal

from skill_scan._ast_detectors import _IMPORT_CALL_NAMES
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
    scope_map = _build_scope_map(tree)
    result: dict[str, RefEntry] = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        if not isinstance(node.value, ast.Call):
            continue

        entry = _try_extract_import(node.value, alias_map)
        if entry is None:
            continue

        scope = scope_map.get(id(node), "")
        key = f"{scope}.{target.id}" if scope else target.id
        result[key] = entry

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
