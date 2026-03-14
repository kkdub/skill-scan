"""Private class-scope helpers for the symbol table builder.

Extracted from _ast_symbol_table_helpers.py to stay under SIZE-001 and
maintainability thresholds. Handles self.attr = 'val' assignment tracking
inside class method bodies.
"""

from __future__ import annotations

import ast

from skill_scan._ast_helpers import try_resolve_string
from skill_scan._ast_symbol_table_return_helpers import _sub_bodies


def _walk_self_attrs(
    body: list[ast.stmt],
    result: dict[str, str],
    self_name: str,
    class_name: str,
) -> None:
    """Walk a method body for self.attr = 'string' assignments.

    Stores resolved values as 'ClassName.attr_name' in result. Recurses into
    control flow blocks but NOT into nested functions or classes.
    """
    for stmt in body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            _check_self_assign(stmt, result, self_name, class_name)
        else:
            for sub in _sub_bodies(stmt):
                _walk_self_attrs(sub, result, self_name, class_name)


def _check_self_assign(
    stmt: ast.Assign,
    result: dict[str, str],
    self_name: str,
    class_name: str,
) -> None:
    """Check if an Assign targets self.attr and store resolved value."""
    target = stmt.targets[0]
    if not isinstance(target, ast.Attribute):
        return
    if not isinstance(target.value, ast.Name) or target.value.id != self_name:
        return
    resolved = try_resolve_string(stmt.value)
    if resolved is not None:
        result[f"{class_name}.{target.attr}"] = resolved
