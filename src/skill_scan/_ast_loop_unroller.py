"""Static for-loop unrolling for string assembly detection.

Detects and resolves limited loop patterns that build strings:

    target = ''
    for VAR in [str_literal, ...]:
        target += VAR

Produces a dict mapping target names to concatenated string values.
Results are merged into the symbol table for split-evasion detection.
"""

from __future__ import annotations

import ast


def collect_loop_assigns(tree: ast.Module) -> dict[str, str]:
    """Pre-pass: resolve loop-assembled string variables.

    Walks module-level and function-level bodies. For each ``for`` node
    matching the supported pattern, resolves the target to the concatenation
    of all list elements.
    """
    result: dict[str, str] = {}
    _scan_body(tree.body, result, scope="")
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            _scan_body(node.body, result, scope=node.name)
    return result


def _scan_body(body: list[ast.stmt], result: dict[str, str], *, scope: str) -> None:
    """Scan a statement body for loop-assembly patterns."""
    for i, stmt in enumerate(body):
        if not isinstance(stmt, ast.For):
            continue
        resolved = _try_resolve_loop(stmt, body[:i])
        if resolved is not None:
            target_name, value = resolved
            key = f"{scope}.{target_name}" if scope else target_name
            result[key] = value


def _try_resolve_loop(loop: ast.For, preceding: list[ast.stmt]) -> tuple[str, str] | None:
    """Try to resolve a single for-loop to a concatenated string.

    Returns (target_name, concatenated_value) or None.
    """
    # 1. Loop variable must be a simple Name
    if not isinstance(loop.target, ast.Name):
        return None
    loop_var = loop.target.id

    # 2. Iter must be an inline list of string constants, or a Name
    #    referencing a local list-literal assignment
    elements = _extract_str_list(loop.iter, preceding)
    if elements is None:
        return None

    # 3. Body must be exactly one AugAssign(target += loop_var)
    if len(loop.body) != 1:
        return None
    stmt = loop.body[0]
    if not isinstance(stmt, ast.AugAssign):
        return None
    if not isinstance(stmt.op, ast.Add):
        return None
    if not isinstance(stmt.target, ast.Name):
        return None
    target_name = stmt.target.id
    if not isinstance(stmt.value, ast.Name) or stmt.value.id != loop_var:
        return None

    # 4. Target must be initialized to '' before the loop
    if not _has_empty_init(target_name, preceding):
        return None

    return target_name, "".join(elements)


def _extract_str_list(iter_node: ast.expr, preceding: list[ast.stmt]) -> list[str] | None:
    """Extract string elements from a list literal or a Name referencing one."""
    if isinstance(iter_node, ast.List):
        return _list_to_strings(iter_node)
    if isinstance(iter_node, ast.Name):
        # Look backwards for Name = [str, str, ...] assignment
        for stmt in reversed(preceding):
            if (
                isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
                and stmt.targets[0].id == iter_node.id
                and isinstance(stmt.value, ast.List)
            ):
                return _list_to_strings(stmt.value)
    return None


def _list_to_strings(node: ast.List) -> list[str] | None:
    """Extract all elements as strings, or None if any is non-string."""
    result: list[str] = []
    for elt in node.elts:
        if not isinstance(elt, ast.Constant) or not isinstance(elt.value, str):
            return None
        result.append(elt.value)
    return result


def _has_empty_init(name: str, preceding: list[ast.stmt]) -> bool:
    """Check if name was initialized to '' in preceding statements."""
    for stmt in reversed(preceding):
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
            and stmt.targets[0].id == name
        ):
            return isinstance(stmt.value, ast.Constant) and stmt.value.value == ""
    return False
