"""Standalone rule-checking functions for AST antipattern detection.

Each public function takes AST nodes and context, returning a violation
message string or ``None``.  The visitor dispatches to these; no
function here touches the visitor or its state.
"""

from __future__ import annotations

import ast

from .models import (
    COMMON_OVERRIDE_METHODS,
    MAX_ELIF_BRANCHES,
    MAX_FUNCTION_LINES,
    MAX_INHERITANCE_DEPTH,
    SKIP_BASE_CLASSES,
)

# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def get_decorator_name(decorator: ast.expr) -> str | None:
    """Extract the simple name from a decorator expression."""
    if isinstance(decorator, ast.Name):
        return decorator.id
    if isinstance(decorator, ast.Call):
        func = decorator.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
    if isinstance(decorator, ast.Attribute):
        return decorator.attr
    return None


def decorator_has_kwarg(decorator: ast.expr, name: str, value: object) -> bool:
    """Return whether a ``Call`` decorator has keyword *name* equal to *value*."""
    if not isinstance(decorator, ast.Call):
        return False
    return any(
        kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value == value
        for kw in decorator.keywords
    )


def get_node_end_line(node: ast.AST) -> int:
    """Return the last line number covered by *node*."""
    end_lineno = getattr(node, "end_lineno", None)
    lineno = getattr(node, "lineno", None)
    end_line: int = end_lineno if end_lineno is not None else (lineno if lineno is not None else 0)
    for child in ast.walk(node):
        child_end = getattr(child, "end_lineno", None)
        if child_end is not None:
            end_line = max(end_line, child_end)
    return end_line


def extract_base_class_names(bases: list[ast.expr]) -> list[str]:
    """Extract class names from base-class AST expressions."""
    names: list[str] = []
    for base in bases:
        if isinstance(base, ast.Name):
            names.append(base.id)
        elif isinstance(base, ast.Attribute):
            names.append(base.attr)
    return names


# ---------------------------------------------------------------------------
# Rule checkers — return a message string on violation, else ``None``
# ---------------------------------------------------------------------------


def check_dataclass_slots(node: ast.ClassDef) -> str | None:
    """DATA-001: dataclass without ``slots=True``."""
    for decorator in node.decorator_list:
        if get_decorator_name(decorator) != "dataclass":
            continue
        if isinstance(decorator, ast.Name) or not decorator_has_kwarg(decorator, "slots", True):
            return f"Class '{node.name}': use @dataclass(slots=True)"
        break
    return None


def check_inheritance_depth(node: ast.ClassDef, base_names: list[str]) -> str | None:
    """INHERIT-002: too many meaningful base classes."""
    meaningful = [b for b in base_names if b not in SKIP_BASE_CLASSES]
    if len(meaningful) >= MAX_INHERITANCE_DEPTH:
        return f"'{node.name}': {len(meaningful)} bases, prefer composition"
    return None


def check_function_size(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """SIZE-002: function exceeds line limit."""
    if not node.body:
        return None
    line_count = get_node_end_line(node) - node.lineno + 1
    if line_count > MAX_FUNCTION_LINES:
        return f"'{node.name}': {line_count} lines (max {MAX_FUNCTION_LINES})"
    return None


def check_self_return_type(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    current_class: str | None,
) -> str | None:
    """TYPE-003: method returns class name instead of ``Self``."""
    if current_class is None or node.returns is None:
        return None
    ret = node.returns
    is_class_ref = (isinstance(ret, ast.Constant) and ret.value == current_class) or (
        isinstance(ret, ast.Name) and ret.id == current_class
    )
    if is_class_ref:
        return f"Use 'Self' instead of '{current_class}' for return type"
    return None


def check_override_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    current_class: str | None,
    class_bases: dict[str, list[str]],
) -> str | None:
    """INHERIT-001: overriding method missing ``@override``."""
    if current_class is None:
        return None
    if node.name.startswith("__") and node.name.endswith("__"):
        return None
    if not class_bases.get(current_class):
        return None
    if node.name not in COMMON_OVERRIDE_METHODS:
        return None
    if any(get_decorator_name(d) == "override" for d in node.decorator_list):
        return None
    return f"Method '{node.name}' overrides parent - add @override"


def check_elif_chain(
    node: ast.If,
    visited_ifs: set[int],
) -> str | None:
    """CONTROL-001: long elif chain."""
    elif_count = 0
    current: ast.If | None = node
    while current is not None:
        visited_ifs.add(id(current))
        if len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If):
            elif_count += 1
            current = current.orelse[0]
        else:
            current = None
    if elif_count >= MAX_ELIF_BRANCHES:
        return f"{elif_count} elif branches - consider match statement"
    return None
