"""Private return-value extraction helpers for the symbol table builder.

Walks function bodies to collect return values from all code paths.
When all return paths converge to the same string constant, that value
is returned; otherwise returns None (conservative approach).

Used by build_symbol_table() to store function return values under
composite keys like 'funcname()'.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping

from skill_scan._ast_helpers import try_resolve_string


def _collect_return_value(
    func_body: list[ast.stmt],
    scope: Mapping[str, object],
) -> str | None:
    """Extract the converged return value from a function body.

    Returns the string if ALL return paths resolve to the same constant;
    returns None otherwise (divergent, unresolvable, or no returns).

    Args:
        func_body: The list of statements in the function body.
        scope: The function's variable assignments (str or _Ref values).
    """
    returns = _collect_all_returns(func_body)

    if not returns:
        return None

    # Check for implicit fallthrough (some paths don't return)
    if _has_implicit_fallthrough(func_body):
        return None

    # Resolve all return values to strings
    resolved: list[str] = []
    for ret_node in returns:
        val = _resolve_return_value(ret_node, scope)
        if val is None:
            return None
        resolved.append(val)

    # All must be the same string
    first = resolved[0]
    if all(v == first for v in resolved):
        return first
    return None


def _resolve_return_value(
    node: ast.Return,
    scope: Mapping[str, object],
) -> str | None:
    """Resolve a single return statement to a string value."""
    if node.value is None:
        # Bare 'return' -> returns None, treat as non-string
        return None

    value = node.value

    # Direct string constant
    resolved = try_resolve_string(value)
    if resolved is not None:
        return resolved

    # Variable reference -> look up in scope
    if isinstance(value, ast.Name):
        scope_val = scope.get(value.id)
        if isinstance(scope_val, str):
            return scope_val
        return None

    # BinOp(Add) of resolvable operands
    if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
        left = _resolve_operand(value.left, scope)
        right = _resolve_operand(value.right, scope)
        if left is not None and right is not None:
            return left + right

    return None


def _resolve_operand(
    node: ast.expr,
    scope: Mapping[str, object],
) -> str | None:
    """Resolve a single operand in a return expression."""
    resolved = try_resolve_string(node)
    if resolved is not None:
        return resolved
    if isinstance(node, ast.Name):
        scope_val = scope.get(node.id)
        if isinstance(scope_val, str):
            return scope_val
    return None


def _collect_all_returns(body: list[ast.stmt]) -> list[ast.Return]:
    """Collect all Return nodes from a function body (non-recursive into nested funcs)."""
    returns: list[ast.Return] = []
    _walk_for_returns(body, returns)
    return returns


def _walk_for_returns(
    body: list[ast.stmt],
    returns: list[ast.Return],
) -> None:
    """Walk statements collecting Return nodes, skipping nested function/class defs."""
    for stmt in body:
        if isinstance(stmt, ast.Return):
            returns.append(stmt)
        elif isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
            continue  # Don't recurse into nested functions
        elif isinstance(stmt, ast.ClassDef):
            continue  # Don't recurse into nested classes
        else:
            for sub_body in _sub_bodies(stmt):
                _walk_for_returns(sub_body, returns)


def _has_implicit_fallthrough(body: list[ast.stmt]) -> bool:
    """Check if a function body has any code path that doesn't end in a return.

    Conservative: if any branch can fall through without returning, the
    function has implicit fallthrough (returns None on that path).
    """
    return not _definitely_returns(body)


def _definitely_returns(body: list[ast.stmt]) -> bool:
    """Return True if every code path through this body ends in a return.

    This is conservative -- when in doubt, returns False (meaning the
    body might fall through without returning).
    """
    if not body:
        return False

    for stmt in body:
        if _stmt_definitely_returns(stmt):
            return True

    return False


def _stmt_definitely_returns(stmt: ast.stmt) -> bool:
    """Check if a single statement guarantees a return on all paths."""
    if isinstance(stmt, ast.Return):
        return True
    if isinstance(stmt, ast.If):
        return _if_definitely_returns(stmt)
    if isinstance(stmt, ast.Try):
        return _try_definitely_returns(stmt)
    if isinstance(stmt, ast.With):
        return _definitely_returns(stmt.body)
    if isinstance(stmt, ast.Match):
        return _match_definitely_returns(stmt)
    # Loops (for/while) might not execute -- can't guarantee return
    return False


def _if_definitely_returns(node: ast.If) -> bool:
    """Check if an if/elif/else chain definitely returns on all branches."""
    if not node.orelse:
        return False  # No else -> can fall through

    body_returns = _definitely_returns(node.body)
    else_returns = _definitely_returns(node.orelse)
    return body_returns and else_returns


def _try_definitely_returns(node: ast.Try) -> bool:
    """Check if a try/except/else/finally block definitely returns."""
    # If finally returns, everything returns
    if node.finalbody and _definitely_returns(node.finalbody):
        return True

    # Otherwise, try body + all handlers + else must all return
    body_returns = _definitely_returns(node.body)

    if not node.handlers:
        return body_returns

    all_handlers_return = all(_definitely_returns(h.body) for h in node.handlers)

    # If there's an else clause, it runs when try succeeds (no exception)
    if node.orelse:
        # success path: body returns directly, OR body completes and else returns
        # try failure path: handler runs
        try_success = _definitely_returns(node.body) or _definitely_returns(node.orelse)
        return try_success and all_handlers_return

    return body_returns and all_handlers_return


def _match_definitely_returns(node: ast.Match) -> bool:
    """Check if a match statement definitely returns on all branches."""
    if not node.cases:
        return False

    # Need a wildcard/default case to guarantee exhaustive matching
    has_wildcard = False
    for case in node.cases:
        # A wildcard with a guard (case _ if cond:) can fail to match,
        # so only treat unguarded wildcards as guaranteeing exhaustiveness.
        if isinstance(case.pattern, ast.MatchAs) and case.pattern.name is None and case.guard is None:
            has_wildcard = True

    if not has_wildcard:
        return False

    return all(_definitely_returns(case.body) for case in node.cases)


def _sub_bodies(stmt: ast.stmt) -> list[list[ast.stmt]]:
    """Return sub-bodies of a statement for return collection."""
    if isinstance(stmt, ast.If):
        return [stmt.body, stmt.orelse]
    if isinstance(stmt, ast.For | ast.While):
        return [stmt.body, stmt.orelse]
    if isinstance(stmt, ast.With):
        return [stmt.body]
    if isinstance(stmt, ast.Try):
        subs: list[list[ast.stmt]] = [stmt.body, stmt.orelse, stmt.finalbody]
        for handler in stmt.handlers:
            subs.append(handler.body)
        return subs
    if isinstance(stmt, ast.Match):
        return [case.body for case in stmt.cases]
    return []
