"""Terminal body detection for AST branch analysis.

Determines whether a body of AST statements always exits scope via
return or raise.  Used by the int-list merge pre-pass to identify
branches whose mutations should be excluded (the branch never reaches
the code after it).

Mirrors the recursive structure of ``_definitely_returns`` in
``_ast_symbol_table_returns.py``, but the leaf check includes both
``ast.Return`` and ``ast.Raise``.  ``break`` and ``continue`` are NOT
terminal -- they exit loop iteration only; mutations remain visible
after the loop.
"""

from __future__ import annotations

import ast


def _is_terminal_body(body: list[ast.stmt]) -> bool:
    """Return True if every code path through *body* exits scope.

    A body is terminal when it always ends in ``return`` or ``raise``
    on every reachable path.  Conservative: returns False when in doubt
    (unrecognized node types, loops, bare ``if`` without ``else``).
    """
    if not body:
        return False

    for stmt in body:
        if _stmt_is_terminal(stmt):
            return True

    return False


def _stmt_is_terminal(stmt: ast.stmt) -> bool:
    """Check if a single statement guarantees scope exit on all paths."""
    if isinstance(stmt, ast.Return | ast.Raise):
        return True
    if isinstance(stmt, ast.If):
        return _if_is_terminal(stmt)
    if isinstance(stmt, ast.Try):
        return _try_is_terminal(stmt)
    if isinstance(stmt, ast.With):
        return _is_terminal_body(stmt.body)
    if isinstance(stmt, ast.Match):
        return _match_is_terminal(stmt)
    # Loops (for/while) might not execute -- can't guarantee exit.
    # break/continue are Expr-level, not stmt-level control flow
    # that guarantees scope exit.
    # FunctionDef, ClassDef, Import, etc. are not terminal.
    return False


def _if_is_terminal(node: ast.If) -> bool:
    """Check if an if/elif/else chain is terminal on all branches."""
    if not node.orelse:
        return False  # No else -> can fall through

    return _is_terminal_body(node.body) and _is_terminal_body(node.orelse)


def _try_is_terminal(node: ast.Try) -> bool:
    """Check if a try/except/else/finally block is terminal."""
    # If finally is terminal, the whole block is terminal
    if node.finalbody and _is_terminal_body(node.finalbody):
        return True

    # Otherwise, try body + all handlers + else must all be terminal
    body_terminal = _is_terminal_body(node.body)

    if not node.handlers:
        return body_terminal

    all_handlers_terminal = all(_is_terminal_body(h.body) for h in node.handlers)

    # If there's an else clause, it runs when try succeeds (no exception)
    if node.orelse:
        try_success = body_terminal or _is_terminal_body(node.orelse)
        return try_success and all_handlers_terminal

    return body_terminal and all_handlers_terminal


def _is_exhaustive_match(node: ast.Match) -> bool:
    """Return True if the match has an unguarded wildcard case.

    An unguarded wildcard (``case _:`` without a guard) guarantees that
    at least one case will always match.  Used by both terminal-body
    analysis and the int-list merge pre-pass.
    """
    if not node.cases:
        return False
    last_case = node.cases[-1]
    last_pat = last_case.pattern
    return isinstance(last_pat, ast.MatchAs) and last_pat.name is None and last_case.guard is None


def _match_is_terminal(node: ast.Match) -> bool:
    """Check if a match statement is terminal on all branches."""
    if not _is_exhaustive_match(node):
        return False

    return all(_is_terminal_body(case.body) for case in node.cases)
