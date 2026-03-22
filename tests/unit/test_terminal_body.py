"""Tests for _is_terminal_body helper (PLAN-036 Part A).

Verifies that the helper correctly identifies bodies of AST statements
that always exit scope (return or raise), with conservative defaults
for ambiguous cases.
"""

from __future__ import annotations

import ast
import textwrap

from skill_scan._ast_terminal_body import _is_terminal_body


def _body(code: str) -> list[ast.stmt]:
    """Parse dedented code and return the module body."""
    return ast.parse(textwrap.dedent(code)).body


class TestLeafTerminals:
    """R001: Return and Raise are terminal; Break and Continue are not."""

    def test_return_is_terminal(self) -> None:
        assert _is_terminal_body(_body("return 42")) is True

    def test_bare_return_is_terminal(self) -> None:
        assert _is_terminal_body(_body("return")) is True

    def test_raise_is_terminal(self) -> None:
        assert _is_terminal_body(_body("raise ValueError('x')")) is True

    def test_bare_raise_is_terminal(self) -> None:
        assert _is_terminal_body(_body("raise")) is True

    def test_break_is_not_terminal(self) -> None:
        assert _is_terminal_body(_body("break")) is False

    def test_continue_is_not_terminal(self) -> None:
        assert _is_terminal_body(_body("continue")) is False

    def test_empty_body_is_not_terminal(self) -> None:
        assert _is_terminal_body([]) is False

    def test_pass_is_not_terminal(self) -> None:
        assert _is_terminal_body(_body("pass")) is False

    def test_expression_stmt_is_not_terminal(self) -> None:
        assert _is_terminal_body(_body("x = 1\ny = 2")) is False

    def test_return_after_assignment_is_terminal(self) -> None:
        assert _is_terminal_body(_body("x = 1\nreturn x")) is True

    def test_raise_after_assignment_is_terminal(self) -> None:
        assert _is_terminal_body(_body("msg = 'err'\nraise RuntimeError(msg)")) is True


class TestIfElseTerminals:
    """R002: If/else branching terminal detection."""

    def test_bare_if_no_else_not_terminal(self) -> None:
        """Bare if (no else) returns False even if body terminates."""
        assert _is_terminal_body(_body("if c:\n    return 1")) is False

    def test_if_else_both_return_is_terminal(self) -> None:
        assert _is_terminal_body(_body("if c:\n    return 1\nelse:\n    return 2")) is True

    def test_if_else_both_raise_is_terminal(self) -> None:
        assert _is_terminal_body(_body("if c:\n    raise A()\nelse:\n    raise B()")) is True

    def test_if_return_else_raise_is_terminal(self) -> None:
        assert _is_terminal_body(_body("if c:\n    return 1\nelse:\n    raise ValueError()")) is True

    def test_if_else_only_one_branch_terminates_not_terminal(self) -> None:
        assert _is_terminal_body(_body("if c:\n    return 1\nelse:\n    x = 2")) is False

    def test_nested_if_else_two_levels(self) -> None:
        """Nested if/else recursion works to 2+ levels."""
        code = """\
        if a:
            if b:
                return 1
            else:
                return 2
        else:
            return 3
        """
        assert _is_terminal_body(_body(code)) is True

    def test_nested_if_else_inner_incomplete(self) -> None:
        """Inner if without else breaks terminal chain."""
        code = """\
        if a:
            if b:
                return 1
        else:
            return 2
        """
        assert _is_terminal_body(_body(code)) is False

    def test_elif_chain_all_terminal(self) -> None:
        code = "if a:\n    return 1\nelif b:\n    return 2\nelse:\n    return 3"
        assert _is_terminal_body(_body(code)) is True

    def test_elif_chain_missing_else_not_terminal(self) -> None:
        code = "if a:\n    return 1\nelif b:\n    return 2"
        assert _is_terminal_body(_body(code)) is False


class TestLoopBodies:
    """For/while body always returns False (might not execute)."""

    def test_for_with_return_not_terminal(self) -> None:
        assert _is_terminal_body(_body("for x in items:\n    return x")) is False

    def test_while_with_return_not_terminal(self) -> None:
        assert _is_terminal_body(_body("while True:\n    return 1")) is False

    def test_for_with_raise_not_terminal(self) -> None:
        assert _is_terminal_body(_body("for x in items:\n    raise StopIteration()")) is False


class TestTryTerminals:
    """Try blocks with finalbody terminal detection."""

    def test_try_finalbody_terminates_is_terminal(self) -> None:
        """If finalbody terminates -> True regardless of other bodies."""
        code = """\
        try:
            x = 1
        finally:
            return 0
        """
        assert _is_terminal_body(_body(code)) is True

    def test_try_finalbody_raise_is_terminal(self) -> None:
        code = """\
        try:
            x = 1
        finally:
            raise SystemExit()
        """
        assert _is_terminal_body(_body(code)) is True

    def test_try_except_all_return_is_terminal(self) -> None:
        code = """\
        try:
            return 1
        except ValueError:
            return 2
        """
        assert _is_terminal_body(_body(code)) is True

    def test_try_except_partial_not_terminal(self) -> None:
        code = """\
        try:
            return 1
        except ValueError:
            x = 2
        """
        assert _is_terminal_body(_body(code)) is False

    def test_try_except_else_all_terminal(self) -> None:
        code = """\
        try:
            x = risky()
        except ValueError:
            return 2
        else:
            return 3
        """
        assert _is_terminal_body(_body(code)) is True

    def test_try_body_returns_no_handlers(self) -> None:
        """try/finally where body returns but finally does not."""
        code = """\
        try:
            return 1
        finally:
            pass
        """
        assert _is_terminal_body(_body(code)) is True


class TestMatchTerminals:
    """Match with exhaustive unguarded wildcard + all cases terminal."""

    def test_match_exhaustive_all_return_is_terminal(self) -> None:
        code = """\
        match x:
            case 1:
                return "one"
            case _:
                return "other"
        """
        assert _is_terminal_body(_body(code)) is True

    def test_match_exhaustive_all_raise_is_terminal(self) -> None:
        code = """\
        match x:
            case 1:
                raise ValueError()
            case _:
                raise RuntimeError()
        """
        assert _is_terminal_body(_body(code)) is True

    def test_match_no_wildcard_not_terminal(self) -> None:
        code = """\
        match x:
            case 1:
                return "one"
            case 2:
                return "two"
        """
        assert _is_terminal_body(_body(code)) is False

    def test_match_guarded_wildcard_not_terminal(self) -> None:
        """Wildcard with guard can fail to match -> not exhaustive."""
        code = """\
        match x:
            case 1:
                return "one"
            case _ if x > 0:
                return "pos"
        """
        assert _is_terminal_body(_body(code)) is False

    def test_match_exhaustive_one_case_incomplete_not_terminal(self) -> None:
        code = """\
        match x:
            case 1:
                x = 1
            case _:
                return "other"
        """
        assert _is_terminal_body(_body(code)) is False

    def test_match_empty_cases_not_terminal(self) -> None:
        """Match with no cases returns False."""
        node = ast.Match(subject=ast.Name(id="x"), cases=[])
        assert _is_terminal_body([node]) is False


class TestWithTerminals:
    """With statement delegates to its body."""

    def test_with_body_returns_is_terminal(self) -> None:
        code = "with open('f') as f:\n    return f.read()"
        assert _is_terminal_body(_body(code)) is True

    def test_with_body_no_return_not_terminal(self) -> None:
        code = "with open('f') as f:\n    data = f.read()"
        assert _is_terminal_body(_body(code)) is False

    def test_async_with_body_returns_is_terminal(self) -> None:
        code = "async with open('f') as f:\n    return f.read()"
        assert _is_terminal_body(_body(code)) is True

    def test_async_with_body_no_return_not_terminal(self) -> None:
        code = "async with open('f') as f:\n    data = f.read()"
        assert _is_terminal_body(_body(code)) is False


class TestConservativeDefault:
    """R005: Unrecognized or ambiguous structures return False."""

    def test_function_def_not_terminal(self) -> None:
        assert _is_terminal_body(_body("def inner():\n    return 1")) is False

    def test_class_def_not_terminal(self) -> None:
        assert _is_terminal_body(_body("class Foo:\n    pass")) is False

    def test_import_not_terminal(self) -> None:
        assert _is_terminal_body(_body("import os")) is False

    def test_mixed_non_terminal_then_return(self) -> None:
        """Return after non-terminal statements is still terminal."""
        assert _is_terminal_body(_body("x = 1\nimport os\nreturn x")) is True
