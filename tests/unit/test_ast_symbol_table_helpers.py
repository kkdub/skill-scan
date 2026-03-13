"""Tests for _ast_symbol_table_helpers -- extracted assignment-tracking helpers.

Verifies that functions migrated from _ast_symbol_table.py to
_ast_symbol_table_helpers.py are importable and behave correctly.
"""

from __future__ import annotations

import ast

from skill_scan._ast_symbol_table import _Ref
from skill_scan._ast_symbol_table_helpers import (
    _collect_walrus,
    _handle_assign,
    _handle_aug_assign,
    _handle_unpack,
    _process_stmt,
    _recurse_control_flow,
    _track_name_assign,
    _walk_body,
)


_PARSE = ast.parse


class TestWalkBody:
    """Verify _walk_body collects assignments from statement lists."""

    def test_collects_string_assign(self) -> None:
        tree = _PARSE("x = 'hello'")
        table: dict[str, str | _Ref] = {}
        _walk_body(tree.body, table)
        assert table == {"x": "hello"}

    def test_collects_multiple_assigns(self) -> None:
        tree = _PARSE("a = 'foo'\nb = 'bar'")
        table: dict[str, str | _Ref] = {}
        _walk_body(tree.body, table)
        assert table == {"a": "foo", "b": "bar"}

    def test_empty_body(self) -> None:
        table: dict[str, str | _Ref] = {}
        _walk_body([], table)
        assert table == {}


class TestProcessStmt:
    """Verify _process_stmt dispatches correctly."""

    def test_dispatches_assign(self) -> None:
        tree = _PARSE("x = 'val'")
        table: dict[str, str | _Ref] = {}
        _process_stmt(tree.body[0], table)
        assert table == {"x": "val"}

    def test_dispatches_aug_assign(self) -> None:
        tree = _PARSE("x = 'start'\nx += 'end'")
        table: dict[str, str | _Ref] = {}
        _process_stmt(tree.body[0], table)
        _process_stmt(tree.body[1], table)
        assert table == {"x": "startend"}

    def test_dispatches_control_flow(self) -> None:
        tree = _PARSE("if True:\n    y = 'inner'")
        table: dict[str, str | _Ref] = {}
        _process_stmt(tree.body[0], table)
        assert table == {"y": "inner"}


class TestRecurseControlFlow:
    """Verify _recurse_control_flow enters if/for/while/with/try bodies."""

    def test_if_body(self) -> None:
        tree = _PARSE("if True:\n    x = 'a'\nelse:\n    y = 'b'")
        table: dict[str, str | _Ref] = {}
        _recurse_control_flow(tree.body[0], table)
        assert table == {"x": "a", "y": "b"}

    def test_for_body(self) -> None:
        tree = _PARSE("for i in range(1):\n    x = 'loop'")
        table: dict[str, str | _Ref] = {}
        _recurse_control_flow(tree.body[0], table)
        assert table == {"x": "loop"}

    def test_while_body(self) -> None:
        tree = _PARSE("while True:\n    x = 'loop'")
        table: dict[str, str | _Ref] = {}
        _recurse_control_flow(tree.body[0], table)
        assert table == {"x": "loop"}

    def test_with_body(self) -> None:
        tree = _PARSE("with open('f') as fh:\n    x = 'ctx'")
        table: dict[str, str | _Ref] = {}
        _recurse_control_flow(tree.body[0], table)
        assert table == {"x": "ctx"}

    def test_try_body(self) -> None:
        code = "try:\n    x = 'try'\nexcept:\n    y = 'exc'\nfinally:\n    z = 'fin'"
        tree = _PARSE(code)
        table: dict[str, str | _Ref] = {}
        _recurse_control_flow(tree.body[0], table)
        assert table == {"x": "try", "y": "exc", "z": "fin"}


class TestCollectWalrus:
    """Verify _collect_walrus finds := assignments."""

    def test_walrus_in_if(self) -> None:
        code = "if (x := 'walrus'):\n    pass"
        tree = _PARSE(code)
        table: dict[str, str | _Ref] = {}
        _collect_walrus(tree.body[0], table)
        assert table == {"x": "walrus"}

    def test_walrus_non_string_skipped(self) -> None:
        code = "if (x := 42):\n    pass"
        tree = _PARSE(code)
        table: dict[str, str | _Ref] = {}
        _collect_walrus(tree.body[0], table)
        assert table == {}


class TestHandleAssign:
    """Verify _handle_assign processes Name and tuple targets."""

    def test_simple_name(self) -> None:
        tree = _PARSE("x = 'val'")
        table: dict[str, str | _Ref] = {}
        stmt = tree.body[0]
        assert isinstance(stmt, ast.Assign)
        _handle_assign(stmt, table)
        assert table == {"x": "val"}

    def test_multiple_targets_skipped(self) -> None:
        tree = _PARSE("a = b = 'val'")
        table: dict[str, str | _Ref] = {}
        stmt = tree.body[0]
        assert isinstance(stmt, ast.Assign)
        _handle_assign(stmt, table)
        assert table == {}

    def test_tuple_unpack(self) -> None:
        tree = _PARSE("a, b = 'x', 'y'")
        table: dict[str, str | _Ref] = {}
        stmt = tree.body[0]
        assert isinstance(stmt, ast.Assign)
        _handle_assign(stmt, table)
        assert table == {"a": "x", "b": "y"}


class TestHandleUnpack:
    """Verify _handle_unpack handles tuple/list unpacking."""

    def test_tuple_unpack(self) -> None:
        tree = _PARSE("a, b = 'x', 'y'")
        stmt = tree.body[0]
        assert isinstance(stmt, ast.Assign)
        target = stmt.targets[0]
        assert isinstance(target, ast.Tuple)
        table: dict[str, str | _Ref] = {}
        _handle_unpack(target, stmt.value, table)
        assert table == {"a": "x", "b": "y"}

    def test_length_mismatch_skipped(self) -> None:
        tree = _PARSE("a, b = ('x',)")
        stmt = tree.body[0]
        assert isinstance(stmt, ast.Assign)
        target = stmt.targets[0]
        assert isinstance(target, ast.Tuple)
        table: dict[str, str | _Ref] = {}
        _handle_unpack(target, stmt.value, table)
        assert table == {}


class TestTrackNameAssign:
    """Verify _track_name_assign resolves strings and creates Refs."""

    def test_string_constant(self) -> None:
        tree = _PARSE("x = 'val'")
        stmt = tree.body[0]
        assert isinstance(stmt, ast.Assign)
        table: dict[str, str | _Ref] = {}
        _track_name_assign("x", stmt.value, table)
        assert table == {"x": "val"}

    def test_name_ref(self) -> None:
        tree = _PARSE("x = y")
        stmt = tree.body[0]
        assert isinstance(stmt, ast.Assign)
        table: dict[str, str | _Ref] = {}
        _track_name_assign("x", stmt.value, table)
        assert isinstance(table["x"], _Ref)
        assert table["x"].target == "y"

    def test_non_resolvable_skipped(self) -> None:
        tree = _PARSE("x = foo()")
        stmt = tree.body[0]
        assert isinstance(stmt, ast.Assign)
        table: dict[str, str | _Ref] = {}
        _track_name_assign("x", stmt.value, table)
        assert table == {}


class TestHandleAugAssign:
    """Verify _handle_aug_assign concatenates strings."""

    def test_string_concatenation(self) -> None:
        tree = _PARSE("x += 'end'")
        stmt = tree.body[0]
        assert isinstance(stmt, ast.AugAssign)
        table: dict[str, str | _Ref] = {"x": "start"}
        _handle_aug_assign(stmt, table)
        assert table == {"x": "startend"}

    def test_non_add_skipped(self) -> None:
        tree = _PARSE("x -= 1")
        stmt = tree.body[0]
        assert isinstance(stmt, ast.AugAssign)
        table: dict[str, str | _Ref] = {"x": "start"}
        _handle_aug_assign(stmt, table)
        assert table == {"x": "start"}

    def test_unknown_var_skipped(self) -> None:
        tree = _PARSE("x += 'end'")
        stmt = tree.body[0]
        assert isinstance(stmt, ast.AugAssign)
        table: dict[str, str | _Ref] = {}
        _handle_aug_assign(stmt, table)
        assert table == {}
