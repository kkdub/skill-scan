"""Edge case and file-size-constraint tests for AST symbol table.

Split from test_ast_symbol_table.py to stay under the 250-line file limit.
Covers: empty/import-only modules, class bodies, reassignment, complex RHS,
file-size guard, dict subscript assignments, and dict literal tracking.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from skill_scan._ast_symbol_table import build_symbol_table


_PARSE = ast.parse


# -- R-IMP003: File size constraint -----------------------------------------


class TestFileSizeConstraint:
    def test_source_file_under_300_lines(self) -> None:
        src = pathlib.Path(__file__).resolve().parent.parent.parent
        target = src / "src" / "skill_scan" / "_ast_symbol_table.py"
        line_count = len(target.read_text().splitlines())
        assert line_count <= 300, f"_ast_symbol_table.py is {line_count} lines (max 300)"


# -- Edge cases -------------------------------------------------------------


class TestEdgeCases:
    def test_empty_module(self) -> None:
        result = build_symbol_table(_PARSE(""))
        assert result == {}

    def test_only_imports(self) -> None:
        result = build_symbol_table(_PARSE("import os\nfrom sys import argv"))
        assert result == {}

    def test_class_body_tracked_with_prefix(self) -> None:
        """Class-level assignments are stored as 'ClassName.attr'."""
        code = "class C:\n    x = 'class_val'"
        result = build_symbol_table(_PARSE(code))
        assert result["C.x"] == "class_val"

    def test_reassignment_takes_last_value(self) -> None:
        code = "x = 'first'\nx = 'second'"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "second"

    @pytest.mark.parametrize(
        "code,expected_key,expected_val",
        [
            ("x = 'a' + 'b'", "x", "ab"),
            ("x = chr(65)", "x", "A"),
        ],
        ids=["concat", "chr"],
    )
    def test_complex_rhs_resolved(self, code: str, expected_key: str, expected_val: str) -> None:
        result = build_symbol_table(_PARSE(code))
        assert result[expected_key] == expected_val


# -- BinOp(Mult) string repetition ------------------------------------------


class TestStringMultiply:
    """build_symbol_table resolves string * positive-int assignments (R007)."""

    def test_string_times_one(self) -> None:
        result = build_symbol_table(_PARSE("x = 'ev' * 1"))
        assert result["x"] == "ev"

    def test_string_times_two(self) -> None:
        result = build_symbol_table(_PARSE("x = 'ev' * 2"))
        assert result["x"] == "evev"

    def test_reversed_operand_order(self) -> None:
        result = build_symbol_table(_PARSE("x = 2 * 'ev'"))
        assert result["x"] == "evev"

    def test_zero_not_tracked(self) -> None:
        result = build_symbol_table(_PARSE("x = 'ev' * 0"))
        assert "x" not in result

    def test_negative_not_tracked(self) -> None:
        result = build_symbol_table(_PARSE("x = 'ev' * -1"))
        assert "x" not in result

    def test_float_not_tracked(self) -> None:
        result = build_symbol_table(_PARSE("x = 'ev' * 2.0"))
        assert "x" not in result

    def test_multiply_in_function_scope(self) -> None:
        code = "def f():\n    x = 'ab' * 3"
        result = build_symbol_table(_PARSE(code))
        assert result["f.x"] == "ababab"

    def test_multiply_feeds_concat(self) -> None:
        """String multiply + variable concat builds dangerous name (R-EFF005)."""
        code = "a = 'ev' * 1\nb = 'al' * 1\nc = a + b"
        result = build_symbol_table(_PARSE(code))
        assert result["a"] == "ev"
        assert result["b"] == "al"
        # c is BinOp(Add) with Name operands -- not resolved in symbol table
        # (the split detector handles this at detection time)
        assert "c" not in result


# -- R003/R004: Dict subscript and literal tracking -------------------------


class TestDictSubscriptAssign:
    """build_symbol_table records d['key'] = 'val' as composite key 'd[key]' (R003)."""

    def test_basic_subscript_assign(self) -> None:
        code = "d = {}\nd['a'] = 'ev'\nd['b'] = 'al'"
        result = build_symbol_table(_PARSE(code))
        assert result["d[a]"] == "ev"
        assert result["d[b]"] == "al"

    def test_subscript_assign_in_function(self) -> None:
        code = "def f():\n    d = {}\n    d['x'] = 'hello'"
        result = build_symbol_table(_PARSE(code))
        assert result["f.d[x]"] == "hello"

    def test_integer_key_tracked(self) -> None:
        """Non-negative integer indices are tracked as composite keys (R001)."""
        code = "d = {}\nd[0] = 'val'"
        result = build_symbol_table(_PARSE(code))
        assert result["d[0]"] == "val"

    def test_non_string_value_ignored(self) -> None:
        code = "d = {}\nd['k'] = 42"
        result = build_symbol_table(_PARSE(code))
        assert "d[k]" not in result

    def test_no_collision_with_plain_name(self) -> None:
        """Bracket format prevents collision with plain variable names (R-IMP002)."""
        code = "x = 'plain'\nd = {}\nd['x'] = 'subscript'"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "plain"
        assert result["d[x]"] == "subscript"


class TestDictLiteralTracking:
    """build_symbol_table records dict literal values as composite keys (R004)."""

    def test_basic_dict_literal(self) -> None:
        code = "parts = {'a': 'ev', 'b': 'al'}"
        result = build_symbol_table(_PARSE(code))
        assert result["parts[a]"] == "ev"
        assert result["parts[b]"] == "al"

    def test_dict_literal_in_function(self) -> None:
        code = "def f():\n    d = {'k': 'val'}"
        result = build_symbol_table(_PARSE(code))
        assert result["f.d[k]"] == "val"

    def test_non_string_key_in_literal_ignored(self) -> None:
        code = "d = {1: 'val', 'k': 'ok'}"
        result = build_symbol_table(_PARSE(code))
        assert "d[1]" not in result
        assert result["d[k]"] == "ok"

    def test_non_string_value_in_literal_ignored(self) -> None:
        code = "d = {'a': 42, 'b': 'ok'}"
        result = build_symbol_table(_PARSE(code))
        assert "d[a]" not in result
        assert result["d[b]"] == "ok"

    def test_dict_literal_reassignment_overwrites(self) -> None:
        code = "d = {'a': 'first'}\nd['a'] = 'second'"
        result = build_symbol_table(_PARSE(code))
        assert result["d[a]"] == "second"

    def test_dict_with_splat_skips_none_keys(self) -> None:
        """Dict with **kwargs: None keys are skipped safely."""
        code = "other = {}\nd = {'a': 'ok', **other}"
        result = build_symbol_table(_PARSE(code))
        assert result["d[a]"] == "ok"


# -- R001/R002: List-index composite keys -----------------------------------


class TestListIndexSubscriptAssign:
    """build_symbol_table records parts[0] = 'ev' as composite key 'parts[0]' (R001)."""

    def test_basic_int_index_assign(self) -> None:
        code = "parts = [None, None]\nparts[0] = 'ev'"
        result = build_symbol_table(_PARSE(code))
        assert result["parts[0]"] == "ev"

    def test_multi_index_assembly(self) -> None:
        """Multi-statement list-index assembly (R002)."""
        code = "items = [None]*3\nitems[0] = 'ex'\nitems[1] = 'ec'"
        result = build_symbol_table(_PARSE(code))
        assert result["items[0]"] == "ex"
        assert result["items[1]"] == "ec"

    def test_string_key_still_works(self) -> None:
        """String-key dict subscript tracking unchanged (R-IMP001 regression)."""
        code = "d = {}\nd['k'] = 'ev'"
        result = build_symbol_table(_PARSE(code))
        assert result["d[k]"] == "ev"

    def test_negative_index_ignored(self) -> None:
        code = "parts = [None]\nparts[-1] = 'val'"
        result = build_symbol_table(_PARSE(code))
        assert "parts[-1]" not in result

    def test_float_index_ignored(self) -> None:
        code = "parts = [None]\nparts[1.5] = 'val'"
        result = build_symbol_table(_PARSE(code))
        assert "parts[1.5]" not in result

    def test_int_string_key_collision_documented(self) -> None:
        """Integer 0 and string '0' produce same composite key (R-IMP002 documented)."""
        code = "d = {}\nd[0] = 'int_val'\nd['0'] = 'str_val'"
        result = build_symbol_table(_PARSE(code))
        # Last assignment wins -- both map to 'd[0]'
        assert result["d[0]"] == "str_val"

    def test_int_index_in_function_scope(self) -> None:
        code = "def f():\n    parts = [None]\n    parts[0] = 'hello'"
        result = build_symbol_table(_PARSE(code))
        assert result["f.parts[0]"] == "hello"

    def test_non_string_value_ignored(self) -> None:
        code = "parts = [None]\nparts[0] = 42"
        result = build_symbol_table(_PARSE(code))
        assert "parts[0]" not in result
