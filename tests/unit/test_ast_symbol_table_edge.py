"""Edge case and file-size-constraint tests for AST symbol table.

Split from test_ast_symbol_table.py to stay under the 250-line file limit.
Covers: empty/import-only modules, class bodies, reassignment, complex RHS,
and the file-size guard for _ast_symbol_table.py itself.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from skill_scan._ast_symbol_table import build_symbol_table


_PARSE = ast.parse


# -- R-IMP003: File size constraint -----------------------------------------


class TestFileSizeConstraint:
    def test_source_file_under_250_lines(self) -> None:
        src = pathlib.Path(__file__).resolve().parent.parent.parent
        target = src / "src" / "skill_scan" / "_ast_symbol_table.py"
        line_count = len(target.read_text().splitlines())
        assert line_count <= 250, f"_ast_symbol_table.py is {line_count} lines (max 250)"


# -- Edge cases -------------------------------------------------------------


class TestEdgeCases:
    def test_empty_module(self) -> None:
        result = build_symbol_table(_PARSE(""))
        assert result == {}

    def test_only_imports(self) -> None:
        result = build_symbol_table(_PARSE("import os\nfrom sys import argv"))
        assert result == {}

    def test_class_body_not_tracked(self) -> None:
        """Class-level assignments are not in module scope or function scope."""
        code = "class C:\n    x = 'class_val'"
        result = build_symbol_table(_PARSE(code))
        assert result == {}

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
