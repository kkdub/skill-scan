"""Tests for format_map extraction to _ast_split_format_map.py (PLAN-033 Part A).

Verifies:
- R001: _ast_split_format_map.py exists and exports the expected functions
- R001: Functions imported from the new module produce correct results
- R-IMP001: Existing behavior is preserved (resolve_call still dispatches to format_map)
- R-IMP003: No orphaned imports (old module re-exports work)
- R-IMP004: Line count constraints are met
"""

from __future__ import annotations

import ast
import importlib
import inspect
from pathlib import Path


_FILE = "test.py"


class TestFormatMapModuleExists:
    """The new _ast_split_format_map module must exist and export correctly."""

    def test_module_importable(self) -> None:
        """_ast_split_format_map can be imported."""
        mod = importlib.import_module("skill_scan._ast_split_format_map")
        assert mod is not None

    def test_resolve_format_map_call_exported(self) -> None:
        """_resolve_format_map_call is importable from the new module."""
        from skill_scan._ast_split_format_map import _resolve_format_map_call

        assert callable(_resolve_format_map_call)

    def test_resolve_dict_arg_exported(self) -> None:
        """_resolve_dict_arg is importable from the new module."""
        from skill_scan._ast_split_format_map import _resolve_dict_arg

        assert callable(_resolve_dict_arg)

    def test_lookup_str_dict_exported(self) -> None:
        """_lookup_str_dict is importable from the new module."""
        from skill_scan._ast_split_format_map import _lookup_str_dict

        assert callable(_lookup_str_dict)


class TestFormatMapFunctionBehavior:
    """Functions in the new module must produce correct results."""

    def test_resolve_format_map_inline_dict(self) -> None:
        """format_map with inline dict resolves to the substituted string."""
        from skill_scan._ast_split_format_map import _resolve_format_map_call

        code = "'{a}{b}'.format_map({'a': 'ev', 'b': 'al'})"
        tree = ast.parse(code, mode="eval")
        node = tree.body
        assert isinstance(node, ast.Call)
        result = _resolve_format_map_call(node, {}, "")
        assert result == "eval"

    def test_resolve_format_map_tracked_var(self) -> None:
        """format_map with tracked variable template resolves via symbol table."""
        from skill_scan._ast_split_format_map import _resolve_format_map_call

        code = "tpl.format_map({'x': 'hi'})"
        tree = ast.parse(code, mode="eval")
        node = tree.body
        assert isinstance(node, ast.Call)
        st = {"tpl": "{x}"}
        result = _resolve_format_map_call(node, st, "")
        assert result == "hi"

    def test_resolve_format_map_returns_none_for_non_format_map(self) -> None:
        """Non-format_map calls return None."""
        from skill_scan._ast_split_format_map import _resolve_format_map_call

        code = "'hello'.upper()"
        tree = ast.parse(code, mode="eval")
        node = tree.body
        assert isinstance(node, ast.Call)
        result = _resolve_format_map_call(node, {}, "")
        assert result is None

    def test_resolve_dict_arg_inline(self) -> None:
        """_resolve_dict_arg resolves an inline ast.Dict to a Python dict."""
        from skill_scan._ast_split_format_map import _resolve_dict_arg

        code = "{'a': 'ev', 'b': 'al'}"
        tree = ast.parse(code, mode="eval")
        node = tree.body
        result = _resolve_dict_arg(node, {}, "")
        assert result == {"a": "ev", "b": "al"}

    def test_resolve_dict_arg_spread_returns_none(self) -> None:
        """_resolve_dict_arg returns None for **spread dicts."""
        from skill_scan._ast_split_format_map import _resolve_dict_arg

        code = "{**base, 'a': 'x'}"
        tree = ast.parse(code, mode="eval")
        node = tree.body
        result = _resolve_dict_arg(node, {}, "")
        assert result is None

    def test_resolve_dict_arg_name_lookup(self) -> None:
        """_resolve_dict_arg resolves a Name by looking up composite keys."""
        from skill_scan._ast_split_format_map import _resolve_dict_arg

        code = "parts"
        tree = ast.parse(code, mode="eval")
        node = tree.body
        st = {"parts[a]": "ev", "parts[b]": "al"}
        result = _resolve_dict_arg(node, st, "")
        assert result == {"a": "ev", "b": "al"}

    def test_lookup_str_dict_scoped(self) -> None:
        """_lookup_str_dict prefers scoped entries over unscoped."""
        from skill_scan._ast_split_format_map import _lookup_str_dict

        st = {
            "parts[a]": "module_val",
            "func.parts[a]": "local_val",
        }
        result = _lookup_str_dict("parts", st, "func")
        assert result is not None
        assert result["a"] == "local_val"

    def test_lookup_str_dict_empty_returns_none(self) -> None:
        """_lookup_str_dict returns None when no matching keys exist."""
        from skill_scan._ast_split_format_map import _lookup_str_dict

        result = _lookup_str_dict("unknown", {}, "func")
        assert result is None


class TestResolveCallStillDispatches:
    """resolve_call in _ast_split_resolve must still dispatch to format_map."""

    def test_resolve_call_format_map_via_old_module(self) -> None:
        """resolve_call dispatches to _resolve_format_map_call after extraction."""
        from skill_scan._ast_split_resolve import resolve_call

        code = "'{a}{b}'.format_map({'a': 'ev', 'b': 'al'})"
        tree = ast.parse(code, mode="eval")
        node = tree.body
        assert isinstance(node, ast.Call)
        result = resolve_call(node, {}, "")
        assert result == ("eval", "split variable")

    def test_existing_format_map_tests_still_pass_e2e(self) -> None:
        """End-to-end: format_map detection still works through analyze_python."""
        from skill_scan.ast_analyzer import analyze_python

        code = (
            "template = '{a}{b}'\n"
            "parts = {'a': 'ev', 'b': 'al'}\n"
            "name = template.format_map(parts)\n"
            "globals()[name]('x')"
        )
        findings = analyze_python(code, _FILE)
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1


class TestReExportFromOldModule:
    """_ast_split_resolve must still expose format_map functions for backward compat."""

    def test_lookup_str_dict_importable_from_resolve(self) -> None:
        """_lookup_str_dict is still importable from _ast_split_resolve."""
        from skill_scan._ast_split_resolve import _lookup_str_dict

        assert callable(_lookup_str_dict)

    def test_resolve_format_map_call_importable_from_resolve(self) -> None:
        """_resolve_format_map_call is still importable from _ast_split_resolve."""
        from skill_scan._ast_split_resolve import _resolve_format_map_call

        assert callable(_resolve_format_map_call)


class TestSplitResolveLineCounts:
    """Line count constraints after extraction."""

    def test_split_resolve_max_225_lines(self) -> None:
        """_ast_split_resolve.py must be <= 225 lines after extraction."""
        src = inspect.getsourcefile(importlib.import_module("skill_scan._ast_split_resolve"))
        assert src is not None
        line_count = len(Path(src).read_text(encoding="utf-8").splitlines())
        assert line_count <= 225, f"_ast_split_resolve.py has {line_count} lines (max 225)"

    def test_format_map_module_max_100_lines(self) -> None:
        """_ast_split_format_map.py must be <= 100 lines."""
        src = inspect.getsourcefile(importlib.import_module("skill_scan._ast_split_format_map"))
        assert src is not None
        line_count = len(Path(src).read_text(encoding="utf-8").splitlines())
        assert line_count <= 100, f"_ast_split_format_map.py has {line_count} lines (max 100)"
