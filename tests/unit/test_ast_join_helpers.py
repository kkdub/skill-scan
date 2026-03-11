"""Tests for _ast_join_helpers.py -- extracted join-resolution helpers.

Verifies that the extraction preserved all behavior and that
re-exports from _ast_helpers still work.
"""

from __future__ import annotations

import ast

from skill_scan._ast_join_helpers import (
    _is_chr_of_target,
    _resolve_int_list_to_chars,
    _resolve_join_listcomp,
    _resolve_join_map_chr,
)


# ---------------------------------------------------------------------------
# _resolve_int_list_to_chars
# ---------------------------------------------------------------------------


class TestResolveIntListToChars:
    def test_eval_chars(self) -> None:
        elts = [ast.Constant(value=v) for v in [101, 118, 97, 108]]
        assert _resolve_int_list_to_chars(elts, "") == "eval"

    def test_with_separator(self) -> None:
        elts = [ast.Constant(value=65), ast.Constant(value=66)]
        assert _resolve_int_list_to_chars(elts, "-") == "A-B"

    def test_invalid_non_int(self) -> None:
        elts = [ast.Constant(value="not_int")]
        assert _resolve_int_list_to_chars(elts, "") is None

    def test_empty_list(self) -> None:
        assert _resolve_int_list_to_chars([], "") == ""

    def test_out_of_range(self) -> None:
        elts = [ast.Constant(value=-1)]
        assert _resolve_int_list_to_chars(elts, "") is None


# ---------------------------------------------------------------------------
# _is_chr_of_target
# ---------------------------------------------------------------------------


class TestIsChrOfTarget:
    def test_matching_target(self) -> None:
        code = "[chr(c) for c in [101]]"
        tree = ast.parse(code, mode="eval")
        listcomp = tree.body
        assert isinstance(listcomp, ast.ListComp)
        assert _is_chr_of_target(listcomp.elt, "c")

    def test_wrong_target_name(self) -> None:
        code = "[chr(x) for x in [101]]"
        tree = ast.parse(code, mode="eval")
        listcomp = tree.body
        assert isinstance(listcomp, ast.ListComp)
        assert not _is_chr_of_target(listcomp.elt, "c")

    def test_not_chr_call(self) -> None:
        code = "[ord(c) for c in 'abc']"
        tree = ast.parse(code, mode="eval")
        listcomp = tree.body
        assert isinstance(listcomp, ast.ListComp)
        assert not _is_chr_of_target(listcomp.elt, "c")


# ---------------------------------------------------------------------------
# _resolve_join_listcomp
# ---------------------------------------------------------------------------


class TestResolveJoinListcomp:
    def test_chr_listcomp_eval(self) -> None:
        code = "[chr(c) for c in [101, 118, 97, 108]]"
        tree = ast.parse(code, mode="eval")
        listcomp = tree.body
        assert isinstance(listcomp, ast.ListComp)
        assert _resolve_join_listcomp(listcomp, "") == "eval"

    def test_multiple_generators_returns_none(self) -> None:
        code = "[chr(c) for c in [101] for d in [102]]"
        tree = ast.parse(code, mode="eval")
        listcomp = tree.body
        assert isinstance(listcomp, ast.ListComp)
        assert _resolve_join_listcomp(listcomp, "") is None

    def test_with_filter_returns_none(self) -> None:
        code = "[chr(c) for c in [101, 118] if c > 100]"
        tree = ast.parse(code, mode="eval")
        listcomp = tree.body
        assert isinstance(listcomp, ast.ListComp)
        assert _resolve_join_listcomp(listcomp, "") is None


# ---------------------------------------------------------------------------
# _resolve_join_map_chr
# ---------------------------------------------------------------------------


class TestResolveJoinMapChr:
    def test_map_chr_eval(self) -> None:
        code = "map(chr, [101, 118, 97, 108])"
        tree = ast.parse(code, mode="eval")
        call = tree.body
        assert isinstance(call, ast.Call)
        assert _resolve_join_map_chr(call, "") == "eval"

    def test_not_map_returns_none(self) -> None:
        code = "filter(chr, [101])"
        tree = ast.parse(code, mode="eval")
        call = tree.body
        assert isinstance(call, ast.Call)
        assert _resolve_join_map_chr(call, "") is None

    def test_not_chr_func_returns_none(self) -> None:
        code = "map(ord, [101])"
        tree = ast.parse(code, mode="eval")
        call = tree.body
        assert isinstance(call, ast.Call)
        assert _resolve_join_map_chr(call, "") is None

    def test_wrong_arg_count_returns_none(self) -> None:
        code = "map(chr)"
        tree = ast.parse(code, mode="eval")
        call = tree.body
        assert isinstance(call, ast.Call)
        assert _resolve_join_map_chr(call, "") is None


# ---------------------------------------------------------------------------
# Re-exports from _ast_helpers still work
# ---------------------------------------------------------------------------


class TestReExportsFromAstHelpers:
    def test_imports_from_ast_helpers(self) -> None:
        from skill_scan._ast_helpers import (
            _is_chr_of_target as reexported_is_chr,
            _resolve_int_list_to_chars as reexported_int_list,
            _resolve_join_listcomp as reexported_listcomp,
            _resolve_join_map_chr as reexported_map_chr,
        )

        assert reexported_is_chr is _is_chr_of_target
        assert reexported_int_list is _resolve_int_list_to_chars
        assert reexported_listcomp is _resolve_join_listcomp
        assert reexported_map_chr is _resolve_join_map_chr
