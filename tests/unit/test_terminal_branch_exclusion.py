"""Tests for terminal branch exclusion in int-list pre-pass (PLAN-036 Part B).

When a branch body always exits scope (return/raise), its mutations should
be excluded from the merge.  This prevents false shadows when one branch
diverges but never reaches the code after the branch.
"""

from __future__ import annotations

import ast
import textwrap

from skill_scan._ast_split_int_list_tracker import _SHADOW
from skill_scan._ast_split_comprehension import _collect_int_list_assigns


def _collect(code: str) -> dict[str, list[int]]:
    """Parse dedented code and run the int-list pre-pass collector."""
    return _collect_int_list_assigns(ast.parse(textwrap.dedent(code)))


class TestIfTerminalBodyExclusion:
    """Terminal if-body or else-body excluded from merge."""

    def test_terminal_if_body_excluded(self) -> None:
        """If-body returns -> excluded; only else-body contributes."""
        code = """\
        def f():
            codes = [101]
            if cond:
                codes += [118, 97, 108]
                return
            else:
                codes += [120]
        """
        result = _collect(code)
        assert result["f.codes"] == [101, 120]

    def test_terminal_if_body_raise_excluded(self) -> None:
        """If-body raises -> excluded; only else-body contributes."""
        code = """\
        def f():
            codes = [101]
            if cond:
                codes = [999]
                raise ValueError
            else:
                codes += [118]
        """
        result = _collect(code)
        assert result["f.codes"] == [101, 118]

    def test_terminal_else_body_excluded(self) -> None:
        """Else-body returns -> excluded; only if-body contributes."""
        code = """\
        def f():
            codes = [101]
            if cond:
                codes += [118]
            else:
                codes += [120, 101, 99]
                return
        """
        result = _collect(code)
        assert result["f.codes"] == [101, 118]

    def test_terminal_else_body_raise_excluded(self) -> None:
        """Else-body raises -> excluded; only if-body contributes."""
        code = """\
        def f():
            codes = [101]
            if cond:
                codes += [120]
            else:
                codes = [1, 2, 3]
                raise RuntimeError
        """
        result = _collect(code)
        assert result["f.codes"] == [101, 120]

    def test_both_terminal_result_equals_snapshot(self) -> None:
        """Both branches terminal -> result equals pre-branch snapshot."""
        code = """\
        def f():
            codes = [101]
            if cond:
                codes += [118, 97, 108]
                return
            else:
                codes = [999]
                raise ValueError
        """
        result = _collect(code)
        assert result["f.codes"] == [101]

    def test_both_terminal_new_key_not_leaked(self) -> None:
        """Both branches terminal and assign new key -> key not in result."""
        code = """\
        def f():
            if cond:
                fresh = [1, 2, 3]
                return
            else:
                fresh = [4, 5, 6]
                raise ValueError
        """
        result = _collect(code)
        assert "f.fresh" not in result

    def test_both_terminal_dead_code_ignored(self) -> None:
        """Both branches terminal -> dead code after if is not tracked."""
        code = """\
        def f():
            codes = [101]
            if cond:
                return
            else:
                return
            codes += [118, 97, 108]
        """
        result = _collect(code)
        assert result["f.codes"] == [101]

    def test_non_terminal_branches_still_merge(self) -> None:
        """Neither branch terminal -> normal merge (disagree = shadow)."""
        code = """\
        def f():
            codes = [101]
            if cond:
                codes += [118]
            else:
                codes += [120]
        """
        result = _collect(code)
        assert result["f.codes"] is _SHADOW

    def test_terminal_if_with_nested_return(self) -> None:
        """If-body terminal via nested if/else both returning -> excluded."""
        code = """\
        def f():
            codes = [101]
            if cond:
                codes += [118, 97, 108]
                if nested:
                    return
                else:
                    return
            else:
                codes += [120]
        """
        result = _collect(code)
        assert result["f.codes"] == [101, 120]


class TestMatchTerminalCaseExclusion:
    """Terminal match case bodies excluded from merge."""

    def test_terminal_case_excluded(self) -> None:
        """Case with return -> excluded; remaining case contributes."""
        code = """\
        def f():
            codes = [101]
            match x:
                case 1:
                    codes += [118]
                    return
                case _:
                    codes += [120]
        """
        result = _collect(code)
        assert result["f.codes"] == [101, 120]

    def test_terminal_case_raise_excluded(self) -> None:
        """Case with raise -> excluded; remaining case contributes."""
        code = """\
        def f():
            codes = [101]
            match x:
                case 1:
                    codes = [999]
                    raise ValueError
                case _:
                    codes += [118]
        """
        result = _collect(code)
        assert result["f.codes"] == [101, 118]

    def test_all_terminal_exhaustive_equals_snapshot(self) -> None:
        """All cases terminal + exhaustive -> pre-match snapshot."""
        code = """\
        def f():
            codes = [101]
            match x:
                case 1:
                    codes = [1, 2]
                    return
                case _:
                    codes = [3, 4]
                    return
        """
        result = _collect(code)
        assert result["f.codes"] == [101]

    def test_all_terminal_exhaustive_new_key_not_leaked(self) -> None:
        """All cases terminal + exhaustive: new key not in result."""
        code = """\
        def f():
            match x:
                case 1:
                    fresh = [1, 2]
                    return
                case _:
                    fresh = [3, 4]
                    raise ValueError
        """
        result = _collect(code)
        assert "f.fresh" not in result

    def test_mixed_terminal_and_nonterminal(self) -> None:
        """Mix of terminal and non-terminal cases; only non-terminal contribute."""
        code = """\
        def f():
            codes = [101]
            match x:
                case 1:
                    codes += [118]
                    return
                case 2:
                    codes += [120]
                    return
                case _:
                    codes += [97]
        """
        result = _collect(code)
        assert result["f.codes"] == [101, 97]

    def test_non_exhaustive_all_terminal_includes_snapshot(self) -> None:
        """Non-exhaustive match, all cases terminal -> snapshot is the only branch."""
        code = """\
        def f():
            codes = [101]
            match x:
                case 1:
                    codes = [1, 2]
                    return
        """
        result = _collect(code)
        # Only the pre-match snapshot survives (the terminal case is excluded,
        # and the snapshot branch is added because non-exhaustive).
        assert result["f.codes"] == [101]

    def test_all_terminal_exhaustive_dead_code_ignored(self) -> None:
        """All cases terminal + exhaustive -> dead code after match ignored."""
        code = """\
        def f():
            codes = [101]
            match x:
                case 1:
                    return
                case _:
                    raise ValueError
            codes += [118, 97, 108]
        """
        result = _collect(code)
        assert result["f.codes"] == [101]

    def test_non_terminal_cases_still_merge_normally(self) -> None:
        """No terminal cases -> normal merge behavior (disagree = shadow)."""
        code = """\
        def f():
            codes = [101]
            match x:
                case 1:
                    codes += [118]
                case _:
                    codes += [120]
        """
        result = _collect(code)
        assert result["f.codes"] is _SHADOW
