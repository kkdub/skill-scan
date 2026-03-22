"""Tests for branch-aware merge in int-list pre-pass (PLAN-035 Part A).

Covers If/Match snapshot-merge, sequential walk preservation, declaration
threading through branches, the DEBT-028 corpus regression, and terminal
branch exclusion integration (PLAN-036 Part C).
"""

from __future__ import annotations

import ast
import textwrap

from skill_scan._ast_split_int_list_tracker import _SHADOW
from skill_scan._ast_split_comprehension import _collect_int_list_assigns


def _collect(code: str) -> dict[str, list[int]]:
    """Parse dedented code and run the int-list pre-pass collector."""
    return _collect_int_list_assigns(ast.parse(textwrap.dedent(code)))


class TestIfBranchMerge:
    """If/else branches walked independently; differing values shadowed."""

    def test_if_else_different_extend_shadows(self) -> None:
        """Divergent extensions in if/else -> shadow."""
        result = _collect(
            "codes = [101]\nif c:\n    codes += [118, 97, 108]\nelse:\n    codes += [120, 101, 99]"
        )
        assert result["codes"] is _SHADOW

    def test_if_else_identical_extend_keeps(self) -> None:
        """Identical extensions in both branches -> kept."""
        result = _collect("codes = [101]\nif c:\n    codes += [118]\nelse:\n    codes += [118]")
        assert result["codes"] == [101, 118]
        assert result["codes"] is not _SHADOW

    def test_if_only_assigns_preserved(self) -> None:
        """Key assigned only in if-branch (no else) -> preserved."""
        result = _collect("if c:\n    codes = [101, 118, 97, 108]")
        assert result["codes"] == [101, 118, 97, 108]

    def test_if_else_different_assign_shadows(self) -> None:
        """Different assignments in if/else -> shadow."""
        result = _collect("if c:\n    codes = [1, 2]\nelse:\n    codes = [3, 4]")
        assert result["codes"] is _SHADOW

    def test_if_only_extends_existing_shadows(self) -> None:
        """Only if extends existing key (else unchanged) -> shadow."""
        result = _collect("codes = [101]\nif c:\n    codes += [118, 97, 108]")
        # if-branch: [101,118,97,108], else-branch keeps snapshot [101] -> differ
        assert result["codes"] is _SHADOW

    def test_elif_chain_diverge_shadows(self) -> None:
        """elif chain with one branch differing -> shadow."""
        code = (
            "codes = [101]\nif a:\n    codes += [118]\nelif b:\n    codes += [120]\nelse:\n    codes += [97]"
        )
        assert _collect(code)["codes"] is _SHADOW

    def test_elif_chain_all_agree_keeps(self) -> None:
        """elif chain where all branches agree -> kept."""
        code = (
            "codes = [101]\nif a:\n    codes += [118]\nelif b:\n    codes += [118]\nelse:\n    codes += [118]"
        )
        result = _collect(code)
        assert result["codes"] == [101, 118]

    def test_if_else_assign_same_value_keeps(self) -> None:
        """Both branches assign identical value -> kept."""
        result = _collect("if c:\n    codes = [101, 118]\nelse:\n    codes = [101, 118]")
        assert result["codes"] == [101, 118]
        assert result["codes"] is not _SHADOW


class TestMatchBranchMerge:
    """Match/case branches walked independently; N-way merge."""

    def test_match_three_cases_diverge_shadows(self) -> None:
        """Three match cases with different values -> shadow."""
        code = "match x:\n    case 1:\n        codes = [1]\n    case 2:\n        codes = [2]\n    case _:\n        codes = [3]"
        assert _collect(code)["codes"] is _SHADOW

    def test_match_non_exhaustive_includes_snapshot(self) -> None:
        """Non-exhaustive match: snapshot is extra branch, disagrees -> shadow."""
        code = "codes = [101]\nmatch x:\n    case 1:\n        codes = [1, 2]"
        assert _collect(code)["codes"] is _SHADOW

    def test_match_exhaustive_wildcard_all_agree(self) -> None:
        """Exhaustive match with wildcard, all cases agree -> kept."""
        code = "match x:\n    case 1:\n        codes = [1, 2]\n    case _:\n        codes = [1, 2]"
        result = _collect(code)
        assert result["codes"] == [1, 2]
        assert result["codes"] is not _SHADOW

    def test_match_all_cases_agree_keeps(self) -> None:
        """All match cases extend identically -> kept."""
        code = "codes = [101]\nmatch x:\n    case 1:\n        codes += [118]\n    case 2:\n        codes += [118]\n    case _:\n        codes += [118]"
        result = _collect(code)
        assert result["codes"] == [101, 118]

    def test_match_guarded_wildcard_not_exhaustive(self) -> None:
        """Guarded wildcard (case _ if cond:) is NOT exhaustive; snapshot included."""
        code = "codes = [101]\nmatch x:\n    case _ if cond:\n        codes = [1, 2]"
        # Guard can fail -> pre-match snapshot [101] is extra branch -> disagrees -> shadow
        assert _collect(code)["codes"] is _SHADOW

    def test_match_unguarded_wildcard_is_exhaustive(self) -> None:
        """Unguarded wildcard with all cases agreeing -> kept (no snapshot branch)."""
        code = "match x:\n    case 1:\n        codes = [1, 2]\n    case _:\n        codes = [1, 2]"
        result = _collect(code)
        assert result["codes"] == [1, 2]

    def test_match_non_exhaustive_new_key_preserved(self) -> None:
        """Non-exhaustive match: new key in single case -> preserved."""
        code = "match x:\n    case 1:\n        fresh = [101, 118]"
        assert _collect(code)["fresh"] == [101, 118]

    def test_match_subset_disagree_shadows(self) -> None:
        """Key in subset of match cases with different values -> shadow."""
        code = "match x:\n    case 1:\n        codes = [1]\n    case 2:\n        codes = [2]\n    case _:\n        pass"
        assert _collect(code)["codes"] is _SHADOW


class TestSequentialWalkPreserved:
    """For/While/Try/With sub-bodies still walked sequentially."""

    def test_for_loop_sequential(self) -> None:
        """For loop body extends sequentially (not branch-aware)."""
        assert _collect("codes = [101]\nfor _ in [1]:\n    codes += [118]")["codes"] == [101, 118]

    def test_while_sequential(self) -> None:
        """While body extends sequentially."""
        assert _collect("codes = [101]\nwhile c:\n    codes += [118]")["codes"] == [101, 118]

    def test_try_sequential(self) -> None:
        """Try body and handler walked sequentially."""
        assert _collect("codes = [101]\ntry:\n    codes += [118]\nexcept E:\n    codes += [97]")["codes"] == [
            101,
            118,
            97,
        ]

    def test_with_sequential(self) -> None:
        """With body extends sequentially."""
        assert _collect("codes = [101]\nwith ctx:\n    codes += [118]")["codes"] == [101, 118]


class TestBranchDeclarations:
    """Declaration threading works through branch-aware paths."""

    def test_global_if_else_agree(self) -> None:
        """Global decl: if/else extend identically -> module key kept."""
        code = "codes = [101]\ndef f():\n    global codes\n    if c:\n        codes += [118]\n    else:\n        codes += [118]"
        result = _collect(code)
        assert result["codes"] == [101, 118]
        assert "f.codes" not in result

    def test_global_if_else_diverge_shadows(self) -> None:
        """Global decl: if/else differ -> module key shadowed."""
        code = "codes = [101]\ndef f():\n    global codes\n    if c:\n        codes += [118]\n    else:\n        codes += [120]"
        assert _collect(code)["codes"] is _SHADOW

    def test_nonlocal_if_else_agree(self) -> None:
        """Nonlocal decl: if/else extend identically -> enclosing key kept."""
        code = "def outer():\n    codes = [101]\n    def inner():\n        nonlocal codes\n        if c:\n            codes += [118]\n        else:\n            codes += [118]\n    inner()"
        result = _collect(code)
        assert result["outer.codes"] == [101, 118]

    def test_nonlocal_if_else_diverge_shadows(self) -> None:
        """Nonlocal decl: if/else differ -> enclosing key shadowed."""
        code = "def outer():\n    codes = [101]\n    def inner():\n        nonlocal codes\n        if c:\n            codes += [118]\n        else:\n            codes += [120]\n    inner()"
        assert _collect(code)["outer.codes"] is _SHADOW


class TestCollectIntListsFromBody:
    """Module-level _collect_int_list_assigns uses branch-aware _walk_fn_body."""

    def test_module_level_if_else_branch_aware(self) -> None:
        """Module-level if/else uses branch-aware merge."""
        assert (
            _collect("codes = [101]\nif c:\n    codes += [118]\nelse:\n    codes += [120]")["codes"]
            is _SHADOW
        )

    def test_class_body_if_else_branch_aware(self) -> None:
        """Class body if/else uses branch-aware merge."""
        code = "class C:\n    codes = [101]\n    if c:\n        codes += [118]\n    else:\n        codes += [120]"
        assert _collect(code)["C.codes"] is _SHADOW


class TestCorpusRegression:
    """DEBT-028 corpus regression: platform-conditional int-list evasion."""

    def test_debt028_branch_divergence_shadows(self) -> None:
        """Corpus: if/else extends codes differently -> _SHADOW, not nonsense merge."""
        code = (
            "import os\ncodes = [101]\n"
            "if os.name == 'nt':\n    codes += [118, 97, 108]\n"
            "else:\n    codes += [120, 101, 99]\n"
            "name = ''.join(chr(c) for c in codes)\n"
            "globals()[name](\"print('pwned')\")\n"
        )
        result = _collect(code)
        assert result["codes"] is _SHADOW

    def test_debt028_not_nonsense_merge(self) -> None:
        """Merged result must NOT be the buggy sequential concatenation."""
        code = "import os\ncodes = [101]\nif os.name == 'nt':\n    codes += [118, 97, 108]\nelse:\n    codes += [120, 101, 99]"
        assert _collect(code)["codes"] != [101, 118, 97, 108, 120, 101, 99]


class TestTerminalBranchExclusion:
    """Integration: terminal branches excluded from merge (PLAN-036 Part C).

    Full per-branch tests live in test_terminal_branch_exclusion.py.
    Unique here: post-branch continuation, break semantics, declaration scope.
    """

    def test_if_return_excluded_post_if_uses_else(self) -> None:
        """if-body returns -> excluded; post-if continues from surviving branch."""
        code = (
            "def f():\n    codes = [101]\n    if cond:\n"
            "        codes = [118, 97, 108]\n        return\n"
            "    else:\n        codes += [120]\n    codes += [99]"
        )
        assert _collect(code)["f.codes"] == [101, 120, 99]

    def test_break_not_excluded(self) -> None:
        """break is NOT terminal -- mutations visible after loop."""
        code = (
            "def f():\n    codes = [101]\n    for x in items:\n"
            "        if cond:\n            codes += [118]\n            break\n"
            "        else:\n            codes += [120]"
        )
        assert _collect(code)["f.codes"] is _SHADOW

    def test_global_var_in_terminal_branch(self) -> None:
        """Global variable in terminal branch -- scope routing correct."""
        code = (
            "codes = [101]\ndef f():\n    global codes\n    if cond:\n"
            "        codes += [118, 97, 108]\n        return\n"
            "    else:\n        codes += [120]"
        )
        result = _collect(code)
        assert result["codes"] == [101, 120]
        assert "f.codes" not in result

    def test_nonlocal_var_in_terminal_branch(self) -> None:
        """Nonlocal variable in terminal branch -- scope routing correct."""
        code = (
            "def outer():\n    codes = [101]\n    def inner():\n"
            "        nonlocal codes\n        if cond:\n"
            "            codes += [118, 97, 108]\n            return\n"
            "        else:\n            codes += [120]\n    inner()"
        )
        assert _collect(code)["outer.codes"] == [101, 120]
