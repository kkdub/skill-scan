"""Extended tests for AST symbol table -- augmented assign, unpacking, control flow, walrus.

Covers the Tier 1 evasion hardening additions to _ast_symbol_table.py:
augmented assignment (+=), tuple/list unpacking, control flow body recursion,
and walrus operator (:=) tracking.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.ast_analyzer import analyze_python


_PARSE = ast.parse


# -- Augmented assignment (+=) tracking -------------------------------------


class TestAugmentedAssignment:
    def test_string_concat_via_augassign(self) -> None:
        code = "a = 'ev'\na += 'al'"
        result = build_symbol_table(_PARSE(code))
        assert result["a"] == "eval"

    def test_augassign_multiple_appends(self) -> None:
        code = "a = 'e'\na += 'v'\na += 'a'\na += 'l'"
        result = build_symbol_table(_PARSE(code))
        assert result["a"] == "eval"

    def test_augassign_non_string_skipped(self) -> None:
        code = "a = 1\na += 2"
        result = build_symbol_table(_PARSE(code))
        assert result == {}

    def test_augassign_untracked_var_skipped(self) -> None:
        """AugAssign on a variable not in the table is ignored."""
        code = "x += 'suffix'"
        result = build_symbol_table(_PARSE(code))
        assert result == {}

    def test_augassign_non_add_skipped(self) -> None:
        """Only += (Add) is tracked, not *= or other operators."""
        code = "a = 'hello'\na *= 3"
        result = build_symbol_table(_PARSE(code))
        assert result == {"a": "hello"}

    def test_augassign_in_function(self) -> None:
        code = "def f():\n    a = 'ev'\n    a += 'al'"
        result = build_symbol_table(_PARSE(code))
        assert result["f.a"] == "eval"


# -- Tuple/list unpacking tracking -----------------------------------------


class TestTupleUnpacking:
    def test_tuple_unpack_two_strings(self) -> None:
        code = "a, b = 'ev', 'al'"
        result = build_symbol_table(_PARSE(code))
        assert result["a"] == "ev"
        assert result["b"] == "al"

    def test_list_unpack_two_strings(self) -> None:
        code = "[a, b] = ['ev', 'al']"
        result = build_symbol_table(_PARSE(code))
        assert result["a"] == "ev"
        assert result["b"] == "al"

    def test_unpack_three_values(self) -> None:
        code = "a, b, c = 'x', 'y', 'z'"
        result = build_symbol_table(_PARSE(code))
        assert result == {"a": "x", "b": "y", "c": "z"}

    def test_unpack_mismatched_length_skipped(self) -> None:
        """Different target/value counts should not crash."""
        code = "a, b = ('x',)"
        result = build_symbol_table(_PARSE(code))
        assert "a" not in result
        assert "b" not in result

    def test_unpack_mixed_types_partial(self) -> None:
        """Non-string values in the tuple are skipped, strings are tracked."""
        code = "a, b = 'hello', 42"
        result = build_symbol_table(_PARSE(code))
        assert result["a"] == "hello"
        assert "b" not in result

    def test_unpack_non_tuple_rhs_skipped(self) -> None:
        """Tuple target with non-tuple RHS (e.g., function call) is skipped."""
        code = "a, b = some_func()"
        result = build_symbol_table(_PARSE(code))
        assert result == {}

    def test_unpack_in_function(self) -> None:
        code = "def f():\n    x, y = 'a', 'b'"
        result = build_symbol_table(_PARSE(code))
        assert result["f.x"] == "a"
        assert result["f.y"] == "b"


# -- Control flow body recursion --------------------------------------------


class TestControlFlowBodies:
    def test_if_body_tracked(self) -> None:
        code = "if True:\n    x = 'eval'"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "eval"

    def test_if_else_body_tracked(self) -> None:
        code = "if cond:\n    x = 'a'\nelse:\n    y = 'b'"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "a"
        assert result["y"] == "b"

    def test_for_body_tracked(self) -> None:
        code = "for i in [1]:\n    x = 'eval'"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "eval"

    def test_while_body_tracked(self) -> None:
        code = "while True:\n    x = 'eval'\n    break"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "eval"

    def test_with_body_tracked(self) -> None:
        code = "with open('f') as fh:\n    x = 'eval'"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "eval"

    def test_try_body_tracked(self) -> None:
        code = "try:\n    x = 'eval'\nexcept:\n    pass"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "eval"

    def test_try_handler_body_tracked(self) -> None:
        code = "try:\n    pass\nexcept Exception:\n    x = 'eval'"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "eval"

    def test_nested_if_in_for(self) -> None:
        code = "for i in [1]:\n    if True:\n        x = 'eval'"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "eval"

    def test_conditional_in_function(self) -> None:
        code = "def f():\n    if True:\n        x = 'eval'"
        result = build_symbol_table(_PARSE(code))
        assert result["f.x"] == "eval"

    def test_if_else_same_var_takes_last(self) -> None:
        """When both branches assign the same var, last write wins."""
        code = "if cond:\n    x = 'first'\nelse:\n    x = 'second'"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "second"


# -- Walrus operator (:=) tracking -----------------------------------------


class TestWalrusOperator:
    def test_walrus_string_tracked(self) -> None:
        code = "(x := 'eval')"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "eval"

    def test_walrus_in_if_condition(self) -> None:
        code = "if (x := 'eval'):\n    pass"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "eval"

    def test_walrus_multiple(self) -> None:
        code = "if (a := 'ev') and (b := 'al'):\n    pass"
        result = build_symbol_table(_PARSE(code))
        assert result["a"] == "ev"
        assert result["b"] == "al"

    def test_walrus_non_string_skipped(self) -> None:
        code = "(x := 42)"
        result = build_symbol_table(_PARSE(code))
        assert result == {}

    def test_walrus_in_while(self) -> None:
        code = "while (x := 'eval'):\n    break"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "eval"

    def test_walrus_in_function(self) -> None:
        code = "def f():\n    if (x := 'eval'):\n        pass"
        result = build_symbol_table(_PARSE(code))
        assert result["f.x"] == "eval"


# -- Corpus integration: new evasion fixtures produce findings --------------


class TestCorpusIntegration:
    """Verify new corpus files produce EXEC-002 findings through full pipeline."""

    _FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "split_evasion"

    @pytest.mark.parametrize(
        "filename",
        [
            "pos_augmented_assign.py",
            "pos_tuple_unpack.py",
            "pos_conditional_assign.py",
            "pos_walrus.py",
        ],
    )
    def test_corpus_produces_finding(self, filename: str) -> None:
        filepath = self._FIXTURES / filename
        code = filepath.read_text()
        findings = analyze_python(code, str(filepath))
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1, f"{filename} should produce EXEC-002 finding"
