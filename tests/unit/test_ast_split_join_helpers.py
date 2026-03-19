"""Tests for nested comprehension join resolution.

Covers:
- R006: Nested comprehension [chr(c) for row in [[ints]] for c in row] resolves in join
- _resolve_nested_comprehension_join: flattens 2D int list, dispatches to chr resolver
- 3+ generators return None (only 2 supported)
- Existing single-generator comprehension still works (no regression)
"""

from __future__ import annotations

import ast
import pathlib

from skill_scan._ast_split_detector import detect_split_evasion
from skill_scan._ast_split_join_helpers import _resolve_comprehension_join
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.ast_analyzer import analyze_python
from skill_scan.models import Finding

_PARSE = ast.parse
_FILE = "test.py"


def _detect(code: str) -> list[Finding]:
    """Helper: parse code, build symbol table, run split detector."""
    tree = _PARSE(code)
    st = build_symbol_table(tree)
    return detect_split_evasion(tree, _FILE, {}, st)


def _make_genexp(code: str) -> ast.GeneratorExp:
    """Parse a generator expression from join call arg."""
    tree = ast.parse(code, mode="eval")
    call = tree.body
    assert isinstance(call, ast.Call)
    arg = call.args[0]
    assert isinstance(arg, ast.GeneratorExp)
    return arg


def _make_listcomp(code: str) -> ast.ListComp:
    """Parse a list comprehension from join call arg."""
    tree = ast.parse(code, mode="eval")
    call = tree.body
    assert isinstance(call, ast.Call)
    arg = call.args[0]
    assert isinstance(arg, ast.ListComp)
    return arg


# -- R006: Nested comprehension with 2 generators ----------------------------


class TestNestedComprehensionJoin:
    """Nested comprehension [chr(c) for row in [[ints]] for c in row] resolves."""

    def test_nested_genexp_chr_resolves_eval(self) -> None:
        """2-generator pattern: chr(c) for row in [[101,118],[97,108]] for c in row -> 'eval'."""
        genexp = _make_genexp("''.join(chr(c) for row in [[101, 118], [97, 108]] for c in row)")
        result = _resolve_comprehension_join(genexp, "", {}, "")
        assert result == "eval"

    def test_nested_listcomp_chr_resolves_eval(self) -> None:
        """ListComp variant with 2 generators also resolves."""
        listcomp = _make_listcomp("''.join([chr(c) for row in [[101, 118], [97, 108]] for c in row])")
        result = _resolve_comprehension_join(listcomp, "", {}, "")
        assert result == "eval"

    def test_nested_genexp_exec(self) -> None:
        """chr(c) for row in [[101,120],[101,99]] for c in row -> 'exec'."""
        genexp = _make_genexp("''.join(chr(c) for row in [[101, 120], [101, 99]] for c in row)")
        result = _resolve_comprehension_join(genexp, "", {}, "")
        assert result == "exec"

    def test_nested_with_separator(self) -> None:
        """Non-empty separator joins correctly."""
        genexp = _make_genexp("','.join(chr(c) for row in [[65], [66]] for c in row)")
        result = _resolve_comprehension_join(genexp, ",", {}, "")
        assert result == "A,B"

    def test_three_generators_returns_none(self) -> None:
        """3+ generators return None -- only 2 supported."""
        genexp = _make_genexp("''.join(chr(c) for row in [[101]] for c in row for _ in [1])")
        result = _resolve_comprehension_join(genexp, "", {}, "")
        assert result is None

    def test_outer_not_list_of_lists_returns_none(self) -> None:
        """Outer iter must be list of lists, not flat list of ints."""
        genexp = _make_genexp("''.join(chr(c) for row in [101, 118] for c in row)")
        result = _resolve_comprehension_join(genexp, "", {}, "")
        assert result is None

    def test_inner_target_mismatch_returns_none(self) -> None:
        """Inner target must match outer variable name."""
        # for row in [[101]] for c in other_name -- mismatch
        code = "''.join(chr(c) for row in [[101, 118]] for c in [97])"
        genexp = _make_genexp(code)
        result = _resolve_comprehension_join(genexp, "", {}, "")
        # The inner iter is not the outer target name, so should not match nested pattern
        assert result is None

    def test_nested_with_filter_returns_none(self) -> None:
        """Generators with if-clauses not supported in nested pattern."""
        genexp = _make_genexp("''.join(chr(c) for row in [[101, 118], [97, 108]] for c in row if c > 0)")
        result = _resolve_comprehension_join(genexp, "", {}, "")
        assert result is None

    def test_nested_non_chr_elt_returns_none(self) -> None:
        """Element must be chr() call, not arbitrary expression."""
        genexp = _make_genexp("''.join(str(c) for row in [[101, 118], [97, 108]] for c in row)")
        result = _resolve_comprehension_join(genexp, "", {}, "")
        assert result is None

    def test_outer_with_tuple_of_lists(self) -> None:
        """Outer iter can be a Tuple of Lists."""
        genexp = _make_genexp("''.join(chr(c) for row in ([101, 118], [97, 108]) for c in row)")
        result = _resolve_comprehension_join(genexp, "", {}, "")
        assert result == "eval"

    def test_outer_contains_non_list_element_returns_none(self) -> None:
        """Outer list element must be a List, not a non-list constant."""
        genexp = _make_genexp("''.join(chr(c) for row in [101, [97, 108]] for c in row)")
        result = _resolve_comprehension_join(genexp, "", {}, "")
        assert result is None


# -- Single-generator regression tests ----------------------------------------


class TestSingleGeneratorRegression:
    """Existing single-generator comprehension still works."""

    def test_single_generator_chr_still_works(self) -> None:
        """chr(c) for c in [101, 118, 97, 108] -> 'eval' (no regression)."""
        genexp = _make_genexp("''.join(chr(c) for c in [101, 118, 97, 108])")
        result = _resolve_comprehension_join(genexp, "", {}, "")
        assert result == "eval"

    def test_single_generator_identity_still_works(self) -> None:
        """p for p in ['ev', 'al'] -> 'eval' (no regression)."""
        genexp = _make_genexp("''.join(p for p in ['ev', 'al'])")
        result = _resolve_comprehension_join(genexp, "", {"ev": "ev", "al": "al"}, "")
        # Identity pattern resolves elements via symbol table or literals
        # With literal strings in iter, should resolve
        assert result == "eval"


# -- Full-path detection (split detector) ------------------------------------


class TestNestedComprehensionDetection:
    """R006: Nested comprehension triggers EXEC-002 via split detector."""

    def test_nested_genexp_triggers_exec002(self) -> None:
        code = "name = ''.join(chr(c) for row in [[101, 118], [97, 108]] for c in row)"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_nested_listcomp_triggers_exec002(self) -> None:
        code = "name = ''.join([chr(c) for row in [[101, 118], [97, 108]] for c in row])"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_nested_safe_no_finding(self) -> None:
        """Non-dangerous nested comprehension produces no finding."""
        code = "x = ''.join(chr(c) for row in [[104, 101], [108, 108]] for c in row)"
        assert len(_detect(code)) == 0


# -- Full pipeline (analyze_python) acceptance ---------------------------------


class TestNestedComprehensionAcceptance:
    """R006 acceptance: analyze_python detects nested comprehension patterns."""

    def test_nested_comprehension_full_pipeline(self) -> None:
        code = "name = ''.join(chr(c) for row in [[101, 118], [97, 108]] for c in row)"
        findings = analyze_python(code, _FILE)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1
        assert any("eval" in f.description for f in exec_findings)

    def test_nested_safe_no_false_positive(self) -> None:
        """Safe nested comprehension produces no dangerous findings."""
        code = "x = ''.join(chr(c) for row in [[104, 105]] for c in row)"
        findings = analyze_python(code, _FILE)
        dangerous = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert len(dangerous) == 0


# -- Corpus fixture test ------------------------------------------------------


class TestNestedComprehensionCorpus:
    """Corpus fixture produces expected findings."""

    def test_pos_nested_comprehension_fixture(self) -> None:
        fixture = (
            pathlib.Path(__file__).resolve().parent.parent
            / "fixtures"
            / "split_evasion"
            / "pos_nested_comprehension.py"
        )
        code = fixture.read_text()
        findings = analyze_python(code, str(fixture))
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1
