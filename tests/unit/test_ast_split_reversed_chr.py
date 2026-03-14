"""Tests for reversed() join and chr(ord()) expression resolution.

Covers:
- _resolve_reversed_join(): reversed string/list/tracked-var inside join
- _resolve_chr_call(): chr(N), chr(ord('x')), chr(ord('x') + N)
- Edge cases: non-constant args, safe strings, boundary values
"""

from __future__ import annotations

import ast
import textwrap


from skill_scan._ast_split_detector import detect_split_evasion
from skill_scan._ast_split_resolve import (
    _resolve_chr_arg,
    _resolve_chr_call,
    _resolve_int_arg,
    _resolve_ord_call,
)
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


def _parse_call(code: str) -> ast.Call:
    """Parse a single call expression string into an AST Call node."""
    node = ast.parse(code, mode="eval").body
    assert isinstance(node, ast.Call)
    return node


# -- reversed() join resolution -----------------------------------------------


class TestReversedJoinStringLiteral:
    """R003: reversed() on string literals inside join."""

    def test_reversed_string_produces_exec002(self) -> None:
        findings = _detect("x = ''.join(reversed('lave'))")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_reversed_string_system(self) -> None:
        findings = _detect("x = ''.join(reversed('metsys'))")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_reversed_string_exec006_import(self) -> None:
        findings = _detect("x = ''.join(reversed('__tropmi__'))")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-006"


class TestReversedJoinList:
    """R003: reversed() on list/tuple of tracked elements inside join."""

    def test_reversed_list_produces_exec002(self) -> None:
        findings = _detect("x = ''.join(reversed(['l', 'a', 'v', 'e']))")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_reversed_tuple_produces_exec002(self) -> None:
        findings = _detect("x = ''.join(reversed(('l', 'a', 'v', 'e')))")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_reversed_list_with_tracked_vars(self) -> None:
        code = "a = 'l'\nb = 'a'\nc = 'v'\nd = 'e'\nx = ''.join(reversed([a, b, c, d]))"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"


class TestReversedJoinTrackedVar:
    """R003: reversed() on a tracked variable name."""

    def test_reversed_tracked_var_produces_exec002(self) -> None:
        code = "s = 'lave'\nx = ''.join(reversed(s))"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"


class TestReversedJoinSafe:
    """R-IMP002: reversed() on safe strings produces no findings."""

    def test_reversed_safe_string_no_finding(self) -> None:
        assert len(_detect("x = ''.join(reversed('olleh'))")) == 0

    def test_reversed_safe_list_no_finding(self) -> None:
        assert len(_detect("x = ''.join(reversed(['d', 'l', 'r', 'o', 'w']))")) == 0

    def test_reversed_untracked_var_no_finding(self) -> None:
        """reversed() on a variable not in the symbol table should not resolve."""
        assert len(_detect("x = ''.join(reversed(unknown_var))")) == 0

    def test_reversed_with_separator(self) -> None:
        """reversed with a separator that doesn't build a dangerous name."""
        assert len(_detect("x = '-'.join(reversed('lave'))")) == 0


# -- chr() / ord() resolution -------------------------------------------------


class TestChrCallResolution:
    """R004: chr(N) and chr(ord('x')) resolution via resolve_expr."""

    def test_chr_int_literal(self) -> None:
        node = _parse_call("chr(101)")
        result = _resolve_chr_call(node)
        assert result == "e"

    def test_chr_ord_single_char(self) -> None:
        node = _parse_call("chr(ord('e'))")
        result = _resolve_chr_call(node)
        assert result == "e"

    def test_chr_ord_padded_add_zero(self) -> None:
        """R-EFF006: chr(ord('e') + 0) resolves correctly."""
        node = _parse_call("chr(ord('e') + 0)")
        result = _resolve_chr_call(node)
        assert result == "e"

    def test_chr_ord_arithmetic_add(self) -> None:
        """chr(ord('a') + 3) -> 'd'."""
        node = _parse_call("chr(ord('a') + 3)")
        result = _resolve_chr_call(node)
        assert result == "d"

    def test_chr_ord_arithmetic_sub(self) -> None:
        """chr(ord('d') - 3) -> 'a'."""
        node = _parse_call("chr(ord('d') - 3)")
        result = _resolve_chr_call(node)
        assert result == "a"

    def test_chr_boundary_zero(self) -> None:
        node = _parse_call("chr(0)")
        result = _resolve_chr_call(node)
        assert result == "\x00"

    def test_chr_boundary_max(self) -> None:
        node = _parse_call("chr(0x10FFFF)")
        result = _resolve_chr_call(node)
        assert result == chr(0x10FFFF)

    def test_chr_out_of_range_returns_none(self) -> None:
        node = _parse_call("chr(0x110000)")
        assert _resolve_chr_call(node) is None

    def test_chr_negative_returns_none(self) -> None:
        node = _parse_call("chr(-1)")
        assert _resolve_chr_call(node) is None


class TestChrOrdGuards:
    """R-IMP003: Non-constant arguments return None without error."""

    def test_chr_non_call_returns_none(self) -> None:
        node = _parse_call("len([1, 2])")
        assert _resolve_chr_call(node) is None

    def test_chr_no_args_returns_none(self) -> None:
        node = _parse_call("chr()")
        assert _resolve_chr_call(node) is None

    def test_chr_with_keyword_returns_none(self) -> None:
        node = _parse_call("chr(x=101)")
        assert _resolve_chr_call(node) is None

    def test_ord_multi_char_returns_none(self) -> None:
        node = _parse_call("ord('ab')")
        assert _resolve_ord_call(node) is None

    def test_ord_non_string_returns_none(self) -> None:
        node = _parse_call("ord(42)")
        assert _resolve_ord_call(node) is None

    def test_ord_variable_returns_none(self) -> None:
        """R-IMP003: ord(variable) returns None without error."""
        node = _parse_call("ord(x)")
        assert _resolve_ord_call(node) is None

    def test_chr_variable_returns_none(self) -> None:
        """R-IMP003: chr(variable) returns None without error."""
        node = _parse_call("chr(x)")
        assert _resolve_chr_arg(node.args[0]) is None

    def test_int_arg_non_binop_non_const_returns_none(self) -> None:
        """Non-constant, non-call, non-binop returns None."""
        node = ast.parse("x", mode="eval").body
        assert _resolve_int_arg(node) is None


# -- chr(ord()) concatenation (full path) --------------------------------------


class TestChrOrdConcatDetection:
    """R004: chr(ord()) nesting reconstructs dangerous names via concatenation."""

    def test_chr_ord_eval_produces_exec002(self) -> None:
        code = '_result = chr(ord("e")) + chr(ord("v")) + chr(ord("a")) + chr(ord("l"))'
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_chr_ord_padded_eval_produces_exec002(self) -> None:
        """R-EFF006: chr(ord('e') + 0) padding resistance."""
        code = '_result = chr(ord("e") + 0) + chr(ord("v") + 0) + chr(ord("a") + 0) + chr(ord("l") + 0)'
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_chr_ord_exec006_import(self) -> None:
        """chr(ord()) building __import__ should produce EXEC-006."""
        parts = " + ".join(f'chr(ord("{c}"))' for c in "__import__")
        code = f"_result = {parts}"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-006"

    def test_chr_ord_safe_no_finding(self) -> None:
        """chr(ord()) building non-dangerous string produces no finding."""
        code = '_result = chr(ord("h")) + chr(ord("i"))'
        assert len(_detect(code)) == 0


# -- Full path acceptance (analyze_python) -------------------------------------


class TestReversedChrOrdAcceptance:
    """Plan-level acceptance scenarios for reversed() and chr(ord()) features."""

    def test_reversed_join_full_pipeline(self) -> None:
        """R003: ''.join(reversed('lave')) detected via analyze_python."""
        code = "x = ''.join(reversed('lave'))"
        findings = analyze_python(code, _FILE)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1
        assert any("eval" in f.description for f in exec_findings)

    def test_chr_ord_full_pipeline(self) -> None:
        """R004: chr(ord()) concatenation detected via analyze_python."""
        code = textwrap.dedent("""\
            _result = chr(ord("e")) + chr(ord("v")) + chr(ord("a")) + chr(ord("l"))
        """)
        findings = analyze_python(code, _FILE)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1
        assert any("eval" in f.description for f in exec_findings)

    def test_chr_ord_padded_full_pipeline(self) -> None:
        """R-EFF006: chr(ord('e') + 0) detected via analyze_python."""
        code = textwrap.dedent("""\
            _result = chr(ord("e") + 0) + chr(ord("v") + 0) + chr(ord("a") + 0) + chr(ord("l") + 0)
        """)
        findings = analyze_python(code, _FILE)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1

    def test_reversed_list_full_pipeline(self) -> None:
        """R003: ''.join(reversed([...])) detected via analyze_python."""
        code = "x = ''.join(reversed(['l', 'a', 'v', 'e']))"
        findings = analyze_python(code, _FILE)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1

    def test_safe_reversed_no_false_positive(self) -> None:
        """R-IMP002: reversed() on safe strings produces no dangerous findings."""
        code = "x = ''.join(reversed('olleh'))"
        findings = analyze_python(code, _FILE)
        dangerous = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert len(dangerous) == 0
