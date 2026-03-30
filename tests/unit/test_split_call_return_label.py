"""Tests for call-return label accuracy in split resolvers.

Validates that BinOp, f-string, and mixed-leaf expressions containing
call-return resolved leaves produce findings with "call-return evasion"
in matched_text, while plain string splits produce "split variable evasion".

Covers: R001, R003, R-IMP001, R-IMP002 from PLAN-037.
"""

from __future__ import annotations

import ast

from skill_scan._ast_split_detector import detect_split_evasion
from skill_scan._ast_split_resolve import resolve_call
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.models import Finding

_PARSE = ast.parse
_FILE = "test.py"


def _detect(code: str) -> list[Finding]:
    """Helper: parse code, build symbol table, run split detector."""
    tree = _PARSE(code)
    st = build_symbol_table(tree)
    return detect_split_evasion(tree, _FILE, {}, st)


# -- Call-return label tests --


class TestBinOpCallReturnLabel:
    """BinOp a()+b() where both functions have tracked call-return values."""

    def test_both_call_return_yields_call_return_label(self) -> None:
        """BinOp of two call-return functions must produce 'call-return evasion' via EXEC-002."""
        code = "def a(): return 'ex'\ndef b(): return 'ec'\nx = a() + b()"
        findings = _detect(code)
        assert len(findings) == 1
        assert "call-return evasion" in findings[0].matched_text
        assert findings[0].rule_id == "EXEC-002"


class TestFstringCallReturnLabel:
    """f-string f'{a()}{b()}' where both functions have tracked call-return values."""

    def test_fstring_call_return_yields_call_return_label(self) -> None:
        """f-string with call-return values must produce 'call-return evasion' via EXEC-002."""
        code = "def a(): return 'ex'\ndef b(): return 'ec'\nx = f'{a()}{b()}'"
        findings = _detect(code)
        assert len(findings) == 1
        assert "call-return evasion" in findings[0].matched_text
        assert findings[0].rule_id == "EXEC-002"


class TestResolveCallDirect:
    """Direct invocation of resolve_call on a tracked function."""

    def test_resolve_call_returns_call_return_tuple(self) -> None:
        """resolve_call on a symbol-table-tracked function returns ('value', 'call-return')."""
        code = "def func(): return 'exec'"
        tree = _PARSE(code)
        st = build_symbol_table(tree)
        # Get the Call node for func()
        call_code = _PARSE("func()")
        call_node = call_code.body[0].value  # type: ignore[attr-defined]
        result = resolve_call(call_node, st, "")
        assert result == ("exec", "call-return")

    def test_resolve_call_unknown_returns_none(self) -> None:
        """resolve_call on an unknown function returns None."""
        call_node = _PARSE("unknown()").body[0].value  # type: ignore[attr-defined]
        result = resolve_call(call_node, {}, "")
        assert result is None


class TestNegativePlainStringSplit:
    """Plain string split 'ex'+'ec' with no call-return involvement."""

    def test_plain_binop_yields_split_variable_label(self) -> None:
        """String concat via variables yields 'split variable evasion', not 'call-return'."""
        code = "a = 'ex'\nb = 'ec'\nx = a + b"
        findings = _detect(code)
        assert len(findings) == 1
        assert "split variable evasion" in findings[0].matched_text
        assert "call-return" not in findings[0].matched_text


class TestMixedLeafCallReturn:
    """Mixed-leaf: a()+'ec' where only one operand is call-return."""

    def test_one_call_return_leaf_yields_call_return_label(self) -> None:
        """Any leaf being call-return makes the whole expression 'call-return evasion'."""
        code = "def a(): return 'ex'\nb = 'ec'\nx = a() + b"
        findings = _detect(code)
        assert len(findings) == 1
        assert "call-return evasion" in findings[0].matched_text

    def test_mixed_leaf_right_side_call_return(self) -> None:
        """Call-return on right operand also yields 'call-return evasion'."""
        code = "a = 'ex'\ndef b(): return 'ec'\nx = a + b()"
        findings = _detect(code)
        assert len(findings) == 1
        assert "call-return evasion" in findings[0].matched_text
