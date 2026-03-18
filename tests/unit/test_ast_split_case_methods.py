"""Tests for AST split detector -- call-return resolution, case methods, file size.

Moved from test_ast_split_detector.py to keep files under the 300-line limit.
"""

from __future__ import annotations

import ast

from skill_scan._ast_split_detector import detect_split_evasion
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.models import Finding

_PARSE = ast.parse
_FILE = "test.py"


def _detect(code: str) -> list[Finding]:
    """Helper: parse code, build symbol table, run split detector."""
    tree = _PARSE(code)
    st = build_symbol_table(tree)
    return detect_split_evasion(tree, _FILE, {}, st)


# -- Join/format call-return resolution (PR #36 fix) --------------------------


class TestJoinFormatCallReturn:
    def test_join_with_call_return_args(self) -> None:
        """''.join([get_a(), get_b()]) resolves call returns."""
        code = "def a(): return 'ev'\ndef b(): return 'al'\nresult = ''.join([a(), b()])"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"
        assert "eval" in findings[0].description

    def test_format_with_call_return_args(self) -> None:
        """'{}{}'.format(get_a(), get_b()) resolves call returns."""
        code = "def a(): return 'ev'\ndef b(): return 'al'\nresult = '{}{}'.format(a(), b())"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_percent_format_with_call_return_args(self) -> None:
        """'%s%s' % (get_a(), get_b()) resolves call returns."""
        code = "def a(): return 'ev'\ndef b(): return 'al'\nresult = '%s%s' % (a(), b())"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"


# -- R001: String case method resolution --------------------------------------


class TestCaseMethodResolution:
    def test_lower_resolves_to_exec002(self) -> None:
        """'EVAL'.lower() resolves to 'eval' and triggers EXEC-002."""
        findings = _detect("x = 'EVAL'.lower()")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"
        assert "eval" in findings[0].description

    def test_upper_then_lower_resolves(self) -> None:
        """'EVAL'.upper().lower() resolves to 'eval' and triggers EXEC-002."""
        findings = _detect("x = 'EVAL'.upper().lower()")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_tracked_var_lower(self) -> None:
        """Tracked variable base resolves through .lower()."""
        findings = _detect("name = 'EVAL'\nx = name.lower()")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_chained_case_methods(self) -> None:
        """Chained methods: 'EVAL'.lower().upper() -> 'EVAL'."""
        findings = _detect("x = 'EVAL'.lower().upper()")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_casefold_resolves(self) -> None:
        """'EVAL'.casefold() resolves to 'eval'."""
        findings = _detect("x = 'EVAL'.casefold()")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_exec_lower_call_detected(self) -> None:
        """exec('EVAL'.lower()) triggers detection."""
        findings = _detect("exec('EVAL'.lower())")
        assert len(findings) >= 1

    def test_swapcase_resolves(self) -> None:
        """'EVAL'.swapcase() resolves to 'eval' and triggers EXEC-002."""
        findings = _detect("x = 'EVAL'.swapcase()")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_safe_case_method_no_finding(self) -> None:
        """Safe string case method produces no finding."""
        assert len(_detect("x = 'HELLO'.lower()")) == 0

    def test_globals_case_evasion(self) -> None:
        """Red-team pattern: globals()['EVAL'.lower()] detected."""
        findings = _detect("name = 'EVAL'.lower()\nglobals()[name]('print(1)')")
        assert len(findings) >= 1

    def test_binop_base_with_lower(self) -> None:
        """('EV' + 'AL').lower() resolves BinOp base through case method."""
        findings = _detect("x = ('EV' + 'AL').lower()")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_replace_base_with_lower(self) -> None:
        """'XVAL'.replace('X', 'E').lower() resolves replace chain base."""
        findings = _detect("x = 'XVAL'.replace('X', 'E').lower()")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_join_base_with_lower(self) -> None:
        """''.join(['EV', 'AL']).lower() resolves join base through case method."""
        findings = _detect("x = ''.join(['EV', 'AL']).lower()")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_fstring_base_with_lower(self) -> None:
        """f'{a}{b}'.lower() resolves f-string base through case method."""
        findings = _detect("a = 'EV'\nb = 'AL'\nx = f'{a}{b}'.lower()")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"


# -- R-IMP003: File size constraint -------------------------------------------


class TestFileSizeConstraint:
    def test_source_file_under_300_lines(self) -> None:
        import pathlib

        src = pathlib.Path(__file__).resolve().parent.parent.parent
        target = src / "src" / "skill_scan" / "_ast_split_detector.py"
        line_count = len(target.read_text().splitlines())
        assert line_count <= 300, f"_ast_split_detector.py is {line_count} lines (max 300)"
