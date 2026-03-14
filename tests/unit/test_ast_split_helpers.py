"""Tests for AST split helpers -- str.format() and %-format resolution.

Covers _resolve_format_call(), _resolve_percent_format(), and acceptance
scenarios for end-to-end format/percent evasion detection through analyze_python.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from skill_scan._ast_split_detector import detect_split_evasion
from skill_scan._ast_split_helpers import (
    _scoped_lookup,
)
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.ast_analyzer import analyze_python
from skill_scan.decoder import _decode_unicode_escape
from skill_scan.models import Finding

_PARSE = ast.parse
_FILE = "test.py"


def _detect(code: str) -> list[Finding]:
    """Helper: parse code, build symbol table, run split detector."""
    tree = _PARSE(code)
    st = build_symbol_table(tree)
    return detect_split_evasion(tree, _FILE, {}, st)


# -- R004: str.format() evasion -----------------------------------------------


class TestFormatCall:
    def test_format_auto_numbering_eval(self) -> None:
        findings = _detect("a = 'ev'\nb = 'al'\nresult = '{}{}'.format(a, b)")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"
        assert "eval" in findings[0].matched_text

    def test_format_explicit_numbering_exec(self) -> None:
        findings = _detect("x = 'ex'\ny = 'ec'\ncmd = '{0}{1}'.format(x, y)")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"
        assert "exec" in findings[0].matched_text

    def test_format_import_evasion_exec006(self) -> None:
        findings = _detect("a = '__im'\nb = 'port__'\nc = '{}{}'.format(a, b)")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-006"

    def test_format_safe_pattern_no_finding(self) -> None:
        assert len(_detect("a = 'hello'\nb = 'world'\nc = '{}{}'.format(a, b)")) == 0

    def test_format_variable_receiver_no_finding(self) -> None:
        """R-IMP008: variable.format() must NOT trigger (not a string constant receiver)."""
        assert len(_detect("x = 'ev{}'\nx.format('al')")) == 0

    def test_format_with_keyword_args_no_finding(self) -> None:
        assert len(_detect("'{name}'.format(name='eval')")) == 0

    def test_format_unresolvable_arg_no_finding(self) -> None:
        assert len(_detect("a = 'ev'\nc = '{}{}'.format(a, unknown)")) == 0

    def test_format_with_constant_arg(self) -> None:
        findings = _detect("a = 'ev'\nc = '{}{}'.format(a, 'al')")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_format_three_parts_system(self) -> None:
        findings = _detect("a = 'sy'\nb = 'st'\nc = 'em'\nd = '{}{}{}'.format(a, b, c)")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"
        assert "system" in findings[0].matched_text


# -- R005: %-format evasion ---------------------------------------------------


class TestPercentFormat:
    def test_percent_two_vars_eval(self) -> None:
        findings = _detect("a = 'ev'\nb = 'al'\nresult = '%s%s' % (a, b)")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"
        assert "eval" in findings[0].matched_text

    def test_percent_two_vars_exec(self) -> None:
        findings = _detect("x = 'ex'\ny = 'ec'\ncmd = '%s%s' % (x, y)")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"
        assert "exec" in findings[0].matched_text

    def test_percent_import_evasion_exec006(self) -> None:
        findings = _detect("a = '__im'\nb = 'port__'\nc = '%s%s' % (a, b)")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-006"

    def test_percent_integer_modulo_no_finding(self) -> None:
        """R-IMP009: integer modulo must NOT produce findings."""
        assert len(_detect("result = 10 % 3")) == 0

    def test_percent_safe_strings_no_finding(self) -> None:
        assert len(_detect("a = 'hello'\nb = 'world'\nc = '%s %s' % (a, b)")) == 0

    def test_percent_unresolvable_tuple_no_finding(self) -> None:
        assert len(_detect("a = 'ev'\nc = '%s%s' % (a, unknown)")) == 0

    def test_percent_single_arg(self) -> None:
        findings = _detect("a = 'eval'\nc = '%s' % a")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_percent_with_constant_element(self) -> None:
        findings = _detect("a = 'ev'\nc = '%s%s' % (a, 'al')")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_percent_mismatch_count_no_finding(self) -> None:
        """More placeholders than args -> no finding."""
        assert len(_detect("a = 'ev'\nc = '%s%s%s' % (a, 'al')")) == 0


# -- Negative fixtures --------------------------------------------------------


class TestNegativeFixtures:
    _FIXTURE_DIR = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "split_evasion"

    @pytest.mark.parametrize(
        "fixture",
        sorted(
            (pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "split_evasion").glob("neg_*.py"),
        ),
        ids=lambda p: p.stem,
    )
    def test_negative_fixture_zero_findings(self, fixture: pathlib.Path) -> None:
        code = fixture.read_text()
        findings = _detect(code)
        assert len(findings) == 0, f"{fixture.name} produced {len(findings)} findings"


# -- Positive fixtures for format/percent -------------------------------------


class TestPositiveFixtures:
    _FIXTURE_DIR = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "split_evasion"

    def test_pos_format_eval_detected(self) -> None:
        code = (self._FIXTURE_DIR / "pos_format_eval.py").read_text()
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_pos_format_exec_detected(self) -> None:
        code = (self._FIXTURE_DIR / "pos_format_exec.py").read_text()
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_pos_percent_eval_detected(self) -> None:
        code = (self._FIXTURE_DIR / "pos_percent_eval.py").read_text()
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_pos_percent_exec_detected(self) -> None:
        code = (self._FIXTURE_DIR / "pos_percent_exec.py").read_text()
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"


# -- File size constraints ----------------------------------------------------


class TestFileSizeConstraints:
    def test_split_helpers_under_250_lines(self) -> None:
        src = pathlib.Path(__file__).resolve().parent.parent.parent
        target = src / "src" / "skill_scan" / "_ast_split_helpers.py"
        line_count = len(target.read_text().splitlines())
        assert line_count <= 300, f"_ast_split_helpers.py is {line_count} lines (max 300)"


# -- Acceptance scenarios (plan-level) ----------------------------------------


class TestAcceptanceScenarios:
    def test_surrogate_unicode_escape_sanitized(self) -> None:
        """Surrogate-laden unicode-escape payload is sanitized for downstream matching."""
        text = r"\uD800\u0065\u0076\u0061\u006C"
        decoded = _decode_unicode_escape(text)
        assert "eval" in decoded
        assert not any(0xD800 <= ord(c) <= 0xDFFF for c in decoded)

    def test_format_evasion_e2e_analyze_python(self) -> None:
        """str.format() evasion detected end-to-end through analyze_python."""
        source = "a = 'ev'\nb = 'al'\nresult = '{}{}'.format(a, b)"
        findings = analyze_python(source, "test.py")
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1
        assert "eval" in exec002[0].matched_text

    def test_percent_evasion_e2e_analyze_python(self) -> None:
        """%-format evasion detected end-to-end through analyze_python."""
        source = "x = 'ex'\ny = 'ec'\ncmd = '%s%s' % (x, y)"
        findings = analyze_python(source, "test.py")
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1
        assert "exec" in exec002[0].matched_text


# -- _scoped_lookup (moved to _ast_split_helpers) -----------------------------


class TestScopedLookup:
    def test_module_scope_lookup(self) -> None:
        assert _scoped_lookup("x", {"x": "val"}, "") == "val"

    def test_function_scope_lookup(self) -> None:
        assert _scoped_lookup("x", {"func.x": "scoped"}, "func") == "scoped"

    def test_function_scope_shadows_module(self) -> None:
        st = {"x": "module", "func.x": "scoped"}
        assert _scoped_lookup("x", st, "func") == "scoped"

    def test_fallback_to_module_scope(self) -> None:
        assert _scoped_lookup("x", {"x": "module"}, "func") == "module"

    def test_missing_returns_none(self) -> None:
        assert _scoped_lookup("x", {}, "func") is None
