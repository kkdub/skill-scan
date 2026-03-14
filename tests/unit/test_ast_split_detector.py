"""Tests for AST split detector -- concatenation, f-string, and join reconstruction.

Covers detect_split_evasion() with all three reconstruction methods,
dangerous name checks, safe patterns, partial resolution, and edge cases.
"""

from __future__ import annotations

import ast

import pytest

from skill_scan._ast_split_detector import (
    _DYNAMIC_IMPORT_NAMES,
    _EXEC_NAMES,
    detect_split_evasion,
)
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.models import Finding, Severity

_PARSE = ast.parse
_FILE = "test.py"


def _detect(code: str) -> list[Finding]:
    """Helper: parse code, build symbol table, run split detector."""
    tree = _PARSE(code)
    st = build_symbol_table(tree)
    return detect_split_evasion(tree, _FILE, {}, st)


# -- R002: Binary string concatenation --------------------------------------


class TestConcatenation:
    def test_two_var_concat_produces_exec002(self) -> None:
        findings = _detect("a = 'ev'\nb = 'al'\nc = a + b")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"
        assert "eval" in findings[0].description

    def test_three_var_concat_produces_exec002(self) -> None:
        findings = _detect("a = 'e'\nb = 'va'\nc = 'l'\nd = a + b + c")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_concat_with_string_literal_operand(self) -> None:
        findings = _detect("a = 'ev'\nc = a + 'al'")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_safe_concat_no_finding(self) -> None:
        assert len(_detect("a = 'hello'\nb = 'world'\nc = a + b")) == 0

    def test_partial_resolution_no_finding(self) -> None:
        """One operand not in symbol table -> no finding (R-IMP006)."""
        assert len(_detect("a = 'ev'\nc = a + b")) == 0


# -- R003: F-string reconstruction -------------------------------------------


class TestFString:
    def test_fstring_two_vars_produces_exec002(self) -> None:
        findings = _detect("a = 'ev'\nb = 'al'\nc = f'{a}{b}'")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_fstring_three_vars_produces_exec002(self) -> None:
        findings = _detect("a = 'e'\nb = 'va'\nc = 'l'\nd = f'{a}{b}{c}'")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    @pytest.mark.parametrize("fmt", ["f'{a!s}{b!s}'", "f'{a!r}{b!r}'", "f'{a:>2}{b:<2}'"])
    def test_fstring_conversion_and_format_spec(self, fmt: str) -> None:
        findings = _detect(f"a = 'ev'\nb = 'al'\nc = {fmt}")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_fstring_unresolvable_no_finding(self) -> None:
        assert len(_detect("a = 'ev'\nc = f'{a}{unknown}'")) == 0

    def test_fstring_safe_pattern_no_finding(self) -> None:
        assert len(_detect("name = 'Alice'\nmsg = f'Hello {name}'")) == 0


# -- R004: Join reconstruction -----------------------------------------------


class TestJoin:
    def test_join_two_vars_produces_exec002(self) -> None:
        findings = _detect("a = 'ev'\nb = 'al'\nc = ''.join([a, b])")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_join_with_separator_safe(self) -> None:
        assert len(_detect("a = 'ev'\nb = 'al'\nc = '.'.join([a, b])")) == 0

    def test_join_unresolvable_element_no_finding(self) -> None:
        assert len(_detect("a = 'ev'\nc = ''.join([a, unknown])")) == 0

    def test_join_three_vars_produces_exec002(self) -> None:
        findings = _detect("a = 'e'\nb = 'va'\nc = 'l'\nd = ''.join([a, b, c])")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_join_with_constant_element(self) -> None:
        findings = _detect("a = 'ev'\nc = ''.join([a, 'al'])")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_join_tuple_works(self) -> None:
        findings = _detect("a = 'ev'\nb = 'al'\nc = ''.join((a, b))")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"


# -- EXEC-006: Dynamic import evasion ----------------------------------------


class TestExec006:
    def test_import_evasion_concat(self) -> None:
        findings = _detect("a = '__im'\nb = 'port__'\nc = a + b")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-006"
        assert findings[0].severity == Severity.HIGH

    def test_getattr_evasion_concat(self) -> None:
        findings = _detect("a = 'get'\nb = 'attr'\nc = a + b")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-006"

    def test_exec006_via_fstring(self) -> None:
        findings = _detect("a = '__im'\nb = 'port__'\nc = f'{a}{b}'")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-006"

    def test_exec006_via_join(self) -> None:
        findings = _detect("a = '__im'\nb = 'port__'\nc = ''.join([a, b])")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-006"


# -- R-IMP004: Safe patterns produce no findings -----------------------------


class TestSafePatterns:
    def test_config_assignment_no_finding(self) -> None:
        assert len(_detect("host = 'localhost'\nport = '8080'\nurl = host + port")) == 0

    def test_log_message_no_finding(self) -> None:
        assert len(_detect("prefix = 'INFO'\nmsg = 'done'\nlog = f'{prefix}: {msg}'")) == 0

    def test_path_construction_no_finding(self) -> None:
        assert len(_detect("base = '/home'\ndir = '/user'\npath = base + dir")) == 0


# -- Dangerous name coverage -------------------------------------------------


class TestDangerousNames:
    @pytest.mark.parametrize("name", sorted(_EXEC_NAMES), ids=sorted(_EXEC_NAMES))
    def test_exec_names_produce_exec002(self, name: str) -> None:
        mid = max(len(name) // 2, 1)
        code = f"a = {name[:mid]!r}\nb = {name[mid:]!r}\nc = a + b"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    @pytest.mark.parametrize("name", sorted(_DYNAMIC_IMPORT_NAMES), ids=sorted(_DYNAMIC_IMPORT_NAMES))
    def test_dynamic_import_names_produce_exec006(self, name: str) -> None:
        mid = max(len(name) // 2, 1)
        code = f"a = {name[:mid]!r}\nb = {name[mid:]!r}\nc = a + b"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-006"


# -- Finding attributes -------------------------------------------------------


class TestFindingAttributes:
    def test_finding_category_and_file(self) -> None:
        findings = _detect("a = 'ev'\nb = 'al'\nc = a + b")
        assert findings[0].category == "malicious-code"
        assert findings[0].file == _FILE

    def test_finding_has_line_number(self) -> None:
        findings = _detect("a = 'ev'\nb = 'al'\nc = a + b")
        assert findings[0].line is not None and findings[0].line > 0

    def test_finding_has_recommendation(self) -> None:
        findings = _detect("a = 'ev'\nb = 'al'\nc = a + b")
        assert findings[0].recommendation != ""

    def test_exec002_severity_critical(self) -> None:
        findings = _detect("a = 'ev'\nb = 'al'\nc = a + b")
        assert findings[0].severity == Severity.CRITICAL

    def test_exec006_severity_high(self) -> None:
        findings = _detect("a = '__im'\nb = 'port__'\nc = a + b")
        assert findings[0].severity == Severity.HIGH


# -- API and edge cases -------------------------------------------------------


class TestAPIAndEdgeCases:
    def test_signature_accepts_documented_params(self) -> None:
        result = detect_split_evasion(_PARSE(""), "f.py", {}, {})
        assert isinstance(result, list)

    def test_empty_symbol_table_no_findings(self) -> None:
        assert detect_split_evasion(_PARSE("c = a + b"), "f.py", {}, {}) == []

    def test_empty_tree_no_findings(self) -> None:
        assert detect_split_evasion(_PARSE(""), "f.py", {}, {"a": "ev"}) == []

    def test_non_string_join_ignored(self) -> None:
        tree = _PARSE("x.join([a, b])")
        assert len(detect_split_evasion(tree, _FILE, {}, {"a": "ev", "b": "al"})) == 0

    def test_join_no_args_ignored(self) -> None:
        tree = _PARSE("''.join()")
        assert len(detect_split_evasion(tree, _FILE, {}, {})) == 0

    def test_join_multiple_args_ignored(self) -> None:
        tree = _PARSE("''.join([a], extra)")
        assert len(detect_split_evasion(tree, _FILE, {}, {"a": "eval"})) == 0


# -- Call-return resolution ---------------------------------------------------


class TestCallReturn:
    def test_inline_call_concat_produces_exec002(self) -> None:
        code = "def a(): return 'ex'\ndef b(): return 'ec'\nresult = a() + b()"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"
        assert "exec" in findings[0].description

    def test_call_assign_then_concat_produces_exec002(self) -> None:
        code = "def f(): return 'ev'\ndef g(): return 'al'\nx = f()\ny = g()\nresult = x + y"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_fstring_with_call_return(self) -> None:
        code = "def a(): return 'sys'\ndef b(): return 'tem'\ncmd = f'{a()}{b()}'"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"
        assert "system" in findings[0].description

    def test_class_method_self_call_concat(self) -> None:
        code = (
            "class X:\n"
            "    def p(self): return 'po'\n"
            "    def s(self): return 'pen'\n"
            "    def r(self):\n"
            "        cmd = self.p() + self.s()\n"
        )
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_unknown_call_returns_none(self) -> None:
        code = "result = unknown_func() + other_func()"
        assert len(_detect(code)) == 0

    def test_safe_call_concat_no_finding(self) -> None:
        code = "def a(): return 'hello'\ndef b(): return 'world'\nresult = a() + b()"
        assert len(_detect(code)) == 0

    def test_divergent_return_no_finding(self) -> None:
        code = (
            "import random\n"
            "def f():\n"
            "    if random.random() > 0.5:\n"
            "        return 'ev'\n"
            "    else:\n"
            "        return 'xx'\n"
            "def g(): return 'al'\n"
            "result = f() + g()\n"
        )
        assert len(_detect(code)) == 0


# -- R-IMP003: File size constraint -------------------------------------------


class TestFileSizeConstraint:
    def test_source_file_under_300_lines(self) -> None:
        import pathlib

        src = pathlib.Path(__file__).resolve().parent.parent.parent
        target = src / "src" / "skill_scan" / "_ast_split_detector.py"
        line_count = len(target.read_text().splitlines())
        assert line_count <= 300, f"_ast_split_detector.py is {line_count} lines (max 300)"
