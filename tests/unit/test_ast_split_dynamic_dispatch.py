"""Tests for dynamic dispatch detection via introspection subscript chains.

Covers globals()['eval'], vars(obj)['eval'], obj.__dict__['eval'],
two-level chaining, tracked variable keys, and safe non-dangerous keys.
"""

from __future__ import annotations

import ast
import textwrap

import pytest

from skill_scan._ast_split_detector import (
    detect_split_evasion,
)
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.models import Finding

_PARSE = ast.parse
_FILE = "test.py"


def _detect(code: str) -> list[Finding]:
    """Helper: parse code, build symbol table, run split detector."""
    tree = _PARSE(code)
    st = build_symbol_table(tree)
    return detect_split_evasion(tree, _FILE, {}, st)


# -- R006: Dynamic dispatch via introspection subscript -----------------------


class TestGlobalsSubscript:
    """globals()['name'] pattern detection."""

    def test_globals_eval_produces_exec002(self) -> None:
        findings = _detect("globals()['eval']('1+1')")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"
        assert "eval" in findings[0].matched_text

    def test_globals_exec_produces_exec002(self) -> None:
        findings = _detect("globals()['exec']('pass')")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_globals_system_produces_exec002(self) -> None:
        findings = _detect("globals()['system']('ls')")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_globals_import_produces_exec006(self) -> None:
        findings = _detect("globals()['__import__']('os')")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-006"

    def test_globals_getattr_produces_exec006(self) -> None:
        findings = _detect("globals()['getattr'](obj, 'x')")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-006"

    def test_globals_safe_key_no_finding(self) -> None:
        findings = _detect("globals()['safe_name']")
        assert len(findings) == 0

    def test_globals_non_string_key_no_finding(self) -> None:
        findings = _detect("globals()[42]")
        assert len(findings) == 0


class TestLocalsSubscript:
    """locals()['name'] pattern detection."""

    def test_locals_eval_produces_exec002(self) -> None:
        findings = _detect("locals()['eval']('1+1')")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_locals_safe_key_no_finding(self) -> None:
        findings = _detect("locals()['my_var']")
        assert len(findings) == 0


class TestVarsSubscript:
    """vars(obj)['name'] pattern detection."""

    def test_vars_eval_produces_exec002(self) -> None:
        findings = _detect("import builtins\nvars(builtins)['eval']")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_vars_system_produces_exec002(self) -> None:
        findings = _detect("vars(obj)['system']")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_vars_safe_key_no_finding(self) -> None:
        findings = _detect("vars(obj)['counter']")
        assert len(findings) == 0


class TestDictAttrSubscript:
    """obj.__dict__['name'] pattern detection."""

    def test_dict_attr_eval_produces_exec002(self) -> None:
        findings = _detect("obj.__dict__['eval']")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_dict_attr_system_produces_exec002(self) -> None:
        findings = _detect("import os\nos.__dict__['system']('ls')")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_dict_attr_popen_produces_exec002(self) -> None:
        findings = _detect("mod.__dict__['popen']('cmd')")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_dict_attr_safe_key_no_finding(self) -> None:
        findings = _detect("obj.__dict__['safe_attr']")
        assert len(findings) == 0


# -- R-EFF005: Two-level subscript chaining -----------------------------------


class TestTwoLevelChaining:
    """globals()['__builtins__']['eval'] pattern detection."""

    def test_two_level_globals_eval_detected(self) -> None:
        findings = _detect("globals()['__builtins__']['eval']('1+1')")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"
        assert "eval" in findings[0].matched_text

    def test_two_level_globals_exec_detected(self) -> None:
        findings = _detect("globals()['__builtins__']['exec']('pass')")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_two_level_globals_import_produces_exec006(self) -> None:
        findings = _detect("globals()['__builtins__']['__import__']('os')")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-006"

    def test_two_level_dangerous_inner_key_produces_finding(self) -> None:
        """Two-level chain: globals() base with dangerous inner key 'eval' triggers."""
        findings = _detect("globals()['safe']['eval']")
        # globals()['safe'] is still a globals()-based subscript, so the
        # outer subscript globals()['safe']['eval'] detects 'eval' as dangerous.
        assert len(findings) >= 1

    def test_two_level_safe_inner_key_no_finding(self) -> None:
        """Two-level chain with safe inner key does not trigger."""
        findings = _detect("globals()['__builtins__']['safe_func']")
        assert len(findings) == 0


# -- R-IMP005: Tracked variable keys -----------------------------------------


class TestTrackedVariableKeys:
    """Subscript key resolved from tracked variable in symbol table."""

    def test_tracked_variable_key_eval(self) -> None:
        code = textwrap.dedent("""\
            name = "eval"
            globals()[name]('1+1')
        """)
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_tracked_variable_key_safe(self) -> None:
        code = textwrap.dedent("""\
            name = "safe_func"
            globals()[name]
        """)
        findings = _detect(code)
        assert len(findings) == 0

    def test_untracked_variable_key_no_finding(self) -> None:
        """Variable not in symbol table -> key is None -> no finding."""
        findings = _detect("globals()[unknown_var]")
        assert len(findings) == 0


# -- R009: Correct rule ID per _NAME_RULE ------------------------------------


class TestRuleIdConsistency:
    """All dangerous names produce correct rule IDs via _NAME_RULE."""

    @pytest.mark.parametrize(
        "name",
        ["eval", "exec", "system", "popen"],
    )
    def test_exec_names_produce_exec002(self, name: str) -> None:
        findings = _detect(f"globals()['{name}']")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    @pytest.mark.parametrize(
        "name",
        ["__import__", "getattr"],
    )
    def test_import_names_produce_exec006(self, name: str) -> None:
        findings = _detect(f"globals()['{name}']")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-006"
