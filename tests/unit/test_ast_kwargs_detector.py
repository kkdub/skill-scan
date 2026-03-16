"""Tests for kwargs unpacking detection via _ast_kwargs_detector.

Covers detect_kwargs_unpacking for inline dict literals, symbol-table-tracked
dicts (subscript and literal init), aliased imports, and safe-case negatives.
"""

from __future__ import annotations

import ast
import textwrap

from skill_scan._ast_kwargs_detector import (
    _DANGEROUS_KWARGS,
    detect_kwargs_unpacking,
)
from skill_scan._ast_helpers import build_alias_map
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.ast_analyzer import analyze_python
from skill_scan.models import Finding, Severity

_PARSE = ast.parse
_FILE = "test.py"


def _detect(code: str) -> list[Finding]:
    """Helper: parse code, build symbol table, run kwargs detector."""
    tree = _PARSE(textwrap.dedent(code))
    alias_map = build_alias_map(tree)
    st = build_symbol_table(tree)
    return detect_kwargs_unpacking(tree, _FILE, alias_map, st)


def _detect_full(code: str) -> list[Finding]:
    """Helper: run full analyze_python pipeline."""
    return analyze_python(textwrap.dedent(code), _FILE)


# ---------------------------------------------------------------------------
# R006: Table structure
# ---------------------------------------------------------------------------


class TestDangerousKwargsTable:
    """_DANGEROUS_KWARGS is table-driven, not if/else logic."""

    def test_table_is_dict(self) -> None:
        assert isinstance(_DANGEROUS_KWARGS, dict)

    def test_subprocess_prefix_exists(self) -> None:
        assert "subprocess." in _DANGEROUS_KWARGS

    def test_subprocess_shell_true_entry(self) -> None:
        entries = _DANGEROUS_KWARGS["subprocess."]
        assert len(entries) >= 1
        key, value, rule_id, severity, _ = entries[0]
        assert key == "shell"
        assert value is True
        assert rule_id == "EXEC-002"
        assert severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# R002: Inline dict literal unpacking
# ---------------------------------------------------------------------------


class TestInlineDictLiteral:
    """subprocess.run(**{'shell': True}) detection."""

    def test_inline_dict_shell_true_detected(self) -> None:
        code = "import subprocess; subprocess.run(['ls'], **{'shell': True})"
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"
        assert findings[0].severity == Severity.CRITICAL
        assert "shell" in findings[0].matched_text

    def test_inline_dict_call_method_detected(self) -> None:
        code = "import subprocess; subprocess.call(['ls'], **{'shell': True})"
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_inline_dict_popen_detected(self) -> None:
        code = "import subprocess; subprocess.Popen(['ls'], **{'shell': True})"
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"


# ---------------------------------------------------------------------------
# R001/R003: Symbol-table-tracked dict (subscript assignment)
# ---------------------------------------------------------------------------


class TestSymbolTableTrackedDict:
    """subprocess.run(**opts) where opts built via subscript or literal init."""

    def test_subscript_assignment_shell_true(self) -> None:
        code = """\
        import subprocess
        opts = {}
        opts['shell'] = True
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"
        assert findings[0].severity == Severity.CRITICAL

    def test_dict_literal_init_shell_true(self) -> None:
        code = """\
        import subprocess
        opts = {'shell': True}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_dict_with_multiple_keys(self) -> None:
        code = """\
        import subprocess
        opts = {}
        opts['stdout'] = -1
        opts['shell'] = True
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"


# ---------------------------------------------------------------------------
# R008: Aliased imports
# ---------------------------------------------------------------------------


class TestAliasedImports:
    """Detection works with import subprocess as sp."""

    def test_alias_inline_dict(self) -> None:
        code = """\
        import subprocess as sp
        sp.run(['ls'], **{'shell': True})
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_alias_tracked_dict(self) -> None:
        code = """\
        import subprocess as sp
        opts = {'shell': True}
        sp.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"


# ---------------------------------------------------------------------------
# R007: Safe cases -- no false positives
# ---------------------------------------------------------------------------


class TestSafeCases:
    """No findings for safe kwargs passthrough or non-targeted functions."""

    def test_safe_dict_no_shell(self) -> None:
        code = """\
        import subprocess
        opts = {'stdout': -1}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 0

    def test_shell_false_no_finding(self) -> None:
        code = "import subprocess; subprocess.run(['ls'], **{'shell': False})"
        findings = _detect(code)
        assert len(findings) == 0

    def test_non_subprocess_call_no_finding(self) -> None:
        code = "some_function(**{'shell': True})"
        findings = _detect(code)
        assert len(findings) == 0

    def test_named_shell_kwarg_not_double_counted(self) -> None:
        """Named shell=True is handled by existing _detect_unsafe_calls, not us."""
        code = "import subprocess; subprocess.run(['ls'], shell=True)"
        findings = _detect(code)
        # detect_kwargs_unpacking should NOT trigger -- this is a named kwarg
        assert len(findings) == 0

    def test_empty_dict_unpacking(self) -> None:
        code = "import subprocess; subprocess.run(['ls'], **{})"
        findings = _detect(code)
        assert len(findings) == 0

    def test_unresolvable_variable(self) -> None:
        """Variable not in symbol table should not crash or produce findings."""
        code = """\
        import subprocess
        subprocess.run(['ls'], **unknown_var)
        """
        findings = _detect(code)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Scope-aware detection
# ---------------------------------------------------------------------------


class TestScopeAwareDetection:
    """Function-local dicts resolved via scope, not just module-level."""

    def test_function_local_dict_detected(self) -> None:
        code = """\
        import subprocess
        def run_cmd():
            opts = {'shell': True}
            subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_shadowed_local_safe_no_false_positive(self) -> None:
        """Module-level opts={'shell': True} should not trigger on a local safe opts."""
        code = """\
        import subprocess
        opts = {'shell': True}
        def run_cmd():
            opts = {'shell': False}
            subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        # Only module-level opts is dangerous -- local opts shadows it safely
        kwargs_findings = [f for f in findings if "kwargs" in f.description.lower()]
        assert len(kwargs_findings) == 0

    def test_function_local_subscript_detected(self) -> None:
        code = """\
        import subprocess
        def run_cmd():
            opts = {}
            opts['shell'] = True
            subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"


# ---------------------------------------------------------------------------
# Dict spread safety
# ---------------------------------------------------------------------------


class TestDictSpreadSafety:
    """Dicts with **spread are treated as unresolvable (no false positives)."""

    def test_spread_dict_not_detected(self) -> None:
        code = "import subprocess; subprocess.run(['ls'], **{**base, 'shell': True})"
        findings = _detect(code)
        assert len(findings) == 0

    def test_spread_overriding_shell_not_detected(self) -> None:
        code = "import subprocess; subprocess.run(['ls'], **{'shell': True, **safe})"
        findings = _detect(code)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# R005: Finding attributes
# ---------------------------------------------------------------------------


class TestFindingAttributes:
    """Finding has correct rule_id, severity, and matched_text."""

    def test_finding_fields(self) -> None:
        code = "import subprocess; subprocess.run(['ls'], **{'shell': True})"
        findings = _detect(code)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "EXEC-002"
        assert f.severity == Severity.CRITICAL
        assert f.category == "malicious-code"
        assert f.file == _FILE
        assert f.line is not None
        assert "'shell'" in f.matched_text
        assert "True" in f.matched_text
        assert "subprocess" in f.matched_text
        assert "detected via AST" in f.description


# ---------------------------------------------------------------------------
# Integration: full pipeline via analyze_python
# ---------------------------------------------------------------------------


class TestFullPipelineIntegration:
    """detect_kwargs_unpacking is called from analyze_python."""

    def test_analyze_python_detects_inline_kwargs(self) -> None:
        code = "import subprocess; subprocess.run(['ls'], **{'shell': True})"
        findings = _detect_full(code)
        kwargs_findings = [f for f in findings if "kwargs" in f.description.lower()]
        assert len(kwargs_findings) >= 1
        assert kwargs_findings[0].rule_id == "EXEC-002"

    def test_analyze_python_detects_tracked_kwargs(self) -> None:
        code = """\
        import subprocess
        opts = {'shell': True}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect_full(code)
        kwargs_findings = [f for f in findings if "kwargs" in f.description.lower()]
        assert len(kwargs_findings) >= 1
