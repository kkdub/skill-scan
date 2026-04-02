"""Tests for inline import chain detection and builtins.__import__ handling.

Covers EXEC-002 findings for `__import__('mod').dangerous()` and
`importlib.import_module('mod').dangerous()` patterns, plus EXEC-006
for `builtins.__import__('os')`.
"""

from __future__ import annotations

import pytest

from skill_scan.ast_analyzer import analyze_python
from skill_scan.models import Finding, Severity


_FILE = "test.py"


def _findings(code: str) -> list[Finding]:
    """Return all findings from analyze_python."""
    return analyze_python(code, _FILE)


def _rule_findings(code: str, rule_id: str) -> list[Finding]:
    """Return findings matching a specific rule_id."""
    return [f for f in _findings(code) if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# R001: __import__('os').system('cmd') => EXEC-002
# ---------------------------------------------------------------------------


class TestImportDunderSystem:
    """__import__('mod').dangerous_attr() inline chains."""

    def test_import_system_exec002(self) -> None:
        """__import__('os').system('cmd') produces EXEC-002."""
        code = "__import__('os').system('cmd')\n"
        findings = _rule_findings(code, "EXEC-002")
        assert len(findings) >= 1

    def test_import_system_severity_critical(self) -> None:
        """EXEC-002 from inline chain should be CRITICAL."""
        code = "__import__('os').system('whoami')\n"
        findings = _rule_findings(code, "EXEC-002")
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(crit) >= 1


# ---------------------------------------------------------------------------
# R002: Inline chains with other dangerous attrs => EXEC-002
# ---------------------------------------------------------------------------


class TestOtherDangerousAttrs:
    """Various dangerous attribute chains on __import__."""

    def test_import_popen_exec002(self) -> None:
        """__import__('os').popen('id') produces EXEC-002."""
        code = "__import__('os').popen('id')\n"
        findings = _rule_findings(code, "EXEC-002")
        assert len(findings) >= 1

    def test_import_exec_exec002(self) -> None:
        """__import__('builtins').exec('code') produces EXEC-002."""
        code = "__import__('builtins').exec('code')\n"
        findings = _rule_findings(code, "EXEC-002")
        assert len(findings) >= 1

    def test_import_eval_exec002(self) -> None:
        """__import__('builtins').eval('1+1') produces EXEC-002."""
        code = "__import__('builtins').eval('1+1')\n"
        findings = _rule_findings(code, "EXEC-002")
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# R003: importlib.import_module('os').system('cmd') => EXEC-002
# ---------------------------------------------------------------------------


class TestImportlibChain:
    """importlib.import_module inline chains."""

    def test_importlib_system_exec002(self) -> None:
        """importlib.import_module('os').system('cmd') produces EXEC-002."""
        code = "import importlib\nimportlib.import_module('os').system('cmd')\n"
        findings = _rule_findings(code, "EXEC-002")
        assert len(findings) >= 1

    def test_importlib_popen_exec002(self) -> None:
        """importlib.import_module('os').popen('id') produces EXEC-002."""
        code = "import importlib\nimportlib.import_module('os').popen('id')\n"
        findings = _rule_findings(code, "EXEC-002")
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# R004: builtins.__import__('os') => EXEC-006
# ---------------------------------------------------------------------------


class TestBuiltinsImport:
    """builtins.__import__ detected as dynamic import."""

    def test_builtins_import_exec006(self) -> None:
        """builtins.__import__('os') produces EXEC-006."""
        code = "import builtins\nbuiltins.__import__('os')\n"
        findings = _rule_findings(code, "EXEC-006")
        assert len(findings) >= 1

    def test_dunder_builtins_import_exec006(self) -> None:
        """__builtins__.__import__('os') produces EXEC-006."""
        code = "__builtins__.__import__('os')\n"
        findings = _rule_findings(code, "EXEC-006")
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# R-IMP002: __import__('os') still produces EXEC-006 (no regression)
# ---------------------------------------------------------------------------


class TestNoRegression:
    """Existing __import__ detection must not regress."""

    def test_plain_import_exec006_still_fires(self) -> None:
        """__import__('os') still produces EXEC-006."""
        code = "__import__('os')\n"
        findings = _rule_findings(code, "EXEC-006")
        assert len(findings) >= 1

    def test_import_chain_both_rules(self) -> None:
        """__import__('os').system('cmd') produces both EXEC-006 and EXEC-002."""
        code = "__import__('os').system('cmd')\n"
        exec006 = _rule_findings(code, "EXEC-006")
        exec002 = _rule_findings(code, "EXEC-002")
        assert len(exec006) >= 1, "EXEC-006 should still fire for __import__"
        assert len(exec002) >= 1, "EXEC-002 should fire for .system() chain"


# ---------------------------------------------------------------------------
# Negative cases: should NOT produce EXEC-002
# ---------------------------------------------------------------------------


class TestNegativeCases:
    """Patterns that should not trigger inline import chain detection."""

    def test_normal_import_no_chain(self) -> None:
        """Plain __import__('os') without chaining should not produce EXEC-002."""
        code = "__import__('os')\n"
        findings = _rule_findings(code, "EXEC-002")
        assert len(findings) == 0

    def test_safe_attr_no_exec002(self) -> None:
        """__import__('os').path should not produce EXEC-002 (path is safe)."""
        code = "__import__('os').path\n"
        findings = _rule_findings(code, "EXEC-002")
        assert len(findings) == 0

    @pytest.mark.parametrize("attr", ["getcwd", "listdir", "path"])
    def test_benign_attrs_no_exec002(self, attr: str) -> None:
        """Benign attributes should not trigger EXEC-002."""
        code = f"__import__('os').{attr}()\n"
        findings = _rule_findings(code, "EXEC-002")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# R-SUBPROC-001: __import__('subprocess').call/check_output/Popen/run/check_call => EXEC-002
# ---------------------------------------------------------------------------


class TestSubprocessInlineChain:
    """Subprocess family inline chains via __import__."""

    def test_subprocess_call_exec002(self) -> None:
        """__import__('subprocess').call(['ls']) produces EXEC-002."""
        code = "__import__('subprocess').call(['ls'])\n"
        findings = _rule_findings(code, "EXEC-002")
        assert len(findings) >= 1

    def test_subprocess_call_severity_critical(self) -> None:
        """EXEC-002 from subprocess.call inline chain should be CRITICAL."""
        code = "__import__('subprocess').call(['ls'])\n"
        findings = _rule_findings(code, "EXEC-002")
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(crit) >= 1

    def test_subprocess_check_output_exec002(self) -> None:
        """__import__('subprocess').check_output(['id']) produces EXEC-002."""
        code = "__import__('subprocess').check_output(['id'])\n"
        findings = _rule_findings(code, "EXEC-002")
        assert len(findings) >= 1

    def test_subprocess_popen_exec002(self) -> None:
        """__import__('subprocess').Popen(['cmd']) produces EXEC-002."""
        code = "__import__('subprocess').Popen(['cmd'])\n"
        findings = _rule_findings(code, "EXEC-002")
        assert len(findings) >= 1

    def test_subprocess_run_exec002(self) -> None:
        """__import__('subprocess').run(['ls']) produces EXEC-002."""
        code = "__import__('subprocess').run(['ls'])\n"
        findings = _rule_findings(code, "EXEC-002")
        assert len(findings) >= 1

    def test_subprocess_check_call_exec002(self) -> None:
        """__import__('subprocess').check_call(['ls']) produces EXEC-002."""
        code = "__import__('subprocess').check_call(['ls'])\n"
        findings = _rule_findings(code, "EXEC-002")
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# R-SUBPROC-002: importlib.import_module('subprocess') chains => EXEC-002
# ---------------------------------------------------------------------------


class TestSubprocessImportlibChain:
    """Subprocess family inline chains via importlib.import_module."""

    def test_importlib_subprocess_call_exec002(self) -> None:
        """importlib.import_module('subprocess').call(['ls']) produces EXEC-002."""
        code = "import importlib\nimportlib.import_module('subprocess').call(['ls'])\n"
        findings = _rule_findings(code, "EXEC-002")
        assert len(findings) >= 1

    def test_importlib_subprocess_popen_exec002(self) -> None:
        """importlib.import_module('subprocess').Popen(['cmd']) produces EXEC-002."""
        code = "import importlib\nimportlib.import_module('subprocess').Popen(['cmd'])\n"
        findings = _rule_findings(code, "EXEC-002")
        assert len(findings) >= 1

    def test_importlib_subprocess_check_output_exec002(self) -> None:
        """importlib.import_module('subprocess').check_output(['id']) produces EXEC-002."""
        code = "import importlib\nimportlib.import_module('subprocess').check_output(['id'])\n"
        findings = _rule_findings(code, "EXEC-002")
        assert len(findings) >= 1

    def test_importlib_subprocess_run_exec002(self) -> None:
        """importlib.import_module('subprocess').run(['ls']) produces EXEC-002."""
        code = "import importlib\nimportlib.import_module('subprocess').run(['ls'])\n"
        findings = _rule_findings(code, "EXEC-002")
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# R-SUBPROC-003: Negative cases for subprocess inline chains
# ---------------------------------------------------------------------------


class TestSubprocessNegativeCases:
    """Patterns with subprocess that should NOT trigger EXEC-002."""

    def test_plain_subprocess_import_no_chain(self) -> None:
        """__import__('subprocess') without chaining should not produce EXEC-002."""
        code = "__import__('subprocess')\n"
        findings = _rule_findings(code, "EXEC-002")
        assert len(findings) == 0

    def test_subprocess_safe_attr_no_exec002(self) -> None:
        """__import__('subprocess').PIPE should not produce EXEC-002 (PIPE is safe)."""
        code = "__import__('subprocess').PIPE\n"
        findings = _rule_findings(code, "EXEC-002")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# R-SUBPROC-004: Module export verification
# ---------------------------------------------------------------------------


class TestInlineChainModuleExports:
    """Verify _ast_inline_chain_detector module exports."""

    def test_inline_chain_attrs_contains_subprocess_family(self) -> None:
        """_INLINE_CHAIN_ATTRS includes subprocess attrs."""
        from skill_scan._ast_inline_chain_detector import _INLINE_CHAIN_ATTRS

        subprocess_attrs = {"call", "check_output", "Popen", "run", "check_call"}
        for attr in subprocess_attrs:
            assert attr in _INLINE_CHAIN_ATTRS, f"{attr} missing from _INLINE_CHAIN_ATTRS"

    def test_inline_chain_attrs_contains_original_attrs(self) -> None:
        """_INLINE_CHAIN_ATTRS still includes original dangerous attrs."""
        from skill_scan._ast_inline_chain_detector import _INLINE_CHAIN_ATTRS

        original_attrs = {"eval", "exec", "system", "popen"}
        for attr in original_attrs:
            assert attr in _INLINE_CHAIN_ATTRS, f"{attr} missing from _INLINE_CHAIN_ATTRS"

    def test_import_call_names_exported(self) -> None:
        """_IMPORT_CALL_NAMES is exported from the new module."""
        from skill_scan._ast_inline_chain_detector import _IMPORT_CALL_NAMES

        assert isinstance(_IMPORT_CALL_NAMES, frozenset)
        assert "__import__" in _IMPORT_CALL_NAMES

    def test_detect_function_exported(self) -> None:
        """_detect_inline_import_chain is exported from the new module."""
        from skill_scan._ast_inline_chain_detector import _detect_inline_import_chain

        assert callable(_detect_inline_import_chain)
