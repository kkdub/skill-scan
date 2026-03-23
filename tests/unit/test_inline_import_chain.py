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
