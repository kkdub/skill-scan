"""Tests for tree-level dynamic exec detector (detect_dynamic_exec).

Tests symbol-table resolution and taint-sink detection for getattr()
calls with variable second arguments, exercised through analyze_python.
"""

from __future__ import annotations

from skill_scan.ast_analyzer import analyze_python
from skill_scan.models import Finding, Severity


def _exec006_findings(code: str) -> list[Finding]:
    """Return only EXEC-006 findings from analyze_python."""
    return [f for f in analyze_python(code, "test.py") if f.rule_id == "EXEC-006"]


# ---------------------------------------------------------------------------
# Symbol-table resolution: 2nd arg resolves to a dangerous name -> HIGH
# ---------------------------------------------------------------------------


class TestSymbolTableResolution:
    """getattr with 2nd arg resolving to a dangerous name via symbol table."""

    def test_resolved_system_high(self) -> None:
        """getattr(os, var) where var='system' -> EXEC-006 HIGH."""
        code = "import os\nattr_name = 'system'\ngetattr(os, attr_name)\n"
        findings = _exec006_findings(code)
        high_findings = [f for f in findings if f.severity == Severity.HIGH]
        matched = [f for f in high_findings if "system" in (f.matched_text or "")]
        assert len(matched) == 1, f"Expected 1 HIGH finding with 'system' in matched_text, got {matched}"

    def test_resolved_eval_high(self) -> None:
        """getattr(builtins, var) where var='eval' -> EXEC-006 HIGH."""
        code = "import builtins\nfn = 'eval'\ngetattr(builtins, fn)\n"
        findings = _exec006_findings(code)
        high_findings = [f for f in findings if f.severity == Severity.HIGH]
        matched = [f for f in high_findings if "eval" in (f.matched_text or "")]
        assert len(matched) == 1

    def test_resolved_path_no_finding(self) -> None:
        """getattr(os, var) where var='path' -> no finding (path not dangerous)."""
        code = "import os\nattr_name = 'path'\ngetattr(os, attr_name)\n"
        findings = _exec006_findings(code)
        # 'path' is not in _DANGEROUS_NAMES, so no HIGH from symbol-table resolution.
        # Also not a taint sink because var resolves to a known string.
        assert len(findings) == 0

    def test_aliased_module_resolved(self) -> None:
        """import os as o; getattr(o, var) where var='system' -> detected."""
        code = "import os as o\nattr_name = 'system'\ngetattr(o, attr_name)\n"
        findings = _exec006_findings(code)
        high_findings = [f for f in findings if f.severity == Severity.HIGH]
        matched = [f for f in high_findings if "system" in (f.matched_text or "")]
        assert len(matched) == 1


# ---------------------------------------------------------------------------
# Taint sink: sensitive module + non-resolvable 2nd arg -> MEDIUM
# ---------------------------------------------------------------------------


class TestTaintSink:
    """getattr on sensitive module with unresolvable 2nd arg."""

    def test_unknown_var_sensitive_module_medium(self) -> None:
        """getattr(os, unknown_var) -> EXEC-006 MEDIUM (taint sink)."""
        code = "import os\ngetattr(os, unknown_var)\n"
        findings = _exec006_findings(code)
        medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(medium_findings) == 1

    def test_aliased_import_taint_sink_medium(self) -> None:
        """import os as o; getattr(o, unknown_var) -> EXEC-006 MEDIUM (alias resolved)."""
        code = "import os as o\ngetattr(o, unknown_var)\n"
        findings = _exec006_findings(code)
        medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(medium_findings) == 1

    def test_non_sensitive_module_no_finding(self) -> None:
        """getattr(config, unknown_var) -> no finding (config not sensitive)."""
        code = "config = object()\ngetattr(config, unknown_var)\n"
        findings = _exec006_findings(code)
        assert len(findings) == 0

    def test_self_not_sensitive(self) -> None:
        """getattr(self, unknown) -> no finding (self not a sensitive module)."""
        code = "class Foo:\n    def bar(self):\n        getattr(self, unknown)\n"
        findings = _exec006_findings(code)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Skip cases: not getattr, or constant 2nd arg
# ---------------------------------------------------------------------------


class TestSkipCases:
    """Cases where detect_dynamic_exec should NOT produce findings."""

    def test_hasattr_not_detected(self) -> None:
        """hasattr(os, 'system') -> no finding from this detector."""
        code = "import os\nhasattr(os, 'system')\n"
        findings = _exec006_findings(code)
        # hasattr is not getattr -- no finding expected
        assert len(findings) == 0

    def test_constant_arg_handled_by_node_level(self) -> None:
        """getattr(os, 'system') -> detected by node-level, not tree-level.

        The tree-level detector skips constant 2nd args.
        The node-level detector already handles this case.
        """
        code = "import os\ngetattr(os, 'system')\n"
        findings = _exec006_findings(code)
        # Should have exactly 1 HIGH from node-level _detect_dynamic_access
        high_findings = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high_findings) == 1
        # The matched_text from node-level includes the constant
        matched = [f for f in high_findings if "'system'" in (f.matched_text or "")]
        assert len(matched) == 1
