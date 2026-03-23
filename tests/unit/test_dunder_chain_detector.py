"""Tests for dunder chain detector (_detect_dunder_chain / EXEC-011).

Tests MRO walk detection, execution escape chains, benign single-dunder
access (no false positives), subscript/call mid-chain handling, and
scanner-level e2e integration.
"""

from __future__ import annotations

import pytest

from skill_scan.ast_analyzer import analyze_python
from skill_scan.content_scanner import _apply_rules, _deduplicate
from skill_scan.models import Finding, Rule, Severity
from skill_scan.rules import load_default_rules
from tests.unit.rule_helpers import filter_by_rule


def _exec011_findings(code: str) -> list[Finding]:
    """Return only EXEC-011 findings from analyze_python."""
    return [f for f in analyze_python(code, "test.py") if f.rule_id == "EXEC-011"]


# ---------------------------------------------------------------------------
# Category 1: Canonical MRO walk patterns (HIGH severity)
# ---------------------------------------------------------------------------


class TestCanonicalMROWalk:
    """Chains of 2+ MRO walk dunders produce EXEC-011 HIGH findings."""

    def test_class_base_subclasses_high(self) -> None:
        """().__class__.__base__.__subclasses__() -> EXEC-011 HIGH."""
        code = "().__class__.__base__.__subclasses__()\n"
        findings = _exec011_findings(code)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].category == "malicious-code"

    def test_class_mro_subscript_subclasses_high(self) -> None:
        """''.__class__.__mro__[1].__subclasses__() -> HIGH with subscript mid-chain."""
        code = "''.__class__.__mro__[1].__subclasses__()\n"
        findings = _exec011_findings(code)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_class_bases_subscript_subclasses_high(self) -> None:
        """[].__class__.__bases__[0].__subclasses__() -> HIGH."""
        code = "[].__class__.__bases__[0].__subclasses__()\n"
        findings = _exec011_findings(code)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_class_base_only_high(self) -> None:
        """obj.__class__.__base__ -> HIGH (2 MRO dunders)."""
        code = "x = ().__class__.__base__\n"
        findings = _exec011_findings(code)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_matched_text_contains_chain(self) -> None:
        """matched_text should show the dunder chain for debugging."""
        code = "().__class__.__base__.__subclasses__()\n"
        findings = _exec011_findings(code)
        assert len(findings) == 1
        mt = findings[0].matched_text or ""
        assert "__class__" in mt
        assert "__base__" in mt
        assert "__subclasses__" in mt


# ---------------------------------------------------------------------------
# Category 2: Execution escape chains (CRITICAL severity)
# ---------------------------------------------------------------------------


class TestExecutionEscape:
    """Chains reaching __globals__, __builtins__, __import__ etc. -> CRITICAL."""

    def test_globals_in_chain_critical(self) -> None:
        """obj.__class__.__base__.__subclasses__()[N].__init__.__globals__ -> CRITICAL."""
        code = "().__class__.__base__.__subclasses__()[99].__init__.__globals__\n"
        findings = _exec011_findings(code)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 1

    def test_builtins_in_chain_critical(self) -> None:
        """Chain reaching __builtins__ -> CRITICAL."""
        code = "().__class__.__base__.__subclasses__()[99].__init__.__globals__['__builtins__'].__import__('os')\n"
        findings = _exec011_findings(code)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 1

    def test_getattr_escape_critical(self) -> None:
        """Chain with __getattr__ -> CRITICAL."""
        code = "x.__class__.__getattr__\n"
        findings = _exec011_findings(code)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 1

    def test_code_escape_critical(self) -> None:
        """Chain with __code__ -> CRITICAL."""
        code = "x.__class__.__code__\n"
        findings = _exec011_findings(code)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 1


# ---------------------------------------------------------------------------
# Category 3: Benign single-dunder access (no findings)
# ---------------------------------------------------------------------------


class TestBenignSingleDunder:
    """Single dunder access or non-dangerous dunders produce no EXEC-011."""

    def test_isolated_class_no_finding(self) -> None:
        """obj.__class__ alone is not a chain -> no finding."""
        code = "x = obj.__class__\n"
        assert _exec011_findings(code) == []

    def test_isolated_subclasses_no_finding(self) -> None:
        """cls.__subclasses__() alone is not a chain -> no finding."""
        code = "cls.__subclasses__()\n"
        assert _exec011_findings(code) == []

    def test_isolated_base_no_finding(self) -> None:
        """cls.__base__ alone is not a chain -> no finding."""
        code = "x = cls.__base__\n"
        assert _exec011_findings(code) == []

    def test_isolated_mro_no_finding(self) -> None:
        """cls.__mro__ alone is not a chain -> no finding."""
        code = "x = cls.__mro__\n"
        assert _exec011_findings(code) == []


# ---------------------------------------------------------------------------
# Category 4: Benign multi-dunder (non-dangerous dunder in chain)
# ---------------------------------------------------------------------------


class TestBenignMultiDunder:
    """Multi-dunder chains where one dunder is NOT in the dangerous set."""

    def test_class_name_no_finding(self) -> None:
        """obj.__class__.__name__ -> __name__ is not dangerous, only 1 dangerous dunder."""
        code = "x = obj.__class__.__name__\n"
        assert _exec011_findings(code) == []

    def test_class_dict_no_finding(self) -> None:
        """obj.__class__.__dict__ -> __dict__ is not in dangerous set, single dangerous dunder."""
        code = "x = obj.__class__.__dict__\n"
        assert _exec011_findings(code) == []

    def test_init_no_chain(self) -> None:
        """obj.__init__ alone is not dangerous."""
        code = "x = obj.__init__\n"
        assert _exec011_findings(code) == []


# ---------------------------------------------------------------------------
# Category 5: Edge cases (subscript, call, non-dunder breaking chain)
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Subscript, Call in mid-chain, and non-dunder attrs."""

    def test_subscript_does_not_break_chain(self) -> None:
        """__mro__[1] subscript is transparent to chain detection."""
        code = "''.__class__.__mro__[1].__subclasses__()\n"
        findings = _exec011_findings(code)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_call_in_chain_transparent(self) -> None:
        """func().__class__.__base__ -> call is transparent."""
        code = "func().__class__.__base__\n"
        findings = _exec011_findings(code)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_non_dunder_attr_breaks_chain(self) -> None:
        """obj.__class__.some_method.__base__ -> non-dunder 'some_method' breaks the chain."""
        # some_method is not a dunder, so it breaks the chain.
        # Each dangerous dunder is isolated (1 each) — no 2+ chain.
        code = "x = obj.__class__.some_method.__base__\n"
        assert _exec011_findings(code) == []

    def test_deeply_nested_subscript_chain(self) -> None:
        """Multiple subscripts in chain are transparent."""
        code = "().__class__.__mro__[0].__bases__[0].__subclasses__()\n"
        findings = _exec011_findings(code)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Category 6: Scanner-level e2e tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def default_rules() -> list[Rule]:
    """Load the full default rule set for integration tests."""
    return load_default_rules()


class TestScannerE2E:
    """End-to-end tests through _apply_rules / _deduplicate."""

    def test_exec011_propagates_through_scanner(self, default_rules: list[Rule]) -> None:
        """EXEC-011 finding propagates through _apply_rules + _deduplicate."""
        code = "().__class__.__base__.__subclasses__()\n"
        regex_findings = _apply_rules(code, "test.py", default_rules)
        ast_findings = analyze_python(code, "test.py")
        merged = _deduplicate(regex_findings, ast_findings)
        exec011 = filter_by_rule("EXEC-011", merged)
        assert len(exec011) == 1
        assert exec011[0].severity == Severity.HIGH

    def test_exec011_critical_through_scanner(self, default_rules: list[Rule]) -> None:
        """EXEC-011 CRITICAL finding propagates through scanner pipeline."""
        code = "().__class__.__base__.__subclasses__()[99].__init__.__globals__\n"
        regex_findings = _apply_rules(code, "test.py", default_rules)
        ast_findings = analyze_python(code, "test.py")
        merged = _deduplicate(regex_findings, ast_findings)
        exec011 = filter_by_rule("EXEC-011", merged)
        critical = [f for f in exec011 if f.severity == Severity.CRITICAL]
        assert len(critical) == 1

    def test_exec011_not_emitted_for_benign(self, default_rules: list[Rule]) -> None:
        """Benign single-dunder access does not produce EXEC-011 through scanner."""
        code = "x = obj.__class__\n"
        regex_findings = _apply_rules(code, "test.py", default_rules)
        ast_findings = analyze_python(code, "test.py")
        merged = _deduplicate(regex_findings, ast_findings)
        exec011 = filter_by_rule("EXEC-011", merged)
        assert exec011 == []
