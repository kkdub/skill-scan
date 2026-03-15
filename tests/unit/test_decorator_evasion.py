"""Tests for decorator evasion detection (_detect_decorator_evasion).

Covers: R012, R013, R014, R018, R023, R-EFF001, R-EFF002, R-EFF005.
"""

from __future__ import annotations

import textwrap

from skill_scan.ast_analyzer import analyze_python


class TestDecoratorEvasionPositive:
    """Dangerous decorators must produce findings with correct rule IDs."""

    def test_eval_decorator_produces_exec_002(self) -> None:
        """R012: @eval on function def produces EXEC-002."""
        source = textwrap.dedent("""\
            @eval
            def payload():
                pass
        """)
        findings = analyze_python(source, "test.py")
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1
        assert any("@eval" in f.matched_text for f in exec_findings)

    def test_exec_decorator_produces_exec_002(self) -> None:
        """R018: @exec produces EXEC-002."""
        source = textwrap.dedent("""\
            @exec
            def payload():
                pass
        """)
        findings = analyze_python(source, "test.py")
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1
        assert any("@exec" in f.matched_text for f in exec_findings)

    def test_builtins_eval_attribute_decorator(self) -> None:
        """R023: @builtins.eval (attribute form) produces EXEC-002."""
        source = textwrap.dedent("""\
            import builtins
            @builtins.eval
            class Exploit:
                pass
        """)
        findings = analyze_python(source, "test.py")
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1
        assert any("@eval" in f.matched_text for f in exec_findings)

    def test_import_decorator_produces_exec_006(self) -> None:
        """R018: @__import__ produces EXEC-006."""
        source = textwrap.dedent("""\
            @__import__
            def payload():
                pass
        """)
        findings = analyze_python(source, "test.py")
        exec_findings = [f for f in findings if f.rule_id == "EXEC-006"]
        assert len(exec_findings) >= 1
        assert any("@__import__" in f.matched_text for f in exec_findings)

    def test_getattr_decorator_produces_exec_006(self) -> None:
        """R018: @getattr produces EXEC-006."""
        source = textwrap.dedent("""\
            @getattr
            def payload():
                pass
        """)
        findings = analyze_python(source, "test.py")
        exec_findings = [f for f in findings if f.rule_id == "EXEC-006"]
        assert len(exec_findings) >= 1
        assert any("@getattr" in f.matched_text for f in exec_findings)

    def test_async_function_decorator(self) -> None:
        """Decorator on async function def is also detected."""
        source = textwrap.dedent("""\
            @eval
            async def payload():
                pass
        """)
        findings = analyze_python(source, "test.py")
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1

    def test_class_def_decorator(self) -> None:
        """Decorator on class def is detected."""
        source = textwrap.dedent("""\
            @exec
            class Exploit:
                pass
        """)
        findings = analyze_python(source, "test.py")
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1

    def test_multiple_dangerous_decorators(self) -> None:
        """Multiple dangerous decorators produce multiple findings."""
        source = textwrap.dedent("""\
            @eval
            @exec
            def payload():
                pass
        """)
        findings = analyze_python(source, "test.py")
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 2


class TestDecoratorEvasionNegative:
    """Safe decorators must NOT trigger EXEC-002/EXEC-006."""

    def test_staticmethod_safe(self) -> None:
        """R014: @staticmethod does not trigger."""
        source = textwrap.dedent("""\
            class Foo:
                @staticmethod
                def bar():
                    pass
        """)
        findings = analyze_python(source, "test.py")
        dangerous = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert len(dangerous) == 0

    def test_property_safe(self) -> None:
        """R014: @property does not trigger."""
        source = textwrap.dedent("""\
            class Foo:
                @property
                def bar(self):
                    return 42
        """)
        findings = analyze_python(source, "test.py")
        dangerous = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert len(dangerous) == 0

    def test_custom_decorator_safe(self) -> None:
        """R014: custom decorator does not trigger."""
        source = textwrap.dedent("""\
            def my_decorator(fn):
                return fn
            @my_decorator
            def foo():
                pass
        """)
        findings = analyze_python(source, "test.py")
        dangerous = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert len(dangerous) == 0

    def test_functools_wraps_safe(self) -> None:
        """R014: @functools.wraps does not trigger."""
        source = textwrap.dedent("""\
            import functools
            def decorator(fn):
                @functools.wraps(fn)
                def wrapper(*args):
                    return fn(*args)
                return wrapper
        """)
        findings = analyze_python(source, "test.py")
        dangerous = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert len(dangerous) == 0


class TestDecoratorRuleDefinition:
    """R013, R-IMP007: _DECORATOR_RULE is local and detector is registered."""

    def test_decorator_rule_exists_in_detectors(self) -> None:
        """_DECORATOR_RULE is defined in _ast_detectors."""
        from skill_scan._ast_detectors import _DECORATOR_RULE

        assert isinstance(_DECORATOR_RULE, dict)
        assert "eval" in _DECORATOR_RULE
        assert "exec" in _DECORATOR_RULE
        assert "__import__" in _DECORATOR_RULE
        assert "getattr" in _DECORATOR_RULE

    def test_detector_registered_in_detectors_tuple(self) -> None:
        """_detect_decorator_evasion is in _DETECTORS."""
        from skill_scan.ast_analyzer import _DETECTORS, _detect_decorator_evasion

        assert _detect_decorator_evasion in _DETECTORS


class TestDecoratorCorpusFixtures:
    """R-EFF001/R-EFF002: corpus fixtures produce expected results."""

    def test_pos_decorator_eval_detected(self) -> None:
        """pos_decorator_eval.py produces EXEC-002 finding."""
        from pathlib import Path

        fixture = (
            Path(__file__).resolve().parent.parent / "fixtures" / "split_evasion" / "pos_decorator_eval.py"
        )
        source = fixture.read_text(encoding="utf-8")
        findings = analyze_python(source, str(fixture))
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1

    def test_neg_decorator_safe_no_findings(self) -> None:
        """neg_decorator_safe.py produces zero EXEC-002/EXEC-006 findings."""
        from pathlib import Path

        fixture = (
            Path(__file__).resolve().parent.parent / "fixtures" / "split_evasion" / "neg_decorator_safe.py"
        )
        source = fixture.read_text(encoding="utf-8")
        findings = analyze_python(source, str(fixture))
        dangerous = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert len(dangerous) == 0
