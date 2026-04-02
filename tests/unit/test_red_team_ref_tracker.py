"""Red-team adversarial tests for ref_table scope isolation.

Exercises cross-method ref poisoning, rebinding-after-import evasion,
and nested-class overlapping variable names through the full
analyze_python integration path. All tests target EXEC-002.
"""

from __future__ import annotations

from skill_scan.ast_analyzer import analyze_python
from skill_scan.models import Finding, Severity


def _exec002_findings(code: str) -> list[Finding]:
    """Return only EXEC-002 findings from analyze_python."""
    return [f for f in analyze_python(code, "test.py") if f.rule_id == "EXEC-002"]


# --- Adversarial: cross-method ref poisoning ---


class TestCrossMethodRefPoisoning:
    """Method A imports a dangerous module; method B uses the same variable
    name for a safe call.  Ref-table isolation must prevent cross-pollination.
    """

    def test_sibling_method_same_varname_no_leak(self) -> None:
        """method_a imports os as m; method_b calls m.system() without import.

        method_b has no ref_table entry for m, so m.system() must NOT
        resolve through method_a's import.
        """
        code = (
            "class C:\n"
            "    def method_a(self):\n"
            "        m = __import__('os')\n"
            "        m.system('whoami')\n"
            "    def method_b(self):\n"
            "        m.system('ls')\n"
        )
        findings = _exec002_findings(code)
        method_b_false_pos = [f for f in findings if f.line and f.line >= 6]
        assert len(method_b_false_pos) == 0, (
            f"Cross-method ref poisoning: method_b should not inherit "
            f"method_a's import, got {method_b_false_pos}"
        )

    def test_three_sibling_methods_no_cross_leak(self) -> None:
        """Three methods each using 'm' — only the os.system one should fire."""
        code = (
            "class C:\n"
            "    def safe_a(self):\n"
            "        m = __import__('json')\n"
            "        m.loads('{}')\n"
            "    def danger(self):\n"
            "        m = __import__('os')\n"
            "        m.system('ls')\n"
            "    def safe_b(self):\n"
            "        m = __import__('collections')\n"
            "        m.OrderedDict()\n"
        )
        findings = _exec002_findings(code)
        for f in findings:
            assert f.line is not None
            assert 5 <= f.line <= 7, (
                f"EXEC-002 should only fire inside 'danger' (lines 5-7), but fired at line {f.line}"
            )

    def test_importlib_cross_method_no_leak(self) -> None:
        """importlib.import_module variant of cross-method poisoning."""
        code = (
            "import importlib\n"
            "class C:\n"
            "    def method_a(self):\n"
            "        m = importlib.import_module('subprocess')\n"
            "        m.call(['ls'])\n"
            "    def method_b(self):\n"
            "        m = importlib.import_module('json')\n"
            "        m.loads('{}')\n"
        )
        findings = _exec002_findings(code)
        method_b_findings = [f for f in findings if f.line and f.line >= 6]
        assert len(method_b_findings) == 0, (
            f"importlib cross-method leak: method_b should not fire, got {method_b_findings}"
        )


# --- Adversarial: rebinding-after-import evasion ---


class TestRebindingAfterImport:
    """Attacker imports a dangerous module then rebinds the variable,
    hoping to evade detection.  Only Call reassignment clears the ref.
    """

    def test_rebind_to_safe_wrapper_suppresses(self) -> None:
        """m = __import__('os'); m = safe_wrapper(); m.system('ls').

        The Call reassignment deletes the ref_table entry for m.
        """
        code = "m = __import__('os')\nm = safe_wrapper()\nm.system('ls')\n"
        findings = _exec002_findings(code)
        assert len(findings) == 0, f"Rebinding to safe_wrapper() should suppress EXEC-002, got {findings}"

    def test_rebind_to_class_constructor_suppresses(self) -> None:
        """m = __import__('os'); m = SafeModule(); m.system('ls').

        Class constructor Call also clears the ref.
        """
        code = "m = __import__('os')\nm = SafeModule()\nm.system('ls')\n"
        findings = _exec002_findings(code)
        assert len(findings) == 0, f"Rebinding to constructor should suppress EXEC-002, got {findings}"

    def test_rebind_inside_method_scope_suppresses(self) -> None:
        """Method-scoped rebinding: import then reassign inside same method."""
        code = (
            "class C:\n"
            "    def run(self):\n"
            "        m = __import__('os')\n"
            "        m = Wrapper()\n"
            "        m.system('ls')\n"
        )
        findings = _exec002_findings(code)
        assert len(findings) == 0, f"Method-scoped rebinding should suppress EXEC-002, got {findings}"

    def test_rebind_to_literal_does_NOT_suppress(self) -> None:
        """m = __import__('os'); m = 'safe'; m.system('ls').

        Non-Call RHS (string literal) is skipped by ref_table cleanup —
        the dangerous ref persists because only Call reassignment clears it.
        """
        code = "m = __import__('os')\nm = 'safe'\nm.system('ls')\n"
        findings = _exec002_findings(code)
        assert len(findings) >= 1, (
            "Literal rebinding must NOT suppress EXEC-002 — only Call reassignment clears the ref"
        )

    def test_rebind_to_name_does_NOT_suppress(self) -> None:
        """m = __import__('os'); m = other_var; m.system('ls').

        Non-Call RHS (bare Name) is skipped by ref_table cleanup —
        the dangerous ref persists because only Call reassignment clears it.
        """
        code = "m = __import__('os')\nm = other_var\nm.system('ls')\n"
        findings = _exec002_findings(code)
        assert len(findings) >= 1, (
            "Name rebinding must NOT suppress EXEC-002 — only Call reassignment clears the ref"
        )


# --- Adversarial: nested class methods with overlapping variable names ---


class TestNestedClassOverlap:
    """Nested classes with identically-named variables must not produce
    false positives from scope confusion.
    """

    def test_nested_class_inner_safe_no_false_positive(self) -> None:
        """Inner imports json as m; outer imports os as m — scopes independent."""
        code = (
            "class Outer:\n"
            "    def run(self):\n"
            "        m = __import__('os')\n"
            "        m.system('ls')\n"
            "    class Inner:\n"
            "        def run(self):\n"
            "            m = __import__('json')\n"
            "            m.loads('{}')\n"
        )
        findings = _exec002_findings(code)
        inner_findings = [f for f in findings if f.line and f.line >= 5]
        assert len(inner_findings) == 0, (
            f"Inner class json.loads should not trigger EXEC-002, got {inner_findings}"
        )

    def test_nested_class_no_outer_leak(self) -> None:
        """Outer.run imports os; Inner.run uses same varname without import."""
        code = (
            "class Outer:\n"
            "    def run(self):\n"
            "        m = __import__('os')\n"
            "        m.system('id')\n"
            "    class Inner:\n"
            "        def run(self):\n"
            "            m.system('ls')\n"
        )
        findings = _exec002_findings(code)
        inner_findings = [f for f in findings if f.line and f.line >= 5]
        assert len(inner_findings) == 0, (
            f"Nested class must not inherit outer's ref_table, got {inner_findings}"
        )

    def test_deeply_nested_classes_isolated(self) -> None:
        """Three levels of nesting — each level's scope is independent."""
        code = (
            "class A:\n"
            "    def go(self):\n"
            "        m = __import__('os')\n"
            "        m.system('a')\n"
            "    class B:\n"
            "        def go(self):\n"
            "            m = __import__('json')\n"
            "            m.loads('b')\n"
            "        class C:\n"
            "            def go(self):\n"
            "                m = __import__('collections')\n"
            "                m.OrderedDict()\n"
        )
        findings = _exec002_findings(code)
        for f in findings:
            assert f.line is not None
            assert 1 <= f.line <= 4, (
                f"EXEC-002 should only fire in class A (lines 1-4), fired at line {f.line}"
            )


# --- Positive controls ---


class TestPositiveControls:
    """Same-method import + dangerous call must emit EXEC-002 CRITICAL."""

    def test_same_method_import_system(self) -> None:
        """Import os + m.system in same method -> EXEC-002 CRITICAL."""
        code = "class C:\n    def run(self):\n        m = __import__('os')\n        m.system('ls')\n"
        findings = _exec002_findings(code)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1, "Same-method __import__('os') + .system() must emit EXEC-002 CRITICAL"

    def test_same_method_subprocess_call(self) -> None:
        """Import subprocess + m.call in same method -> EXEC-002 CRITICAL."""
        code = "class C:\n    def run(self):\n        m = __import__('subprocess')\n        m.call(['ls'])\n"
        findings = _exec002_findings(code)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1, (
            "Same-method __import__('subprocess') + .call() must emit EXEC-002 CRITICAL"
        )

    def test_module_level_import_system(self) -> None:
        """Module-level __import__('os') + m.system -> EXEC-002 CRITICAL."""
        code = "m = __import__('os')\nm.system('ls')\n"
        findings = _exec002_findings(code)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1, "Module-level __import__('os') + .system() must emit EXEC-002 CRITICAL"


# --- Acceptance scenarios (plan invoke/expect) ---


class TestAcceptanceScenarios:
    """Full pipeline acceptance tests matching the plan's exact invoke/expect."""

    def test_inline_subprocess_chain_exec002_critical(self) -> None:
        """Inline subprocess chain emits EXEC-002 CRITICAL."""
        findings = analyze_python("__import__('subprocess').call(['ls'])", "<test>")
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        critical = [f for f in exec002 if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1, (
            f"Inline __import__('subprocess').call(['ls']) must emit EXEC-002 CRITICAL, got {exec002}"
        )

    def test_cross_method_isolation_acceptance(self) -> None:
        """Plan scenario: class C where a imports os, b imports json + loads.

        method_b's json.loads('{}') is safe — no EXEC-002 expected for b.
        (Stronger isolation check: test_sibling_method_same_varname_no_leak.)
        """
        code = (
            "class C:\n"
            "    def a(self):\n"
            "        m = __import__('os')\n"
            "    def b(self):\n"
            "        m = __import__('json')\n"
            "        m.loads('{}')\n"
        )
        findings = _exec002_findings(code)
        method_b = [f for f in findings if f.line and f.line >= 4]
        assert len(method_b) == 0, f"method b's json.loads() must not trigger EXEC-002, got {method_b}"

    def test_rebinding_clears_ref_acceptance(self) -> None:
        """Variable rebinding clears stale ref_table entry and suppresses false positive."""
        code = "m = __import__('os')\nm = SafeWrapper()\nm.system('ls')\n"
        findings = _exec002_findings(code)
        assert len(findings) == 0, (
            f"Rebinding to SafeWrapper() must clear ref and suppress EXEC-002, got {findings}"
        )
