"""Tests for truthy value matching in kwargs unpacking detector.

Covers type-aware truthiness in _kwarg_matches: native Python types are
preserved from AST, bool() truthiness is used for boolean table entries,
and non-boolean table entries use exact str() comparison.
"""

from __future__ import annotations

import ast

from skill_scan._ast_kwargs_detector import (
    _eval_constant_expr,
    _extract_dict_literal,
    _kwarg_matches,
)
from skill_scan.models import Severity

from tests.unit.kwargs_test_utils import detect as _detect, detect_full as _detect_full


class TestIntegerTruthyMatch:
    """Integer truthy values (1, 2, etc.) match boolean True in the table."""

    def test_shell_int_1_produces_exec002(self) -> None:
        """subprocess.run(**{'shell': 1}) must produce EXEC-002."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': 1})"
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"
        assert findings[0].severity == Severity.CRITICAL

    def test_shell_int_2_produces_exec002(self) -> None:
        """Any nonzero integer is truthy -- shell=2 must also match."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': 2})"
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_tracked_dict_shell_int_1_detected(self) -> None:
        """Tracked dict with shell=1 (via subscript) produces EXEC-002."""
        code = """\
        import subprocess
        opts = {}
        opts['shell'] = 1
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_dict_literal_init_shell_int_1(self) -> None:
        """Dict literal init with integer 1 produces EXEC-002."""
        code = """\
        import subprocess
        opts = {'shell': 1}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"


class TestIntegerFalsyNoMatch:
    """Integer falsy values (0) do not match boolean True in the table."""

    def test_shell_int_0_no_finding(self) -> None:
        """subprocess.run(**{'shell': 0}) must produce zero findings."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': 0})"
        findings = _detect(code)
        assert len(findings) == 0

    def test_tracked_dict_shell_int_0_no_finding(self) -> None:
        """Tracked dict with shell=0 (via subscript) produces no finding."""
        code = """\
        import subprocess
        opts = {}
        opts['shell'] = 0
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 0

    def test_shell_float_0_no_finding(self) -> None:
        """subprocess.run(**{'shell': 0.0}) -- float zero is falsy."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': 0.0})"
        findings = _detect(code)
        assert len(findings) == 0

    def test_shell_complex_0_no_finding(self) -> None:
        """subprocess.run(**{'shell': 0j}) -- complex zero is falsy."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': 0j})"
        findings = _detect(code)
        assert len(findings) == 0

    def test_dict_literal_shell_int_0_no_finding(self) -> None:
        """Dict literal init with integer 0 produces no finding."""
        code = """\
        import subprocess
        opts = {'shell': 0}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 0


class TestNonBooleanExactMatch:
    """Non-boolean table entries do NOT get truthy normalization."""

    def test_kwarg_matches_exact_string_value(self) -> None:
        """String table value uses exact comparison, not truthiness."""
        # 1 is truthy but should NOT match "True" with exact comparison
        assert _kwarg_matches({"key": 1}, "key", "True") is False
        assert _kwarg_matches({"key": "True"}, "key", "True") is True

    def test_kwarg_matches_exact_int_value(self) -> None:
        """Integer table value uses exact str() comparison."""
        assert _kwarg_matches({"key": 42}, "key", 42) is True
        assert _kwarg_matches({"key": 1}, "key", 42) is False


class TestKwargMatchesTruthy:
    """Direct unit tests for _kwarg_matches with boolean table values."""

    def test_bool_true_matches_truthy_values(self) -> None:
        """True, int 1/2, non-empty string, string '0' all match True."""
        for val in (True, 1, 2, "anything", "0"):
            assert _kwarg_matches({"shell": val}, "shell", True) is True, f"failed for {val!r}"

    def test_bool_true_rejects_falsy_values(self) -> None:
        """False, 0, 0.0, 0j, None, '' do not match True."""
        for val in (False, 0, 0.0, 0j, None, ""):
            assert _kwarg_matches({"shell": val}, "shell", True) is False, f"failed for {val!r}"

    def test_bool_false_matches_falsy_values(self) -> None:
        """0, False, None match False."""
        for val in (0, False, None):
            assert _kwarg_matches({"shell": val}, "shell", False) is True, f"failed for {val!r}"

    def test_bool_false_rejects_truthy_values(self) -> None:
        """1, True do not match False."""
        for val in (1, True):
            assert _kwarg_matches({"shell": val}, "shell", False) is False, f"failed for {val!r}"


class TestAcceptanceDictUnionDangerousKwarg:
    """Acceptance: dict union operator delivers dangerous kwarg to subprocess."""

    def test_aug_assign_union_shell_true_detected(self) -> None:
        """opts |= {'shell': True}; subprocess.run(**opts) -> EXEC-002."""
        code = """\
        import subprocess
        opts = {}
        opts |= {'shell': True}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect_full(code)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1
        assert any("shell" in f.matched_text for f in exec_findings)


class TestAcceptanceIntegerTruthyShell:
    """Acceptance: integer truthy shell value detected via full pipeline."""

    def test_shell_int_1_full_pipeline(self) -> None:
        """analyze_python on shell=1 -> at least one EXEC-002."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': 1})"
        findings = _detect_full(code)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1


class TestStringZeroTruthy:
    """String '0' is a truthy value in Python -- must produce EXEC-002."""

    def test_shell_string_0_inline_detected(self) -> None:
        """subprocess.run(**{'shell': '0'}) -- string '0' is truthy."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': '0'})"
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_shell_string_0_tracked_dict_detected(self) -> None:
        """Tracked dict with shell='0' (via literal init) produces EXEC-002."""
        code = """\
        import subprocess
        opts = {'shell': '0'}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_shell_int_0_remains_falsy(self) -> None:
        """Integer 0 is falsy -- no false positive (regression guard)."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': 0})"
        findings = _detect(code)
        assert len(findings) == 0

    def test_shell_string_0_full_pipeline(self) -> None:
        """Full pipeline: shell='0' detected as EXEC-002 (R-EFF001)."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': '0'})"
        findings = _detect_full(code)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1


class TestExtractDictLiteralNativeTypes:
    """_extract_dict_literal stores raw constant values, not str()."""

    def test_bool_preserved(self) -> None:
        node = ast.parse("{'shell': True}").body[0].value  # type: ignore[attr-defined]
        assert _extract_dict_literal(node) == {"shell": True}

    def test_int_preserved(self) -> None:
        result = _extract_dict_literal(ast.parse("{'shell': 1}").body[0].value)  # type: ignore[attr-defined]
        assert result is not None and result["shell"] == 1 and isinstance(result["shell"], int)

    def test_string_preserved(self) -> None:
        result = _extract_dict_literal(ast.parse("{'shell': '0'}").body[0].value)  # type: ignore[attr-defined]
        assert result is not None and result["shell"] == "0" and isinstance(result["shell"], str)

    def test_none_preserved(self) -> None:
        node = ast.parse("{'shell': None}").body[0].value  # type: ignore[attr-defined]
        assert _extract_dict_literal(node) == {"shell": None}


class TestNegativeLiteralEvasion:
    """Negative numeric literals (-1, -1.0) must be detected as truthy (R-027b)."""

    def test_shell_neg_int_inline(self) -> None:
        """subprocess.run(['ls'], **{'shell': -1}) -> EXEC-002."""
        findings = _detect("import subprocess; subprocess.run(['ls'], **{'shell': -1})")
        assert len(findings) == 1 and findings[0].rule_id == "EXEC-002"

    def test_shell_neg_float_inline(self) -> None:
        """subprocess.run(['ls'], **{'shell': -1.0}) -> EXEC-002."""
        findings = _detect("import subprocess; subprocess.run(['ls'], **{'shell': -1.0})")
        assert len(findings) == 1 and findings[0].rule_id == "EXEC-002"

    def test_shell_neg_int_tracked_dict(self) -> None:
        """opts = {'shell': -1}; subprocess.run(**opts) -> EXEC-002."""
        code = "import subprocess\nopts = {'shell': -1}\nsubprocess.run(['ls'], **opts)"
        assert len(_detect(code)) == 1

    def test_shell_neg_int_subscript_assign(self) -> None:
        """opts['shell'] = -1; subprocess.run(**opts) -> EXEC-002."""
        code = "import subprocess\nopts = {}\nopts['shell'] = -1\nsubprocess.run(['ls'], **opts)"
        assert len(_detect(code)) == 1

    def test_neg_0_is_falsy(self) -> None:
        """-0 is still falsy -- no false positive."""
        assert len(_detect("import subprocess; subprocess.run(['ls'], **{'shell': -0})")) == 0


class TestEvalConstantExpr:
    """Unit tests for _eval_constant_expr helper."""

    def test_resolves_constants(self) -> None:
        """Positive int, negative int, negative float, unary plus, None, string."""

        def _p(s: str) -> ast.expr:
            return ast.parse(s).body[0].value  # type: ignore[attr-defined,no-any-return]

        assert _eval_constant_expr(_p("42")) == 42
        assert _eval_constant_expr(_p("-1")) == -1
        assert _eval_constant_expr(_p("-3.14")) == -3.14
        assert _eval_constant_expr(_p("+5")) == 5
        assert _eval_constant_expr(_p("None")) is None
        assert _eval_constant_expr(_p("'hello'")) == "hello"

    def test_unresolvable_returns_sentinel(self) -> None:
        """BinOp is not resolvable -- returns _UNRESOLVABLE sentinel."""
        from skill_scan._ast_kwargs_detector import _UNRESOLVABLE

        node = ast.parse("1 + 2").body[0].value  # type: ignore[attr-defined]
        assert _eval_constant_expr(node) is _UNRESOLVABLE


class TestExtractDictLiteralNegativeValues:
    """_extract_dict_literal resolves negative numeric literals."""

    def test_negative_int_preserved(self) -> None:
        node = ast.parse("{'k': -1}").body[0].value  # type: ignore[attr-defined]
        assert _extract_dict_literal(node) == {"k": -1}

    def test_negative_float_preserved(self) -> None:
        node = ast.parse("{'k': -3.14}").body[0].value  # type: ignore[attr-defined]
        assert _extract_dict_literal(node) == {"k": -3.14}


class TestFalsyStringsRemoved:
    """_FALSY_STRINGS must not exist in the module."""

    def test_no_falsy_strings_attribute(self) -> None:
        import skill_scan._ast_kwargs_detector as mod

        assert not hasattr(mod, "_FALSY_STRINGS")
