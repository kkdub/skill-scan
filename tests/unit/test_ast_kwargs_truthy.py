"""Tests for truthy value matching in kwargs unpacking detector.

Covers boolean truthiness normalization in _kwarg_matches: integer truthy
values (1, 2) match boolean True table entries, integer falsy values (0)
do not, and non-boolean table entries use exact string comparison.
"""

from __future__ import annotations

import pytest

from skill_scan._ast_kwargs_detector import _FALSY_STRINGS, _kwarg_matches
from skill_scan.models import Severity

from tests.unit.kwargs_test_helpers import detect as _detect, detect_full as _detect_full


# ---------------------------------------------------------------------------
# R004: Integer truthy values match boolean True table entries
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# R005: Integer falsy values do NOT match boolean True table entries
# ---------------------------------------------------------------------------


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

    def test_dict_literal_shell_int_0_no_finding(self) -> None:
        """Dict literal init with integer 0 produces no finding."""
        code = """\
        import subprocess
        opts = {'shell': 0}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# R006: Non-boolean table values use exact string comparison
# ---------------------------------------------------------------------------


class TestNonBooleanExactMatch:
    """Non-boolean table entries do NOT get truthy normalization."""

    def test_kwarg_matches_exact_string_value(self) -> None:
        """String table value uses exact comparison, not truthiness."""
        # "1" is truthy but should NOT match "True" with exact comparison
        assert _kwarg_matches({"key": "1"}, "key", "True") is False
        assert _kwarg_matches({"key": "True"}, "key", "True") is True

    def test_kwarg_matches_exact_int_value(self) -> None:
        """Integer table value uses exact str() comparison."""
        assert _kwarg_matches({"key": "42"}, "key", 42) is True
        assert _kwarg_matches({"key": "1"}, "key", 42) is False


# ---------------------------------------------------------------------------
# _kwarg_matches unit tests for truthy logic
# ---------------------------------------------------------------------------


class TestKwargMatchesTruthy:
    """Direct unit tests for _kwarg_matches with boolean table values."""

    def test_bool_true_matches_string_true(self) -> None:
        assert _kwarg_matches({"shell": "True"}, "shell", True) is True

    def test_bool_true_matches_int_1(self) -> None:
        assert _kwarg_matches({"shell": "1"}, "shell", True) is True

    def test_bool_true_matches_int_2(self) -> None:
        assert _kwarg_matches({"shell": "2"}, "shell", True) is True

    def test_bool_true_matches_nonzero_string(self) -> None:
        assert _kwarg_matches({"shell": "anything"}, "shell", True) is True

    def test_bool_true_no_match_string_false(self) -> None:
        assert _kwarg_matches({"shell": "False"}, "shell", True) is False

    def test_bool_true_no_match_string_0(self) -> None:
        assert _kwarg_matches({"shell": "0"}, "shell", True) is False

    def test_bool_true_no_match_string_none(self) -> None:
        assert _kwarg_matches({"shell": "None"}, "shell", True) is False

    def test_bool_true_no_match_empty_string(self) -> None:
        assert _kwarg_matches({"shell": ""}, "shell", True) is False

    def test_bool_true_no_match_lowercase_false(self) -> None:
        assert _kwarg_matches({"shell": "false"}, "shell", True) is False

    def test_bool_false_matches_string_0(self) -> None:
        assert _kwarg_matches({"shell": "0"}, "shell", False) is True

    def test_bool_false_matches_string_false(self) -> None:
        assert _kwarg_matches({"shell": "False"}, "shell", False) is True

    def test_bool_false_no_match_string_1(self) -> None:
        assert _kwarg_matches({"shell": "1"}, "shell", False) is False

    def test_bool_false_no_match_string_true(self) -> None:
        assert _kwarg_matches({"shell": "True"}, "shell", False) is False

    @pytest.mark.parametrize("val", sorted(_FALSY_STRINGS))
    def test_all_falsy_strings_match_bool_false(self, val: str) -> None:
        assert _kwarg_matches({"k": val}, "k", False) is True

    @pytest.mark.parametrize("val", sorted(_FALSY_STRINGS))
    def test_all_falsy_strings_reject_bool_true(self, val: str) -> None:
        assert _kwarg_matches({"k": val}, "k", True) is False


# ---------------------------------------------------------------------------
# Acceptance scenarios (plan-level)
# ---------------------------------------------------------------------------


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
