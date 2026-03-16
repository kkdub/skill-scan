"""Tests for dict union detection in kwargs unpacking detector.

Covers dict binary union (x = a | b) and augmented union (x |= b) tracking
in _collect_from_body, including scope-aware detection, conflict resolution,
unresolvable operands, and PEP 448 spread regression.
"""

from __future__ import annotations

import ast
import textwrap

from skill_scan._ast_kwargs_detector import _collect_dict_assigns

from tests.unit.kwargs_test_helpers import detect as _detect

_PARSE = ast.parse


# ---------------------------------------------------------------------------
# Binary union: opts = opts | {'shell': True}
# ---------------------------------------------------------------------------


class TestBinaryUnion:
    """Detection of opts = a | b dict union assignment."""

    def test_binary_union_detected(self) -> None:
        """opts = opts | {'shell': True} produces EXEC-002."""
        code = """\
        import subprocess
        opts = {}
        opts = opts | {'shell': True}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_union_right_wins_on_conflict(self) -> None:
        """Right operand overrides left, matching Python semantics."""
        code = """\
        import subprocess
        opts = {'shell': False}
        opts = opts | {'shell': True}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_union_right_overrides_to_safe(self) -> None:
        """Right operand overrides dangerous left to safe value."""
        code = """\
        import subprocess
        opts = {'shell': True}
        opts = opts | {'shell': False}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 0

    def test_union_two_literals(self) -> None:
        """Both operands are dict literals (no variable lookup needed)."""
        code = """\
        import subprocess
        opts = {'stdout': -1} | {'shell': True}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_unresolvable_left_operand_no_finding(self) -> None:
        """Unknown | {'shell': True} produces zero findings (conservative)."""
        code = """\
        import subprocess
        opts = unknown | {'shell': True}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 0

    def test_unresolvable_right_operand_no_finding(self) -> None:
        """{'shell': True} | unknown produces zero findings (conservative)."""
        code = """\
        import subprocess
        opts = {'shell': True} | unknown
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Augmented union: opts |= {'shell': True}
# ---------------------------------------------------------------------------


class TestAugmentedUnion:
    """Detection of opts |= rhs augmented union."""

    def test_augmented_union_detected(self) -> None:
        """opts |= {'shell': True} produces EXEC-002."""
        code = """\
        import subprocess
        opts = {'stdout': -1}
        opts |= {'shell': True}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_aug_union_unresolvable_rhs_drops_tracking(self) -> None:
        """opts |= unknown removes opts from tracking (conservative)."""
        code = """\
        import subprocess
        opts = {'shell': True}
        opts |= unknown
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 0

    def test_aug_union_untracked_target_no_crash(self) -> None:
        """Augmented union on untracked variable does not crash."""
        code = """\
        import subprocess
        opts |= {'shell': True}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 0

    def test_aug_union_preserves_existing_keys(self) -> None:
        """Existing constant keys survive the merge."""
        code = """\
        import subprocess
        opts = {'mode': 'fast'}
        opts |= {'shell': True}
        subprocess.run(['ls'], **opts)
        """
        tree = _PARSE(textwrap.dedent(code))
        da = _collect_dict_assigns(tree)
        assert da["opts"]["mode"] == "fast"
        assert da["opts"]["shell"] == "True"


# ---------------------------------------------------------------------------
# Scope-aware dict union
# ---------------------------------------------------------------------------


class TestDictUnionScoped:
    """Dict union inside function bodies is scope-aware."""

    def test_union_in_function_scope(self) -> None:
        """Binary union inside a function body is detected."""
        code = """\
        import subprocess
        def run_cmd():
            opts = {}
            opts = opts | {'shell': True}
            subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_aug_union_in_function_scope(self) -> None:
        """Augmented union inside a function body is detected."""
        code = """\
        import subprocess
        def run_cmd():
            opts = {'stdout': -1}
            opts |= {'shell': True}
            subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"


# ---------------------------------------------------------------------------
# Regression: PEP 448 spread dicts still unresolvable
# ---------------------------------------------------------------------------


class TestSpreadDictRegression:
    """PEP 448 spread dicts remain unresolvable (no false positives)."""

    def test_spread_dict_still_unresolvable(self) -> None:
        code = "import subprocess; subprocess.run(['ls'], **{**base, 'shell': True})"
        findings = _detect(code)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# _collect_dict_assigns unit tests for union tracking
# ---------------------------------------------------------------------------


class TestCollectDictAssignsUnion:
    """Direct unit tests for _collect_dict_assigns with union operators."""

    def test_binary_union_tracked(self) -> None:
        code = "opts = {}\nopts = opts | {'shell': True}"
        tree = _PARSE(code)
        result = _collect_dict_assigns(tree)
        assert result["opts"] == {"shell": "True"}

    def test_aug_union_tracked(self) -> None:
        code = "opts = {'a': 1}\nopts |= {'b': 2}"
        tree = _PARSE(code)
        result = _collect_dict_assigns(tree)
        assert result["opts"] == {"a": "1", "b": "2"}

    def test_aug_union_unresolvable_removes_entry(self) -> None:
        code = "opts = {'a': 1}\nopts |= unknown"
        tree = _PARSE(code)
        result = _collect_dict_assigns(tree)
        assert "opts" not in result

    def test_binary_union_unresolvable_skipped(self) -> None:
        code = "opts = unknown | {'shell': True}"
        tree = _PARSE(code)
        result = _collect_dict_assigns(tree)
        assert "opts" not in result

    def test_empty_dict_tracked(self) -> None:
        """Empty dict literal is tracked (needed for subsequent union)."""
        code = "opts = {}"
        tree = _PARSE(code)
        result = _collect_dict_assigns(tree)
        assert result["opts"] == {}
