"""Tests for chained dict union recursion in kwargs unpacking detector.

Covers chained dict union (a | b | c) via BinOp recursion in
_resolve_dict_operand, including right-wins semantics, unresolvable
operand handling, and _collect_dict_assigns tracking.
"""

from __future__ import annotations

import ast

from skill_scan._ast_kwargs_detector import _collect_dict_assigns

from tests.unit.kwargs_test_utils import detect as _detect

_PARSE = ast.parse


# ---------------------------------------------------------------------------
# Chained union detection: opts = a | b | c (BinOp recursion)
# ---------------------------------------------------------------------------


class TestChainedUnion:
    """Detection of chained dict unions (a | b | c) via BinOp recursion."""

    def test_three_way_union_detected(self) -> None:
        """a | b | c with shell=True in rightmost produces EXEC-002."""
        code = """\
        import subprocess
        a = {'stdout': -1}
        b = {'stderr': -1}
        opts = a | b | {'shell': True}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_three_way_union_right_wins(self) -> None:
        """Rightmost operand wins on key conflicts in chained union."""
        code = """\
        import subprocess
        a = {'shell': True}
        b = {'mode': 'fast'}
        opts = a | b | {'shell': False}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 0

    def test_three_way_union_middle_wins_over_left(self) -> None:
        """Middle operand overrides left, right preserves it."""
        code = """\
        import subprocess
        a = {'shell': False}
        b = {'shell': True}
        opts = a | b | {'stderr': -1}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_three_way_all_literals(self) -> None:
        """Three dict literals chained together."""
        code = """\
        import subprocess
        opts = {'stdout': -1} | {'stderr': -1} | {'shell': True}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_chained_unresolvable_middle_returns_none(self) -> None:
        """Unresolvable middle operand causes entire chain to return None."""
        code = """\
        import subprocess
        a = {'stdout': -1}
        opts = a | unknown | {'shell': True}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 0

    def test_chained_unresolvable_first_returns_none(self) -> None:
        """Unresolvable first operand causes entire chain to return None."""
        code = """\
        import subprocess
        opts = unknown | {'stderr': -1} | {'shell': True}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# _collect_dict_assigns unit tests for chained union tracking
# ---------------------------------------------------------------------------


class TestCollectDictAssignsChainedUnion:
    """Direct unit tests for _collect_dict_assigns with chained unions."""

    def test_chained_three_way_union_tracked(self) -> None:
        """Three-way union a | b | c is tracked with right-wins semantics."""
        code = "a = {'x': 1}\nb = {'y': 2}\nopts = a | b | {'z': 3}"
        tree = _PARSE(code)
        result = _collect_dict_assigns(tree)
        assert result["opts"] == {"x": 1, "y": 2, "z": 3}

    def test_chained_union_right_wins_on_conflict(self) -> None:
        """Three-way union: rightmost value wins key conflict."""
        code = "a = {'k': 'old'}\nb = {'k': 'mid'}\nopts = a | b | {'k': 'new'}"
        tree = _PARSE(code)
        result = _collect_dict_assigns(tree)
        assert result["opts"] == {"k": "new"}

    def test_chained_union_unresolvable_skipped(self) -> None:
        """Three-way union with unresolvable operand is not tracked."""
        code = "a = {'x': '1'}\nopts = a | unknown | {'z': '3'}"
        tree = _PARSE(code)
        result = _collect_dict_assigns(tree)
        assert "opts" not in result
