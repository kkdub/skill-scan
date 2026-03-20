"""Tests for dynamic key resolution in _ast_kwargs_dict_tracker.

Covers _extract_dict_literal with BinOp(Add) concatenated string keys and
Name keys resolved via a local string table, as well as _collect_dict_assigns
end-to-end with concatenated key patterns.
"""

from __future__ import annotations

import ast

from skill_scan._ast_kwargs_detector import (
    _collect_dict_assigns,
    _extract_dict_literal,
)

from tests.unit.kwargs_test_utils import detect as _detect, detect_full as _detect_full

_PARSE = ast.parse


# ---------------------------------------------------------------------------
# _extract_dict_literal: inline BinOp(Add) string keys
# ---------------------------------------------------------------------------


class TestExtractDictLiteralBinOpKey:
    """_extract_dict_literal resolves BinOp(Add) concatenated string keys."""

    def test_inline_binop_key_resolved(self) -> None:
        """{'sh' + 'ell': True} resolves to {'shell': True}."""
        node = _PARSE("{'sh' + 'ell': True}").body[0].value  # type: ignore[attr-defined]
        result = _extract_dict_literal(node)
        assert result is not None
        assert result["shell"] is True

    def test_triple_concat_key_resolved(self) -> None:
        """{'s' + 'h' + 'ell': True} resolves to {'shell': True}."""
        node = _PARSE("{'s' + 'h' + 'ell': True}").body[0].value  # type: ignore[attr-defined]
        result = _extract_dict_literal(node)
        assert result is not None
        assert result["shell"] is True

    def test_mixed_constant_and_binop_keys(self) -> None:
        """Dict with both constant and BinOp keys resolves all."""
        node = _PARSE("{'a': 1, 'sh' + 'ell': True}").body[0].value  # type: ignore[attr-defined]
        result = _extract_dict_literal(node)
        assert result is not None
        assert result == {"a": 1, "shell": True}

    def test_non_string_binop_skipped(self) -> None:
        """BinOp with non-string operands (int + int) is skipped gracefully."""
        node = _PARSE("{1 + 2: 'val'}").body[0].value  # type: ignore[attr-defined]
        result = _extract_dict_literal(node)
        assert result is not None
        assert result == {}

    def test_constant_key_still_works(self) -> None:
        """Existing constant-key behavior is unchanged (no regression)."""
        node = _PARSE("{'shell': True, 'stdout': -1}").body[0].value  # type: ignore[attr-defined]
        result = _extract_dict_literal(node)
        assert result is not None
        assert result == {"shell": True, "stdout": -1}


# ---------------------------------------------------------------------------
# _collect_dict_assigns: Name key from local string table
# ---------------------------------------------------------------------------


class TestCollectDictAssignsNameKey:
    """_collect_dict_assigns resolves Name keys via local string table."""

    def test_name_key_from_constant_assignment(self) -> None:
        """key = 'shell'; opts = {key: True} resolves to {'shell': True}."""
        code = "key = 'shell'\nopts = {key: True}"
        tree = _PARSE(code)
        result = _collect_dict_assigns(tree)
        assert "opts" in result
        assert result["opts"] == {"shell": True}

    def test_name_key_from_binop_assignment(self) -> None:
        """key = 'sh' + 'ell'; opts = {key: True} resolves to {'shell': True}."""
        code = "key = 'sh' + 'ell'\nopts = {key: True}"
        tree = _PARSE(code)
        result = _collect_dict_assigns(tree)
        assert "opts" in result
        assert result["opts"] == {"shell": True}

    def test_unresolvable_name_key_skipped(self) -> None:
        """key = get_key(); opts = {key: True} -- unresolvable Name is skipped."""
        code = "key = get_key()\nopts = {key: True}"
        tree = _PARSE(code)
        result = _collect_dict_assigns(tree)
        # opts should be tracked but with key skipped (not crash)
        assert "opts" in result
        assert result["opts"] == {}

    def test_name_key_in_function_scope(self) -> None:
        """Name key resolution works inside function scope."""
        code = """\
def run():
    k = 'shell'
    opts = {k: True}
"""
        tree = _PARSE(code)
        result = _collect_dict_assigns(tree)
        assert "run.opts" in result
        assert result["run.opts"] == {"shell": True}

    def test_name_key_mixed_with_constant_keys(self) -> None:
        """Dict with both Name and constant keys resolves all."""
        code = "k = 'shell'\nopts = {k: True, 'stdout': -1}"
        tree = _PARSE(code)
        result = _collect_dict_assigns(tree)
        assert result["opts"] == {"shell": True, "stdout": -1}


# ---------------------------------------------------------------------------
# R004: End-to-end detection with concatenated key
# ---------------------------------------------------------------------------


class TestConcatenatedKeyDetection:
    """Kwargs detection works with dynamically constructed dict keys."""

    def test_concat_key_produces_exec002(self) -> None:
        """key = 'sh' + 'ell'; opts = {key: True}; subprocess.run(**opts) => EXEC-002."""
        code = """\
        import subprocess
        key = 'sh' + 'ell'
        opts = {key: True}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_inline_binop_key_produces_exec002(self) -> None:
        """opts = {'sh' + 'ell': True}; subprocess.run(**opts) => EXEC-002."""
        code = """\
        import subprocess
        opts = {'sh' + 'ell': True}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_concat_key_full_pipeline(self) -> None:
        """Full analyze_python pipeline catches concatenated key evasion."""
        code = """\
        import subprocess
        key = 'sh' + 'ell'
        opts = {key: True}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect_full(code)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1


# ---------------------------------------------------------------------------
# Regression: existing constant-key behavior unchanged
# ---------------------------------------------------------------------------


class TestConstantKeyRegression:
    """Existing constant-key dict extraction is unchanged."""

    def test_spread_still_returns_none(self) -> None:
        """**spread dicts still return None."""
        node = _PARSE("{**base, 'shell': True}").body[0].value  # type: ignore[attr-defined]
        result = _extract_dict_literal(node)
        assert result is None

    def test_constant_key_dict_still_works(self) -> None:
        """{'shell': True} still resolves correctly."""
        code = """\
        import subprocess
        opts = {'shell': True}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"
