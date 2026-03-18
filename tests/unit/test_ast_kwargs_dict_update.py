"""Tests for dict.update() tracking in kwargs unpacking detector.

Covers _collect_from_body handling of ast.Expr(Call) where func.attr == 'update',
including literal dict args, tracked variable args, chained updates, scope-aware
detection, and safe-case negatives (keyword args, no args, non-resolvable args).
"""

from __future__ import annotations

import ast

from skill_scan._ast_kwargs_detector import _collect_dict_assigns

from tests.unit.kwargs_test_helpers import detect as _detect, detect_full as _detect_full

_PARSE = ast.parse


# ---------------------------------------------------------------------------
# R007: dict.update() tracking -- detection via kwargs unpacking
# ---------------------------------------------------------------------------


class TestDictUpdateDetection:
    """opts.update({'shell': True}) tracked in dict pre-pass produces EXEC-002."""

    def test_update_literal_dict_detected(self) -> None:
        """opts.update({'shell': True}) produces EXEC-002."""
        code = """\
        import subprocess
        opts = {}
        opts.update({'shell': True})
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_update_tracked_variable(self) -> None:
        """opts.update(other_dict) where other_dict is tracked."""
        code = """\
        import subprocess
        danger = {'shell': True}
        opts = {'stdout': -1}
        opts.update(danger)
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_chained_updates_merge(self) -> None:
        """opts.update(a); opts.update(b) merges both."""
        code = """\
        import subprocess
        opts = {}
        opts.update({'timeout': 30})
        opts.update({'shell': True})
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_update_in_function_scope(self) -> None:
        """dict.update inside function body is scope-aware."""
        code = """\
        import subprocess
        def run_cmd():
            opts = {}
            opts.update({'shell': True})
            subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"


# ---------------------------------------------------------------------------
# R007: dict.update() tracking -- _collect_dict_assigns unit tests
# ---------------------------------------------------------------------------


class TestDictUpdateCollect:
    """Direct unit tests for _collect_dict_assigns with .update() calls."""

    def test_update_on_untracked_creates_entry(self) -> None:
        """opts.update({'shell': True}) on untracked variable creates new entry."""
        tree = _PARSE("opts.update({'shell': True})")
        result = _collect_dict_assigns(tree)
        assert result["opts"] == {"shell": True}

    def test_update_preserves_existing_keys(self) -> None:
        """Existing keys survive after .update() merge."""
        code = "opts = {'mode': 'fast'}\nopts.update({'shell': True})"
        tree = _PARSE(code)
        result = _collect_dict_assigns(tree)
        assert result["opts"]["mode"] == "fast"
        assert result["opts"]["shell"] is True

    def test_update_right_wins_on_conflict(self) -> None:
        """Update value overrides existing key (right-wins semantics)."""
        code = "opts = {'shell': False}\nopts.update({'shell': True})"
        tree = _PARSE(code)
        result = _collect_dict_assigns(tree)
        assert result["opts"]["shell"] is True

    def test_chained_updates_tracked(self) -> None:
        """Multiple .update() calls accumulate correctly."""
        code = "opts = {}\nopts.update({'a': 1})\nopts.update({'b': 2})"
        tree = _PARSE(code)
        result = _collect_dict_assigns(tree)
        assert result["opts"] == {"a": 1, "b": 2}


# ---------------------------------------------------------------------------
# R007: dict.update() safe cases -- no false positives
# ---------------------------------------------------------------------------


class TestDictUpdateSafeCases:
    """Non-dict update args are silently skipped (no false positives)."""

    def test_update_keyword_args_skipped(self) -> None:
        """opts.update(shell=True) with keyword args is silently skipped."""
        code = """\
        import subprocess
        opts = {}
        opts.update(shell=True)
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert len(findings) == 0

    def test_update_no_args_skipped(self) -> None:
        """opts.update() with no args is silently skipped."""
        code = "opts = {}\nopts.update()"
        tree = _PARSE(code)
        result = _collect_dict_assigns(tree)
        assert result["opts"] == {}

    def test_update_non_dict_arg_skipped(self) -> None:
        """opts.update(some_call()) with non-resolvable arg is skipped."""
        code = "opts = {}\nopts.update(get_config())"
        tree = _PARSE(code)
        result = _collect_dict_assigns(tree)
        assert result["opts"] == {}

    def test_update_multiple_positional_args_skipped(self) -> None:
        """opts.update(a, b) with multiple args is silently skipped."""
        code = "opts = {}\nopts.update({'a': 1}, {'b': 2})"
        tree = _PARSE(code)
        result = _collect_dict_assigns(tree)
        assert result["opts"] == {}


# ---------------------------------------------------------------------------
# R-EFF001: Corpus file kwargs_method_chain.py produces EXEC-002
# ---------------------------------------------------------------------------


class TestCorpusKwargsMethodChain:
    """Corpus file kwargs_method_chain.py produces EXEC-002 finding."""

    def test_corpus_kwargs_method_chain(self) -> None:
        """Red-team corpus: dict built via update() method."""
        code = """\
        import subprocess
        opts = {}
        opts.update({'timeout': 30})
        opts.update({'shell': True})
        subprocess.run(['echo', 'hello'], **opts)
        """
        findings = _detect_full(code)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1
