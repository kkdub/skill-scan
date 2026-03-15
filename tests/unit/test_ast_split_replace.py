"""Tests for .replace() chain detection in the split evasion detector.

Covers _resolve_replace_chain() directly and via the full detect_split_evasion
pipeline. Exercises 2-step, 3+ step, variable-base, and safe-string cases.
"""

from __future__ import annotations

import ast
import textwrap

from skill_scan._ast_split_detector import detect_split_evasion
from skill_scan._ast_split_resolve import _resolve_replace_chain
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.models import Finding

_PARSE = ast.parse
_FILE = "test.py"


def _detect(code: str) -> list[Finding]:
    """Helper: parse code, build symbol table, run split detector."""
    tree = _PARSE(code)
    st = build_symbol_table(tree)
    return detect_split_evasion(tree, _FILE, {}, st)


def _resolve(code: str) -> str | None:
    """Helper: parse a single expression and resolve its replace chain."""
    tree = _PARSE(code)
    st = build_symbol_table(tree)
    # Find the first Call node with .replace in the tree
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "replace"
        ):
            return _resolve_replace_chain(node, st, "")
    return None


class TestResolveReplaceChainDirect:
    """Unit tests for _resolve_replace_chain resolver function."""

    def test_two_step_literal_base(self) -> None:
        result = _resolve("x = 'eXYl'.replace('X', 'va').replace('Y', '')")
        assert result == "eval"

    def test_three_step_literal_base(self) -> None:
        result = _resolve("x = 'abbc'.replace('a', 'e').replace('bb', 'xe').replace('c', 'c')")
        assert result == "exec"

    def test_variable_base_from_symbol_table(self) -> None:
        code = textwrap.dedent("""\
            base = "syZZem"
            x = base.replace("ZZ", "st")
        """)
        result = _resolve(code)
        assert result == "system"

    def test_single_replace_literal_base(self) -> None:
        result = _resolve("x = 'evXl'.replace('X', 'a')")
        assert result == "eval"

    def test_safe_replace_returns_safe_string(self) -> None:
        result = _resolve("x = 'hello'.replace('h', 'j')")
        assert result == "jello"

    def test_untracked_variable_returns_none(self) -> None:
        code = "x = unknown.replace('a', 'b')"
        result = _resolve(code)
        assert result is None

    def test_non_string_arg_returns_none(self) -> None:
        """Replace with non-constant args returns None."""
        code = "x = 'hello'.replace(y, 'z')"
        result = _resolve(code)
        assert result is None

    def test_keyword_arg_replace_returns_none(self) -> None:
        """Replace with keyword arguments returns None (resolver bails out)."""
        # str.replace doesn't accept kwargs in CPython, but AST can parse them
        code = "x = 'hello'.replace(old='h', new='j')"
        result = _resolve(code)
        assert result is None

    def test_non_call_base_returns_none(self) -> None:
        """Replace on a complex expression base returns None."""
        code = "x = (a + b).replace('x', 'y')"
        result = _resolve(code)
        assert result is None


class TestReplaceChainDetection:
    """Integration tests: .replace() chains detected via full pipeline."""

    def test_two_step_eval_produces_exec_002(self) -> None:
        findings = _detect("name = 'eXYl'.replace('X', 'va').replace('Y', '')")
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1
        assert any("eval" in f.description for f in exec_findings)

    def test_three_step_exec_produces_exec_002(self) -> None:
        findings = _detect("name = 'abbc'.replace('a', 'e').replace('bb', 'xe').replace('c', 'c')")
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1
        assert any("exec" in f.description for f in exec_findings)

    def test_variable_base_system_produces_exec_002(self) -> None:
        code = textwrap.dedent("""\
            base = "syZZem"
            name = base.replace("ZZ", "st")
        """)
        findings = _detect(code)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1
        assert any("system" in f.description for f in exec_findings)

    def test_replace_chain_import_produces_exec_006(self) -> None:
        findings = _detect("name = '__imXort__'.replace('X', 'p')")
        exec_findings = [f for f in findings if f.rule_id == "EXEC-006"]
        assert len(exec_findings) >= 1
        assert any("__import__" in f.description for f in exec_findings)

    def test_safe_replace_produces_no_findings(self) -> None:
        findings = _detect("msg = 'hello'.replace('h', 'j')")
        exec_findings = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert len(exec_findings) == 0

    def test_safe_multi_replace_produces_no_findings(self) -> None:
        code = "cleaned = 'foo_bar'.replace('_', '-').replace('bar', 'qux')"
        findings = _detect(code)
        exec_findings = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert len(exec_findings) == 0

    def test_safe_variable_base_replace_produces_no_findings(self) -> None:
        code = textwrap.dedent("""\
            template = "Dear NAME"
            msg = template.replace("NAME", "Alice")
        """)
        findings = _detect(code)
        exec_findings = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert len(exec_findings) == 0


class TestReplaceChainEdgeCases:
    """Edge cases for .replace() chain resolution."""

    def test_empty_replace_args(self) -> None:
        """Replace with empty string args is valid Python."""
        result = _resolve("x = 'eval'.replace('', '')")
        assert result == "eval"

    def test_replace_chain_popen(self) -> None:
        """Builds 'popen' via replace chain."""
        result = _resolve("x = 'pXpen'.replace('X', 'o')")
        assert result == "popen"

    def test_replace_preserves_order(self) -> None:
        """Replacements apply left-to-right as in Python."""
        # First replace: 'aXc' -> 'abc', second: 'abc' -> 'axc'
        result = _resolve("x = 'aXc'.replace('X', 'b').replace('b', 'x')")
        assert result == "axc"
