"""Tests for AST hardening: RecursionError, depth limits, INFO finding.

Covers resilience against adversarial inputs with deeply nested AST trees,
depth-limited recursive resolution helpers, and informative findings on
parse failures.
"""

from __future__ import annotations

import ast

from skill_scan._ast_helpers import MAX_AST_RESOLVE_DEPTH, try_resolve_string
from skill_scan.ast_analyzer import analyze_python
from skill_scan.models import Severity
from tests.unit.rule_helpers import filter_by_rule

_FILE = "test.py"
_ids = filter_by_rule


# -- Helpers ---------------------------------------------------------------


def _build_nested_binop_source(depth: int) -> str:
    """Build Python source with deeply nested string concatenation."""
    parts = [f"'{chr(97 + (i % 26))}'" for i in range(depth)]
    expr = " + ".join(parts)
    return f"x = {expr}\n"


def _build_nested_binop_node(depth: int) -> ast.BinOp:
    """Build a deeply nested BinOp AST node (left-leaning tree)."""
    node: ast.expr = ast.Constant(value="a")
    for _ in range(depth):
        node = ast.BinOp(left=node, op=ast.Add(), right=ast.Constant(value="b"))
    assert isinstance(node, ast.BinOp)
    return node


# -- RecursionError resilience (R001) --------------------------------------


class TestRecursionErrorResilience:
    def test_deeply_nested_binop_no_crash(self) -> None:
        source = _build_nested_binop_source(200)
        # Must not raise RecursionError -- returns a list (possibly empty)
        result = analyze_python(source, _FILE)
        assert isinstance(result, list)

    def test_recursion_error_returns_accumulated_findings(self) -> None:
        # Source with a real finding followed by deeply nested concat
        source = "eval('x')\n" + _build_nested_binop_source(200)
        result = analyze_python(source, _FILE)
        assert isinstance(result, list)
        # eval finding should be present (accumulated before any recursion issue)
        eval_findings = _ids("EXEC-002", result)
        assert len(eval_findings) >= 1


# -- Depth limits in AST helpers (R002) ------------------------------------


class TestAstDepthLimits:
    def test_resolve_string_returns_none_at_depth_limit(self) -> None:
        node = _build_nested_binop_node(MAX_AST_RESOLVE_DEPTH + 10)
        result = try_resolve_string(node)
        assert result is None

    def test_resolve_string_works_within_limit(self) -> None:
        node = _build_nested_binop_node(5)
        result = try_resolve_string(node)
        assert result == "a" + "b" * 5

    def test_max_ast_resolve_depth_is_50(self) -> None:
        assert MAX_AST_RESOLVE_DEPTH == 50


# -- AST-PARSE INFO finding (R003) ----------------------------------------


class TestAstParseInfoFinding:
    def test_syntax_error_produces_ast_parse_finding(self) -> None:
        findings = analyze_python("def broken(\n", _FILE)
        assert len(findings) == 1
        assert findings[0].rule_id == "AST-PARSE"
        assert findings[0].severity == Severity.INFO
        assert findings[0].line is None
        assert "parse error" in findings[0].description.lower()

    def test_ast_parse_finding_has_file_path(self) -> None:
        findings = analyze_python("not valid {{\n", "my/bad.py")
        assert len(findings) == 1
        assert findings[0].file == "my/bad.py"

    def test_valid_python_no_ast_parse_finding(self) -> None:
        findings = analyze_python("x = 1\n", _FILE)
        ast_parse = [f for f in findings if f.rule_id == "AST-PARSE"]
        assert not ast_parse


# -- Acceptance scenarios (full feature path) ------------------------------


class TestAcceptanceAstHardening:
    def test_deeply_nested_adversarial_input_no_crash(self) -> None:
        """AST analysis of deeply nested adversarial input does not crash.

        Invokes analyze_python with source containing 100+ nested
        string concatenations. Must return a list without raising.
        """
        result = analyze_python(_build_nested_binop_source(150), _FILE)
        assert isinstance(result, list)
