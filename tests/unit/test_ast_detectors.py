"""Tests for _ast_detectors direct invocation and _make_finding."""

from __future__ import annotations

import ast

from skill_scan.ast_analyzer import (
    _detect_dynamic_access,
    _detect_dynamic_imports,
    _detect_string_concat_evasion,
    _detect_unsafe_calls,
    _detect_unsafe_deserialization,
    _make_finding,
)
from skill_scan.models import Finding, Severity


_FILE = "test.py"


# -- _make_finding produces correct Finding ---------------------------------


class TestMakeFinding:
    def test_basic_finding(self) -> None:
        f = _make_finding(
            rule_id="EXEC-002",
            severity=Severity.CRITICAL,
            file="test.py",
            line=1,
            matched_text="eval(",
            description="test desc",
        )
        assert isinstance(f, Finding)
        assert f.rule_id == "EXEC-002"
        assert f.severity == Severity.CRITICAL
        assert f.category == "malicious-code"
        assert f.file == "test.py"
        assert f.line == 1
        assert f.matched_text == "eval("
        assert f.description == "test desc"
        assert (
            f.recommendation == "Remove dynamic code execution; use safe alternatives with validated inputs"
        )

    def test_unknown_rule_default_recommendation(self) -> None:
        f = _make_finding(
            rule_id="UNKNOWN-999",
            severity=Severity.LOW,
            file="test.py",
            line=1,
            matched_text="x",
            description="test",
        )
        assert f.recommendation == "Review and remove unsafe pattern"


# -- Detector functions work when called directly ---------------------------


class TestDetectorsDirect:
    def test_detect_unsafe_calls_eval(self) -> None:
        tree = ast.parse("eval('x')\n")
        call_node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_unsafe_calls(call_node, _FILE)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_detect_dynamic_imports_dunder(self) -> None:
        tree = ast.parse("__import__('os')\n")
        call_node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_dynamic_imports(call_node, _FILE)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-006"

    def test_detect_unsafe_deserialization_pickle(self) -> None:
        tree = ast.parse("pickle.loads(data)\n")
        call_node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_unsafe_deserialization(call_node, _FILE)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-007"

    def test_detect_string_concat_evasion_binop(self) -> None:
        tree = ast.parse("x = 'ev' + 'al'\n")
        binop_node = next(n for n in ast.walk(tree) if isinstance(n, ast.BinOp))
        findings = _detect_string_concat_evasion(binop_node, _FILE)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"
        assert "evasion" in findings[0].description.lower()

    def test_detect_dynamic_access_getattr(self) -> None:
        tree = ast.parse("getattr(obj, 'ev' + 'al')\n")
        call_nodes = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
        # The getattr call is the outermost Call node
        getattr_node = next(n for n in call_nodes if isinstance(n.func, ast.Name) and n.func.id == "getattr")
        findings = _detect_dynamic_access(getattr_node, _FILE)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-006"

    def test_detect_unsafe_calls_safe_returns_empty(self) -> None:
        tree = ast.parse("print('hello')\n")
        call_node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_unsafe_calls(call_node, _FILE)
        assert findings == []
