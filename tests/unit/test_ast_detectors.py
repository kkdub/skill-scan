"""Tests for _ast_detectors module and ast_analyzer facade re-exports.

Verifies the module split preserves all import paths and that the
_ast_detectors module contains the expected names.
"""

from __future__ import annotations

import ast

from skill_scan import _ast_detectors
from skill_scan.ast_analyzer import (
    _CATEGORY,
    _DANGEROUS_NAMES,
    _RECOMMENDATIONS,
    _UNSAFE_DESER_CALLS,
    _UNSAFE_EXEC_CALLS,
    _detect_dynamic_access,
    _detect_dynamic_imports,
    _detect_string_concat_evasion,
    _detect_unsafe_calls,
    _detect_unsafe_deserialization,
    _make_finding,
    analyze_python,
)
from skill_scan.models import Finding, Severity


_FILE = "test.py"


# -- Module structure: _ast_detectors has all expected names ----------------


class TestModuleStructure:
    def test_detectors_module_has_category(self) -> None:
        assert _ast_detectors._CATEGORY == "malicious-code"

    def test_detectors_module_has_dangerous_names(self) -> None:
        assert "eval" in _ast_detectors._DANGEROUS_NAMES
        assert "exec" in _ast_detectors._DANGEROUS_NAMES

    def test_detectors_module_has_recommendations(self) -> None:
        assert "EXEC-002" in _ast_detectors._RECOMMENDATIONS
        assert "EXEC-006" in _ast_detectors._RECOMMENDATIONS
        assert "EXEC-007" in _ast_detectors._RECOMMENDATIONS

    def test_detectors_module_has_unsafe_exec_calls(self) -> None:
        assert "eval" in _ast_detectors._UNSAFE_EXEC_CALLS
        assert "os.system" in _ast_detectors._UNSAFE_EXEC_CALLS

    def test_detectors_module_has_unsafe_deser_calls(self) -> None:
        assert "pickle.loads" in _ast_detectors._UNSAFE_DESER_CALLS
        assert "yaml.unsafe_load" in _ast_detectors._UNSAFE_DESER_CALLS

    def test_detectors_module_has_detect_functions(self) -> None:
        assert callable(_ast_detectors._detect_unsafe_calls)
        assert callable(_ast_detectors._detect_dynamic_imports)
        assert callable(_ast_detectors._detect_unsafe_deserialization)
        assert callable(_ast_detectors._detect_string_concat_evasion)
        assert callable(_ast_detectors._detect_dynamic_access)

    def test_detectors_module_has_make_finding(self) -> None:
        assert callable(_ast_detectors._make_finding)


# -- Facade re-exports resolve to the same objects --------------------------


class TestFacadeReexports:
    def test_category_reexport(self) -> None:
        assert _CATEGORY is _ast_detectors._CATEGORY

    def test_dangerous_names_reexport(self) -> None:
        assert _DANGEROUS_NAMES is _ast_detectors._DANGEROUS_NAMES

    def test_recommendations_reexport(self) -> None:
        assert _RECOMMENDATIONS is _ast_detectors._RECOMMENDATIONS

    def test_unsafe_exec_calls_reexport(self) -> None:
        assert _UNSAFE_EXEC_CALLS is _ast_detectors._UNSAFE_EXEC_CALLS

    def test_unsafe_deser_calls_reexport(self) -> None:
        assert _UNSAFE_DESER_CALLS is _ast_detectors._UNSAFE_DESER_CALLS

    def test_detect_unsafe_calls_reexport(self) -> None:
        assert _detect_unsafe_calls is _ast_detectors._detect_unsafe_calls

    def test_detect_dynamic_imports_reexport(self) -> None:
        assert _detect_dynamic_imports is _ast_detectors._detect_dynamic_imports

    def test_detect_unsafe_deserialization_reexport(self) -> None:
        assert _detect_unsafe_deserialization is _ast_detectors._detect_unsafe_deserialization

    def test_detect_string_concat_evasion_reexport(self) -> None:
        assert _detect_string_concat_evasion is _ast_detectors._detect_string_concat_evasion

    def test_detect_dynamic_access_reexport(self) -> None:
        assert _detect_dynamic_access is _ast_detectors._detect_dynamic_access

    def test_make_finding_reexport(self) -> None:
        assert _make_finding is _ast_detectors._make_finding

    def test_analyze_python_still_importable(self) -> None:
        assert callable(analyze_python)


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

    def test_non_call_node_returns_empty(self) -> None:
        tree = ast.parse("x = 1\n")
        assign_node = next(n for n in ast.walk(tree) if isinstance(n, ast.Assign))
        assert _detect_unsafe_calls(assign_node, _FILE) == []
        assert _detect_dynamic_imports(assign_node, _FILE) == []
        assert _detect_unsafe_deserialization(assign_node, _FILE) == []
        assert _detect_dynamic_access(assign_node, _FILE) == []
