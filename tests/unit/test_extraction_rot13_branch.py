"""Tests for ROT13 branch analysis extraction to _ast_rot13_branch_analysis.py (PLAN-033 Part A).

Verifies:
- R002: _ast_rot13_branch_analysis.py exists and exports the expected functions
- R002: Branch analysis functions produce correct results from the new module
- R-IMP001: Existing detection behavior is preserved (custom ROT13 still detected)
- R-IMP003: _ast_rot13.py still imports _branch_case from the new module
- R-IMP004: Line count constraints are met
"""

from __future__ import annotations

import ast
import importlib
import inspect
from pathlib import Path


_FILE = "test.py"


class TestRot13BranchModuleExists:
    """The new _ast_rot13_branch_analysis module must exist and export correctly."""

    def test_module_importable(self) -> None:
        """_ast_rot13_branch_analysis can be imported."""
        mod = importlib.import_module("skill_scan._ast_rot13_branch_analysis")
        assert mod is not None

    def test_branch_case_exported(self) -> None:
        """_branch_case is importable from the new module."""
        from skill_scan._ast_rot13_branch_analysis import _branch_case

        assert callable(_branch_case)

    def test_compare_case_exported(self) -> None:
        """_compare_case is importable from the new module."""
        from skill_scan._ast_rot13_branch_analysis import _compare_case

        assert callable(_compare_case)

    def test_case_from_comparators_exported(self) -> None:
        """_case_from_comparators is importable from the new module."""
        from skill_scan._ast_rot13_branch_analysis import _case_from_comparators

        assert callable(_case_from_comparators)

    def test_case_from_constant_exported(self) -> None:
        """_case_from_constant is importable from the new module."""
        from skill_scan._ast_rot13_branch_analysis import _case_from_constant

        assert callable(_case_from_constant)

    def test_first_case_from_boolop_exported(self) -> None:
        """_first_case_from_boolop is importable from the new module."""
        from skill_scan._ast_rot13_branch_analysis import _first_case_from_boolop

        assert callable(_first_case_from_boolop)


class TestBranchCaseBehavior:
    """Branch analysis functions in the new module must produce correct results."""

    def test_case_from_constant_lowercase_a(self) -> None:
        """'a' constant -> 'lower'."""
        from skill_scan._ast_rot13_branch_analysis import _case_from_constant

        node = ast.Constant(value="a")
        assert _case_from_constant(node) == "lower"

    def test_case_from_constant_lowercase_z(self) -> None:
        """'z' constant -> 'lower'."""
        from skill_scan._ast_rot13_branch_analysis import _case_from_constant

        node = ast.Constant(value="z")
        assert _case_from_constant(node) == "lower"

    def test_case_from_constant_uppercase_A(self) -> None:
        """'A' constant -> 'upper'."""
        from skill_scan._ast_rot13_branch_analysis import _case_from_constant

        node = ast.Constant(value="A")
        assert _case_from_constant(node) == "upper"

    def test_case_from_constant_uppercase_Z(self) -> None:
        """'Z' constant -> 'upper'."""
        from skill_scan._ast_rot13_branch_analysis import _case_from_constant

        node = ast.Constant(value="Z")
        assert _case_from_constant(node) == "upper"

    def test_case_from_constant_non_sentinel(self) -> None:
        """Non-sentinel constant -> None."""
        from skill_scan._ast_rot13_branch_analysis import _case_from_constant

        node = ast.Constant(value="m")
        assert _case_from_constant(node) is None

    def test_case_from_constant_non_string(self) -> None:
        """Non-string constant -> None."""
        from skill_scan._ast_rot13_branch_analysis import _case_from_constant

        node = ast.Constant(value=42)
        assert _case_from_constant(node) is None

    def test_compare_case_lower_range(self) -> None:
        """Compare 'a' <= c <= 'z' -> 'lower'."""
        from skill_scan._ast_rot13_branch_analysis import _compare_case

        code = "'a' <= c <= 'z'"
        tree = ast.parse(code, mode="eval")
        assert _compare_case(tree.body) == "lower"

    def test_compare_case_upper_range(self) -> None:
        """Compare 'A' <= c <= 'Z' -> 'upper'."""
        from skill_scan._ast_rot13_branch_analysis import _compare_case

        code = "'A' <= c <= 'Z'"
        tree = ast.parse(code, mode="eval")
        assert _compare_case(tree.body) == "upper"

    def test_compare_case_boolop_and(self) -> None:
        """BoolOp(And) with 'a' <= c -> 'lower'."""
        from skill_scan._ast_rot13_branch_analysis import _compare_case

        code = "c >= 'a' and c <= 'z'"
        tree = ast.parse(code, mode="eval")
        assert _compare_case(tree.body) == "lower"

    def test_compare_case_non_range(self) -> None:
        """Non-range expression -> None."""
        from skill_scan._ast_rot13_branch_analysis import _compare_case

        code = "x + y"
        tree = ast.parse(code, mode="eval")
        assert _compare_case(tree.body) is None

    def test_branch_case_if_node_lower(self) -> None:
        """_branch_case on an If with lowercase test -> 'lower'."""
        from skill_scan._ast_rot13_branch_analysis import _branch_case

        code = "if 'a' <= c <= 'z':\n    pass"
        tree = ast.parse(code)
        if_node = tree.body[0]
        assert isinstance(if_node, ast.If)
        assert _branch_case(if_node, False) == "lower"

    def test_branch_case_elif_upper(self) -> None:
        """_branch_case with is_orelse=True inspects the elif branch."""
        from skill_scan._ast_rot13_branch_analysis import _branch_case

        code = "if 'a' <= c <= 'z':\n    pass\nelif 'A' <= c <= 'Z':\n    pass"
        tree = ast.parse(code)
        if_node = tree.body[0]
        assert isinstance(if_node, ast.If)
        assert _branch_case(if_node, True) == "upper"


class TestCustomRot13StillDetected:
    """Custom ROT13 detection must still work after extraction."""

    def test_standard_custom_rot13(self) -> None:
        """Standard custom ROT13 with both branches is still detected."""
        from skill_scan.ast_analyzer import analyze_python

        code = """\
def rot13(text):
    result = []
    for c in text:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(c)
    return ''.join(result)
"""
        findings = analyze_python(code, _FILE)
        obfs001 = [f for f in findings if f.rule_id == "OBFS-001"]
        assert len(obfs001) == 1
        assert obfs001[0].category == "obfuscation"


class TestBranchCaseImportedInRot13:
    """_ast_rot13.py must import _branch_case from _ast_rot13_branch_analysis."""

    def test_branch_case_used_in_rot13_module(self) -> None:
        """_branch_case is accessible via the rot13 module (imported there)."""
        import skill_scan._ast_rot13 as rot13_mod

        # The module must have imported _branch_case from the new location
        assert hasattr(rot13_mod, "_branch_case") or ("_branch_case" in dir(rot13_mod))


class TestRot13LineCounts:
    """Line count constraints after extraction."""

    def test_rot13_max_250_lines(self) -> None:
        """_ast_rot13.py must be <= 250 lines after extraction."""
        src = inspect.getsourcefile(importlib.import_module("skill_scan._ast_rot13"))
        assert src is not None
        line_count = len(Path(src).read_text(encoding="utf-8").splitlines())
        assert line_count <= 250, f"_ast_rot13.py has {line_count} lines (max 250)"

    def test_branch_analysis_max_60_lines(self) -> None:
        """_ast_rot13_branch_analysis.py must be <= 60 lines."""
        src = inspect.getsourcefile(importlib.import_module("skill_scan._ast_rot13_branch_analysis"))
        assert src is not None
        line_count = len(Path(src).read_text(encoding="utf-8").splitlines())
        assert line_count <= 60, f"_ast_rot13_branch_analysis.py has {line_count} lines (max 60)"
