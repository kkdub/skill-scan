"""Tests for class-scope symbol table and class attribute resolution.

Covers: ClassDef walking, self.attr storage, cross-method resolution,
nested classes, and class-level split evasion detection (EXEC-002).
"""

from __future__ import annotations

import ast

from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.ast_analyzer import analyze_python


_PARSE = ast.parse


class TestClassLevelAssignments:
    """R008: build_symbol_table walks ClassDef nodes and stores class-level attrs."""

    def test_class_level_string_assignment(self) -> None:
        code = "class C:\n    x = 'hello'"
        result = build_symbol_table(_PARSE(code))
        assert result["C.x"] == "hello"

    def test_class_level_multiple_attrs(self) -> None:
        code = "class C:\n    a = 'ev'\n    b = 'al'"
        result = build_symbol_table(_PARSE(code))
        assert result["C.a"] == "ev"
        assert result["C.b"] == "al"

    def test_class_level_non_string_ignored(self) -> None:
        code = "class C:\n    x = 42\n    y = 'ok'"
        result = build_symbol_table(_PARSE(code))
        assert "C.x" not in result
        assert result["C.y"] == "ok"

    def test_class_level_concat(self) -> None:
        code = "class C:\n    x = 'a' + 'b'"
        result = build_symbol_table(_PARSE(code))
        assert result["C.x"] == "ab"

    def test_class_level_indirection(self) -> None:
        """Class-level variable chains resolve within class scope."""
        code = "class C:\n    a = 'hello'\n    b = a"
        result = build_symbol_table(_PARSE(code))
        assert result["C.a"] == "hello"
        assert result["C.b"] == "hello"


class TestSelfAttrAssignment:
    """R007: Self-attribute writes stored as 'ClassName.attr'."""

    def test_self_attr_string(self) -> None:
        code = "class C:\n    def __init__(self):\n        self.x = 'hello'"
        result = build_symbol_table(_PARSE(code))
        assert result["C.x"] == "hello"

    def test_self_attr_concat(self) -> None:
        code = "class C:\n    def __init__(self):\n        self.x = 'a' + 'b'"
        result = build_symbol_table(_PARSE(code))
        assert result["C.x"] == "ab"

    def test_self_attr_non_string_ignored(self) -> None:
        code = "class C:\n    def __init__(self):\n        self.x = 42"
        result = build_symbol_table(_PARSE(code))
        assert "C.x" not in result

    def test_different_self_name(self) -> None:
        """First parameter name is used as self, not hardcoded 'self'."""
        code = "class C:\n    def __init__(this):\n        this.x = 'hello'"
        result = build_symbol_table(_PARSE(code))
        assert result["C.x"] == "hello"


class TestCrossMethodResolution:
    """R007/R-IMP004: Writes from different methods resolve to same key."""

    def test_two_methods_same_attr(self) -> None:
        code = (
            "class E:\n"
            "    def build(self):\n"
            "        self.x = 'first'\n"
            "    def run(self):\n"
            "        self.x = 'second'\n"
        )
        result = build_symbol_table(_PARSE(code))
        # Both write to E.x -- last method wins
        assert "E.x" in result
        # No method-scoped keys
        assert "build.x" not in result
        assert "run.x" not in result

    def test_class_level_and_self_attr_merge(self) -> None:
        code = "class C:\n    x = 'class_val'\n    def __init__(self):\n        self.x = 'init_val'\n"
        result = build_symbol_table(_PARSE(code))
        # self.attr overwrites class-level since methods are processed after
        assert result["C.x"] == "init_val"


class TestNestedClassAndFunction:
    """R-IMP003: No crash on nested classes or functions inside class methods."""

    def test_nested_class_no_crash(self) -> None:
        code = "class Outer:\n    class Inner:\n        x = 'inner'\n    y = 'outer'\n"
        result = build_symbol_table(_PARSE(code))
        assert result["Outer.y"] == "outer"
        # Nested class body tracked at class level (collected as plain assignment)
        assert isinstance(result, dict)

    def test_nested_function_in_method_no_crash(self) -> None:
        code = (
            "class C:\n"
            "    def method(self):\n"
            "        def inner():\n"
            "            x = 'val'\n"
            "        self.y = 'ok'\n"
        )
        result = build_symbol_table(_PARSE(code))
        assert result["C.y"] == "ok"

    def test_static_method_no_args(self) -> None:
        """Method with no args (e.g. @staticmethod) should not crash."""
        code = (
            "class C:\n    def no_args():\n        x = 'val'\n    def normal(self):\n        self.y = 'ok'\n"
        )
        result = build_symbol_table(_PARSE(code))
        assert result["C.y"] == "ok"


class TestClassSplitEvasionDetection:
    """R-EFF006: Class-level attribute assembly triggers EXEC-002."""

    def test_class_attr_concat_triggers_exec002(self) -> None:
        code = "class E:\n    a = 'ev'\n    b = 'al'\n    def run(self):\n        x = self.a + self.b\n"
        findings = analyze_python(code, "test.py")
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1

    def test_class_attr_fstring_triggers_exec002(self) -> None:
        code = "class E:\n    a = 'ev'\n    b = 'al'\n    def run(self):\n        x = f'{self.a}{self.b}'\n"
        findings = analyze_python(code, "test.py")
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1

    def test_self_attr_write_concat_triggers_exec002(self) -> None:
        code = (
            "class E:\n"
            "    def __init__(self):\n"
            "        self.a = 'ev'\n"
            "        self.b = 'al'\n"
            "    def run(self):\n"
            "        x = self.a + self.b\n"
        )
        findings = analyze_python(code, "test.py")
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1


class TestCorpusFixture:
    """R-EFF006: pos_class_level_attr.py triggers EXEC-002."""

    def test_fixture_triggers_exec002(self) -> None:
        import pathlib

        fixture = (
            pathlib.Path(__file__).resolve().parent.parent
            / "fixtures"
            / "split_evasion"
            / "pos_class_level_attr.py"
        )
        code = fixture.read_text()
        findings = analyze_python(code, str(fixture))
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1
