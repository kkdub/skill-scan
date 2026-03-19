"""Tests for Part D: class-level string assembly, dict.pop() tracking, class-body scope.

Covers:
- R007: class-level BinOp(Add) string assembly (prefix + suffix in class body)
- R008: dict.pop() tracking (funcs.pop('target') resolves to tracked value)
- R003: class-body scope propagation (_build_scope_map maps class body nodes)
- R-EFF001: corpus inputs produce findings when scanned
"""

from __future__ import annotations

import ast
from pathlib import Path

from skill_scan._ast_symbol_table import build_symbol_table


_PARSE = ast.parse


# -- R007: Class-level string assembly via BinOp(Add) -----------------------


class TestClassVarBinOpAdd:
    """Class body: prefix = 'ev'; suffix = 'al'; func_name = prefix + suffix."""

    def test_class_binop_add_two_vars(self) -> None:
        """BinOp(Add) of two class-level Name references resolves."""
        code = "class Config:\n    prefix = 'ev'\n    suffix = 'al'\n    func_name = prefix + suffix\n"
        result = build_symbol_table(_PARSE(code))
        assert result["Config.func_name"] == "eval"

    def test_class_binop_add_preserves_parts(self) -> None:
        """Individual class vars are still tracked alongside the concat."""
        code = "class Config:\n    prefix = 'ev'\n    suffix = 'al'\n    func_name = prefix + suffix\n"
        result = build_symbol_table(_PARSE(code))
        assert result["Config.prefix"] == "ev"
        assert result["Config.suffix"] == "al"

    def test_class_binop_add_three_parts(self) -> None:
        """Three-part concatenation: a + b + c resolves."""
        code = "class Evasion:\n    a = 'ex'\n    b = 'ec'\n    c = a + b\n"
        result = build_symbol_table(_PARSE(code))
        assert result["Evasion.c"] == "exec"

    def test_class_binop_add_var_plus_literal(self) -> None:
        """Name + string literal resolves."""
        code = "class C:\n    x = 'ev'\n    y = x + 'al'\n"
        result = build_symbol_table(_PARSE(code))
        assert result["C.y"] == "eval"

    def test_class_binop_add_literal_plus_var(self) -> None:
        """String literal + Name resolves."""
        code = "class C:\n    x = 'al'\n    y = 'ev' + x\n"
        result = build_symbol_table(_PARSE(code))
        assert result["C.y"] == "eval"

    def test_module_level_binop_add_of_names_resolves(self) -> None:
        """Module-level BinOp(Add) of two Name references also resolves."""
        code = "a = 'ev'\nb = 'al'\nc = a + b\n"
        result = build_symbol_table(_PARSE(code))
        assert result["c"] == "eval"

    def test_function_level_binop_add_of_names_resolves(self) -> None:
        """Function-level BinOp(Add) of two local Name references resolves."""
        code = "def f():\n    a = 'ev'\n    b = 'al'\n    c = a + b\n"
        result = build_symbol_table(_PARSE(code))
        assert result["f.c"] == "eval"


# -- R008: dict.pop() tracking ----------------------------------------------


class TestDictPopTracking:
    """Track dict literal elements and resolve dict.pop('key')."""

    def test_dict_literal_elements_tracked(self) -> None:
        """Dict literal stores composite keys: funcs[target] = 'eval'."""
        code = "funcs = {'target': 'eval', 'decoy': 'print'}\n"
        result = build_symbol_table(_PARSE(code))
        assert result["funcs[target]"] == "eval"
        assert result["funcs[decoy]"] == "print"

    def test_dict_pop_resolves_to_value(self) -> None:
        """name = funcs.pop('target') resolves name to tracked dict element."""
        code = "funcs = {'target': 'eval', 'decoy': 'print'}\nname = funcs.pop('target')\n"
        result = build_symbol_table(_PARSE(code))
        assert result["name"] == "eval"

    def test_dict_pop_different_key(self) -> None:
        """dict.pop with a different key resolves to that key's value."""
        code = "d = {'a': 'os', 'b': 'system'}\nx = d.pop('b')\n"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "system"

    def test_dict_pop_unknown_key_not_tracked(self) -> None:
        """dict.pop with a key not in the dict does not create an entry."""
        code = "d = {'a': 'os'}\nx = d.pop('missing')\n"
        result = build_symbol_table(_PARSE(code))
        assert "x" not in result

    def test_dict_pop_non_string_key_not_tracked(self) -> None:
        """dict.pop with a non-string key argument is not tracked."""
        code = "d = {'a': 'os'}\nx = d.pop(some_var)\n"
        result = build_symbol_table(_PARSE(code))
        assert "x" not in result

    def test_dict_pop_in_function_scope(self) -> None:
        """dict.pop resolves inside a function scope too."""
        code = "def f():\n    d = {'k': 'eval'}\n    x = d.pop('k')\n"
        result = build_symbol_table(_PARSE(code))
        assert result["f.x"] == "eval"


# -- R003: Class-body scope propagation in _build_scope_map -----------------


class TestClassBodyScopePropagation:
    """_build_scope_map must map class body nodes to ClassName scope."""

    def test_class_body_scope_mapped(self) -> None:
        """Class-level assignments get class scope in scope_map."""
        from skill_scan._ast_split_detector import _build_scope_map

        code = "class MyClass:\n    x = 'hello'\n    y = x + 'world'\n"
        tree = _PARSE(code)
        scope_map = _build_scope_map(tree)
        # Walk class body statements and verify they have scope
        class_node = tree.body[0]
        assert isinstance(class_node, ast.ClassDef)
        for stmt in class_node.body:
            assert scope_map.get(id(stmt)) == "MyClass"

    def test_class_body_and_method_scopes_coexist(self) -> None:
        """Class body nodes get class scope, method nodes get class scope too."""
        from skill_scan._ast_split_detector import _build_scope_map

        code = "class C:\n    x = 'val'\n    def method(self):\n        y = 'other'\n"
        tree = _PARSE(code)
        scope_map = _build_scope_map(tree)
        class_node = tree.body[0]
        assert isinstance(class_node, ast.ClassDef)
        # Class body assignment gets class scope
        assign_stmt = class_node.body[0]
        assert scope_map.get(id(assign_stmt)) == "C"
        # Method body also has class scope
        method_node = class_node.body[1]
        assert isinstance(method_node, ast.FunctionDef)
        for child in ast.walk(method_node):
            assert scope_map.get(id(child)) == "C"


# -- R-EFF001: End-to-end corpus detection -----------------------------------


class TestCorpusDetection:
    """Verify corpus files produce expected findings."""

    def test_classvar_assembly_corpus_detected(self) -> None:
        """corpus classvar_assembly.py should produce EXEC findings."""
        from skill_scan.ast_analyzer import analyze_python

        corpus_path = Path("corpus/red-team/2026-03-17-full/exec-evasion/classvar_assembly.py")
        if not corpus_path.exists():
            return
        content = corpus_path.read_text()
        findings = analyze_python(content, str(corpus_path))
        exec_findings = [f for f in findings if f.rule_id.startswith("EXEC-")]
        assert len(exec_findings) >= 1, f"Expected EXEC finding from classvar_assembly.py, got: {findings}"

    def test_dict_pop_corpus_detected(self) -> None:
        """corpus dict_pop_evasion.py should produce EXEC findings."""
        from skill_scan.ast_analyzer import analyze_python

        corpus_path = Path("corpus/red-team/2026-03-17-full/exec-evasion/dict_pop_evasion.py")
        if not corpus_path.exists():
            return
        content = corpus_path.read_text()
        findings = analyze_python(content, str(corpus_path))
        exec_findings = [f for f in findings if f.rule_id.startswith("EXEC-")]
        assert len(exec_findings) >= 1, f"Expected EXEC finding from dict_pop_evasion.py, got: {findings}"
