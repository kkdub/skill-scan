"""Tests for functools.reduce() and operator.add/concat detection.

Covers _resolve_reduce_concat in _ast_split_reduce.py and its integration
with the split detector via the resolve_call chain.
"""

from __future__ import annotations

import ast
import textwrap


from skill_scan._ast_split_detector import detect_split_evasion
from skill_scan._ast_split_reduce import _resolve_reduce_concat
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.ast_analyzer import analyze_python
from skill_scan.models import Finding

_PARSE = ast.parse
_FILE = "test.py"


def _detect(code: str) -> list[Finding]:
    """Helper: parse code, build symbol table, run split detector."""
    tree = _PARSE(code)
    st = build_symbol_table(tree)
    return detect_split_evasion(tree, _FILE, {}, st)


def _detect_with_aliases(code: str) -> list[Finding]:
    """Helper: parse code, build alias map and symbol table, run full analyzer."""
    return analyze_python(code, _FILE)


def _resolve_direct(code: str, *, alias_map: dict[str, str] | None = None) -> str | None:
    """Helper: parse a single expression and run _resolve_reduce_concat on it."""
    tree = _PARSE(code)
    node = tree.body[0].value  # type: ignore[attr-defined]
    return _resolve_reduce_concat(node, {}, "", alias_map=alias_map)


class TestResolveLambdaReduce:
    """Test functools.reduce(lambda a,b: a+b, [...]) resolution."""

    def test_lambda_reduce_resolves_to_eval(self) -> None:
        result = _resolve_direct(
            "functools.reduce(lambda a, b: a + b, ['ev', 'al'])",
            alias_map={"functools": "functools"},
        )
        assert result == "eval"

    def test_lambda_reduce_resolves_to_exec(self) -> None:
        result = _resolve_direct(
            "functools.reduce(lambda a, b: a + b, ['ex', 'ec'])",
            alias_map={"functools": "functools"},
        )
        assert result == "exec"

    def test_bare_reduce_resolves(self) -> None:
        result = _resolve_direct(
            "reduce(lambda a, b: a + b, ['ev', 'al'])",
            alias_map={"reduce": "functools.reduce"},
        )
        assert result == "eval"

    def test_aliased_functools_resolves(self) -> None:
        result = _resolve_direct(
            "ft.reduce(lambda a, b: a + b, ['ev', 'al'])",
            alias_map={"ft": "functools"},
        )
        assert result == "eval"

    def test_returns_none_for_non_reduce_call(self) -> None:
        result = _resolve_direct("foo(['ev', 'al'])")
        assert result is None

    def test_returns_none_for_wrong_lambda(self) -> None:
        """Lambda with subtraction body is not a concat combiner."""
        result = _resolve_direct(
            "functools.reduce(lambda a, b: a - b, ['ev', 'al'])",
            alias_map={"functools": "functools"},
        )
        assert result is None

    def test_returns_none_for_non_string_list(self) -> None:
        result = _resolve_direct(
            "functools.reduce(lambda a, b: a + b, [1, 2, 3])",
            alias_map={"functools": "functools"},
        )
        assert result is None

    def test_returns_none_for_empty_list(self) -> None:
        result = _resolve_direct(
            "functools.reduce(lambda a, b: a + b, [])",
            alias_map={"functools": "functools"},
        )
        assert result is None

    def test_returns_none_for_single_arg(self) -> None:
        """reduce() with only one argument (missing iterable)."""
        result = _resolve_direct(
            "functools.reduce(lambda a, b: a + b)",
            alias_map={"functools": "functools"},
        )
        assert result is None


class TestResolveOperatorAdd:
    """Test functools.reduce(operator.add/concat, [...]) resolution."""

    def test_operator_add_resolves(self) -> None:
        result = _resolve_direct(
            "functools.reduce(operator.add, ['ev', 'al'])",
            alias_map={"functools": "functools", "operator": "operator"},
        )
        assert result == "eval"

    def test_operator_concat_resolves(self) -> None:
        result = _resolve_direct(
            "functools.reduce(operator.concat, ['ex', 'ec'])",
            alias_map={"functools": "functools", "operator": "operator"},
        )
        assert result == "exec"

    def test_aliased_operator_resolves(self) -> None:
        result = _resolve_direct(
            "functools.reduce(op.add, ['sy', 'stem'])",
            alias_map={"functools": "functools", "op": "operator"},
        )
        assert result == "system"

    def test_non_operator_attribute_rejected(self) -> None:
        """Attribute on non-operator module is not a concat combiner."""
        result = _resolve_direct(
            "functools.reduce(math.add, ['ev', 'al'])",
            alias_map={"functools": "functools", "math": "math"},
        )
        assert result is None

    def test_operator_sub_rejected(self) -> None:
        """operator.sub is not a string concatenation combiner."""
        result = _resolve_direct(
            "functools.reduce(operator.sub, ['ev', 'al'])",
            alias_map={"functools": "functools", "operator": "operator"},
        )
        assert result is None


class TestReduceDetectorIntegration:
    """Integration tests: reduce patterns detected through full pipeline."""

    def test_functools_reduce_lambda_produces_exec_002(self) -> None:
        source = textwrap.dedent("""\
            import functools
            _result = functools.reduce(lambda a, b: a + b, ["ev", "al"])
        """)
        findings = _detect_with_aliases(source)
        exec_f = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_f) >= 1
        assert any("eval" in f.description for f in exec_f)

    def test_aliased_functools_reduce_detected(self) -> None:
        source = textwrap.dedent("""\
            import functools as ft
            _result = ft.reduce(lambda a, b: a + b, ["ex", "ec"])
        """)
        findings = _detect_with_aliases(source)
        exec_f = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_f) >= 1
        assert any("exec" in f.description for f in exec_f)

    def test_operator_add_produces_exec_002(self) -> None:
        source = textwrap.dedent("""\
            import functools
            import operator
            _result = functools.reduce(operator.add, ["ev", "al"])
        """)
        findings = _detect_with_aliases(source)
        exec_f = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_f) >= 1

    def test_operator_concat_produces_exec_002(self) -> None:
        source = textwrap.dedent("""\
            import functools
            import operator
            _result = functools.reduce(operator.concat, ["po", "pen"])
        """)
        findings = _detect_with_aliases(source)
        exec_f = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_f) >= 1
        assert any("popen" in f.description for f in exec_f)

    def test_aliased_operator_detected(self) -> None:
        source = textwrap.dedent("""\
            import functools
            import operator as op
            _result = functools.reduce(op.add, ["sy", "stem"])
        """)
        findings = _detect_with_aliases(source)
        exec_f = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_f) >= 1
        assert any("system" in f.description for f in exec_f)

    def test_reduce_import_produces_exec_006(self) -> None:
        """reduce building '__import__' should produce EXEC-006."""
        source = textwrap.dedent("""\
            import functools
            _result = functools.reduce(lambda a, b: a + b, ["__im", "port__"])
        """)
        findings = _detect_with_aliases(source)
        exec_f = [f for f in findings if f.rule_id == "EXEC-006"]
        assert len(exec_f) >= 1

    def test_safe_reduce_no_findings(self) -> None:
        source = textwrap.dedent("""\
            import functools
            _greeting = functools.reduce(lambda a, b: a + b, ["hel", "lo"])  # codespell:ignore hel
        """)
        findings = _detect_with_aliases(source)
        exec_f = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert len(exec_f) == 0

    def test_safe_operator_add_no_findings(self) -> None:
        source = textwrap.dedent("""\
            import functools
            import operator
            _greeting = functools.reduce(operator.add, ["hel", "lo"])  # codespell:ignore hel
        """)
        findings = _detect_with_aliases(source)
        exec_f = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert len(exec_f) == 0

    def test_tuple_iterable_detected(self) -> None:
        """Tuple as second arg (instead of list) should also be detected."""
        source = textwrap.dedent("""\
            import functools
            _result = functools.reduce(lambda a, b: a + b, ("ev", "al"))
        """)
        findings = _detect_with_aliases(source)
        exec_f = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_f) >= 1


class TestReduceModuleConstraints:
    """Verify file size constraints are maintained."""

    def test_detector_under_200_lines(self) -> None:
        """_ast_split_detector.py must remain at or below 200 lines."""
        from pathlib import Path

        detector = Path("src/skill_scan/_ast_split_detector.py")
        line_count = len(detector.read_text().splitlines())
        assert line_count <= 200, f"_ast_split_detector.py is {line_count} lines (max 200)"

    def test_reduce_module_under_300_lines(self) -> None:
        """_ast_split_reduce.py must remain under 300 lines."""
        from pathlib import Path

        reducer = Path("src/skill_scan/_ast_split_reduce.py")
        line_count = len(reducer.read_text().splitlines())
        assert line_count <= 300, f"_ast_split_reduce.py is {line_count} lines (max 300)"

    def test_resolve_module_under_300_lines(self) -> None:
        """_ast_split_resolve.py must remain under 300 lines."""
        from pathlib import Path

        resolver = Path("src/skill_scan/_ast_split_resolve.py")
        line_count = len(resolver.read_text().splitlines())
        assert line_count <= 300, f"_ast_split_resolve.py is {line_count} lines (max 300)"
